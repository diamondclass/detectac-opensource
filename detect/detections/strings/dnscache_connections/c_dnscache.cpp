#include "c_dnscache.h"

#define MIN_STRING_LENGTH 4

bool dnsscan::enable_debug_privilege() {
    try {
        HANDLE h_token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) return false;

        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(h_token); return false; }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), NULL, NULL)) { CloseHandle(h_token); return false; }
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { CloseHandle(h_token); return false; }

        CloseHandle(h_token);
        return true;
    }
    catch (...) { return false; }
    return false;
}

DWORD dnsscan::get_process_id_by_name(const std::string& service_name) {
    try {
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCManager) return 0;

        SC_HANDLE hService = OpenService(hSCManager, service_name.c_str(), SERVICE_QUERY_STATUS);
        if (!hService) { CloseServiceHandle(hSCManager); return 0; }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytes_needed = 0;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes_needed)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return 0;
        }

        DWORD pid = ssp.dwProcessId;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return pid;
    }
    catch (...) { return 0; }
    return 0;
}

static inline std::pair<std::string, std::string> split_custom_string(const std::string& s) { try{
    size_t pos = s.find(xorstr_(":::"));
    if (pos != std::string::npos) return { s.substr(0, pos), s.substr(pos + 3) };
    return { xorstr_(""), s }; } catch (...) { return {}; }
}

static inline std::string sanitize_ascii_printable(const std::string& s) { try{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) if (c >= 32 && c <= 126) out.push_back((char)c);
    return out; } catch (...) { return ""; }
}

static std::vector<std::pair<std::string, std::string>> hardcoded_filters = {

            #ifdef DETECT_FIVEM

            {xorstr_("skript.gg"), xorstr_("Visited Skript Website Since Restart \"skript.gg\"")},
            {xorstr_("tzproject.com"), xorstr_("Visited TZ Project Website Since Restart \"tzproject.com\"")},
            {xorstr_("hxcheats.tech"), xorstr_("Visited Hx Cheats Website Since Restart \"hxcheats.tech\"")},
            {xorstr_("gosth.gg"), xorstr_("Visited Gosth Website Since Restart \"gosth.gg\"")},
            {xorstr_("ghostesportpanel.com"), xorstr_("Visited Gosth Website Since Restart \"ghostesportpanel.com\"")},
            {xorstr_("eulencheats.com"), xorstr_("Visited Eulen Website Since Restart \"eulencheats.com\"")},
            {xorstr_("eulen.cc"), xorstr_("Visited Eulen Website Since Restart \"eulen.cc\"")},
            {xorstr_("luamenu.xyz"), xorstr_("Visited Lua (RedEngine) Website Since Restart \"luamenu.xyz\"")},
            {xorstr_("redengine.eu"), xorstr_("Visited RedEngine Website Since Restart \"redengine.eu\"")},
            {xorstr_("redengine.net"), xorstr_("Visited RedEngine Website Since Restart \"redengine.net\"")},
            {xorstr_("susano.re"), xorstr_("Visited Susano Website Since Restart \"susano.re\"")},
            {xorstr_("machocheats.com"), xorstr_("Visited Macho Cheats Website Since Restart \"machocheats.com\"")},
            {xorstr_("88-cheats.xyz"), xorstr_("Visited 88 Cheats Website Since Restart \"88-cheats.xyz\"")},
            {xorstr_("testo.gg"), xorstr_("Visited Testo Cheats Website Since Restart \"testo.gg\"")},
            {xorstr_("blackout.wtf"), xorstr_("Visited Blackout Cheats Website Since Restart \"blackout.wtf\"")},
            {xorstr_("monstermenu.cc"), xorstr_("Visited Monster Menu Website Since Restart \"monstermenu.cc\"")},
            {xorstr_("9zproject.xyz"), xorstr_("Visited 9z Project Website Since Restart \"9zproject.xyz\"")},
            {xorstr_("sergiu.pro"), xorstr_("Visited Spotless Website Since Restart \"sergiu.pro\"")},
            {xorstr_("projectdow.com"), xorstr_("Visited Dow Website Since Restart \"projectdow.com\"")},
            {xorstr_("api.shilav2.shop"), xorstr_("Visited Wexless Website Since Restart \"api.shilav2.shop\"")},
            {xorstr_("193.23.160.168"), xorstr_("Visited Signer Website Since Restart \"193.23.160.168\"")},
            {xorstr_("orbit.signer.cc"), xorstr_("Visited Signer Website Since Restart \"orbit.signer.cc\"")},
            {xorstr_("signer.cc"), xorstr_("Visited Signer Website Since Restart \"signer.cc\"")},
            {xorstr_("bypass.fun"), xorstr_("Visited Bypass.Fun Website Since Restart \"bypass.fun\"")},
            {xorstr_("keyser-lts.com"), xorstr_("Visited Keyser Website Since Restart \"keyser-lts.com\"")},
            {xorstr_("keyser.gg"), xorstr_("Visited Keyser Website Since Restart \"keyser.gg\"")},
            {xorstr_("185.236.228.154"), xorstr_("Visited FLK Website Since Restart \"185.236.228.154\"")},
            {xorstr_("flkstore.com"), xorstr_("Visited FLK Website Since Restart \"flkstore.com\"")},
            {xorstr_("flk-uhq.xyz"), xorstr_("Visited FLK Website Since Restart \"flk-uhq.xyz\"")},
            {xorstr_("5.206.224.37"), xorstr_("Visited FLK Website Since Restart \"5.206.224.37\"")},
            {xorstr_("bebetter-fivem"), xorstr_("Visited Be-better Website Since Restart \"bebetter-fivem\"")},
            {xorstr_("venacy.club"), xorstr_("Visited Venacy Website Since Restart \"venacy.club\"")},
            {xorstr_("antiecho.xyz"), xorstr_("Visited Ant-Echo Website Since Restart \"antiecho.xyz\"")},
            {xorstr_("203.159.90.127"), xorstr_("Visited Lethality Script Website Since Restart \"203.159.90.127\"")},
            {xorstr_("leet-cheats.ru"), xorstr_("Visited Leet Cheats Website Since Restart \"leet-cheats.ru\"")},
            {xorstr_("hydrogen.ac"), xorstr_("Visited Hydrogen Cheats Website Since Restart \"hydrogen.ac\"")},
            {xorstr_("trinitas.top"), xorstr_("Visited Trinitas Cheats Website Since Restart \"trinitas.top\"")},
            {xorstr_("vanish-cheat.com"), xorstr_("Visited Vanish Cheats Website Since Restart \"vanish-cheat.com\"")},
            {xorstr_("91.218.66.77"), xorstr_("Visited Forte Website Since Restart \"91.218.66.77\"")},
            {xorstr_("uzuimarket.xyz"), xorstr_("Visited Uzui Market Website Since Restart \"uzuimarket.xyz\"")},
            {xorstr_("spotless.gg"), xorstr_("Visited Spotless Bypass Since Restart \"spotless.gg\"")},
            {xorstr_("traceless.wtf"), xorstr_("Visited Traceless Bypass Since Restart \"traceless.wtf\"")},
            {xorstr_("serapi.mom"), xorstr_("Visited Spotless/Binary Bypass Since Restart \"serapi.mom\"")},
            {xorstr_("freshbypass.xyz"), xorstr_("Visited Fresh Bypass Since Restart \"freshbypass.xyz\"")},
            {xorstr_("designcraft.xyz"), xorstr_("Visited Response Bypass Since Restart \"designcraft.xyz\"")},
            {xorstr_("snowbp.xyz"), xorstr_("Visited Snow Bypass Since Restart \"snowbp.xyz\"")},
            {xorstr_("87.120.191.29"), xorstr_("Visited Quanta Since Restart \"87.120.191.29\"")},
            {xorstr_("club44.lol"), xorstr_("Visited Club44 Since Restart \"club44.lol\"")},
            {xorstr_("catatau.xyz"), xorstr_("Visited XYZ DMA Since Restart \"catatau.xyz\"")},
            {xorstr_("auis.binaryy.top"), xorstr_("Visited Binary Bypass Website Since Restart \"auis.binaryy.top\"")},
            {xorstr_("etezmdkyybdrsczqfjky.supabase.co"), xorstr_("Visited Binary Bypass")},
            {xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/auth-login"), xorstr_("Visited Binary Bypass Login Page")},
            {xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/vpn-check"), xorstr_("Visited Binary Bypass VPN Check Page")},
            {xorstr_("etezmdkyybdrsczqfjky.supabase.co/rest/v1/rpc/get_maintenance_mode"), xorstr_("Visited Binary Bypass Maintinence Page")},
            {xorstr_("serotonin.win"), xorstr_("Visited Serotonin Bypass \"serotonin.win\"")},
            {xorstr_("181.215.45.13"), xorstr_("Visited Club44 Bypass")},
            {xorstr_("93.127.215.67"), xorstr_("Visited Club44 Bypass")},
            {xorstr_("severance.today"), xorstr_("Visited Severance Bypass")},
            {xorstr_("gnomus.lol"), xorstr_("Visited FiveM Enjoyer")},
            {xorstr_("gnomus.lol"), xorstr_("Visited Severance Bypass")},
            {xorstr_("45.156.87.118"), xorstr_("Visited Unknown Bypass")},
            {xorstr_("16.171.254.8"), xorstr_("Visited Bypass.fun Bypass")},
            {xorstr_("certificate.wtf"), xorstr_("Visited certificate.wtf Website Since Restart \"certificate.wtf\"")},
            {xorstr_("cosmos.pm"), xorstr_("Visited Cosmos Website Since Restart \"cosmos.pm\"")},
            {xorstr_("rxmenu.shop"), xorstr_("Visited RX Menu Website Since Restart \"rxmenu.shop\"")},
            {xorstr_("omertasoftware.com"), xorstr_("Visited Omerta Software Website Since Restart \"omertasoftware.com\"")},
            {xorstr_("xentro.xyz"), xorstr_("Visited Xentro Website Since Restart \"xentro.xyz\"")},
            {xorstr_("titanbypass.com"), xorstr_("Visited Titan Bypass Website Since Restart \"titanbypass.com\"")},
            {xorstr_("us1.phase.uno"), xorstr_("Visited Phase Uno Since Restart \"us1.phase.uno\"")},
            {xorstr_("phase.uno"), xorstr_("Visited Phase Uno Since Restart \"phase.uno\"")},
            {xorstr_("104.21.82.227"), xorstr_("Visited Phase Uno Since Restart \"104.21.82.227\"")},
            {xorstr_("104.18.2.36"), xorstr_("Visited Phase Uno Since Restart \"104.18.2.36\"")},
            {xorstr_("wizardbypass.com"), xorstr_("Visited Wizard Bypass Website Since Restart \"wizardbypass.com\"")},
            {xorstr_("loginlive.cloud"), xorstr_("Visited Wizard Bypass Ran Since Restart \"Wizard\"")},
            {xorstr_("54.39.67.23"), xorstr_("Visited Rolex Bypass Since Restart \"54.39.67.23\"")},
            {xorstr_("richh.lol"), xorstr_("Visited Rolex Bypass Website Since Restart \"richh.lol\"")},
            {xorstr_("antiscan.xyz"), xorstr_("Visited Rolex Bypass Website Since Restart \"antiscan.xyz\"")},
            {xorstr_("evora.pw"), xorstr_("Visited Evora Website Since Restart \"evora.pw\"")},
            {xorstr_("45.143.196.213"), xorstr_("Connected To Bytecode Bypass Since Restart \"45.143.196.213\"")},
            {xorstr_("Sirius.lv"), xorstr_("Visited Sirius Bypass Since Restart \"Sirius.lv\"")},

            #elif DETECT_MINECRAFT

            {xorstr_("drip.gg"), xorstr_("Visited Drip Website Since Restart \"drip.gg\"")},
            {xorstr_("karma.rip"), xorstr_("Visited Karma Website Since Restart \"karma.rip\"")},
            {xorstr_("vape.gg"), xorstr_("Visited Vape Website Since Restart \"vape.gg\"")},
            {xorstr_("sunset.rip"), xorstr_("Visited Sunset Website Since Restart \"sunset.rip\"")},
            {xorstr_("doomsdayclient.com"), xorstr_("Visited Doomsday Website Since Restart \"doomsdayclient.com\"")},
            {xorstr_("neverlack.in"), xorstr_("Visited Drip Website Since Restart \"neverlack.in\"")},
            {xorstr_("akiraghost.com"), xorstr_("Visited Akira Website Since Restart \"akiraghost.com\"")},
            {xorstr_("entropy.club"), xorstr_("Visited Entropy Website Since Restart \"entropy.club\"")},
            {xorstr_("dreamclient.xyz"), xorstr_("Visited Dream Website Since Restart \"dreamclient.xyz\"")},
            {xorstr_("crypp.in"), xorstr_("Visited Crypp Website Since Restart \"crypp.in\"")},
            {xorstr_("dopp.in"), xorstr_("Visited Dopp Website Since Restart \"dopp.in\"")},
            {xorstr_("slapp.in"), xorstr_("Visited Slapp Website Since Restart \"slapp.in\"")},
            {xorstr_("unicorn-hacks.net"), xorstr_("Visited Unicorn Hacks Website Since Restart \"unicorn-hacks.net\"")},
            {xorstr_("prestigeclient.vip"), xorstr_("Visited Prestige Client Website Since Restart \"prestigeclient.vip\"")},
            {xorstr_("api.prestigeclient.vip"), xorstr_("Visited Prestige Client Website Since Restart \"api.prestigeclient.vip\"")},
            {xorstr_("bypassing.gg"), xorstr_("Visited Cold Bypassing Website Since Restart \"bypassing.gg\"")},
            {xorstr_("grimclient.eu"), xorstr_("Visited Grim Client Website Since Restart \"grimclient.eu\"")},
            {xorstr_("axen.lol"), xorstr_("Visited Axen Website Since Restart \"axen.lol\"")},
            {xorstr_("aristois.net"), xorstr_("Visited Aristois Website Since Restart \"aristois.net\"")},
            {xorstr_("catlean.su"), xorstr_("Visited Catlean Website Since Restart \"catlean.su\"")},
            {xorstr_("client-analytics.dev"), xorstr_("Visited Cold Bypass Website Since Restart \"client-analytics.dev\"")},

            #elif DETECT_ROBLOX
            {xorstr_("robloxcheatz.com"), xorstr_("Visited Robloxcheatz Website Since Restart \"robloxcheatz.com\"")},
            {xorstr_("radiant.cc"), xorstr_("Visited Radiant Website Since Restart \"radiant.cc\"")},
            {xorstr_("eternalproduct.com"), xorstr_("Visited Eternal Product Website Since Restart \"eternalproduct.com\"")},
            {xorstr_("matrixhubs.shop"), xorstr_("Visited Matrix Website Since Restart \"matrixhubs.shop\"")},
            {xorstr_("buymtx.online"), xorstr_("Visited Matrix Website Since Restart \"buymtx.online\"")},
            {xorstr_("buymtx"), xorstr_("Visited Matrix Website Since Restart \"buymtx.online\"")},
            {xorstr_("mega.nz/folder/KehEhLzB#Cs0PiuqggmwItBIcAG4z6w"), xorstr_("Visited Mooze MegaFolder Since Restart \"mega.nz/folder/KehEhLzB#Cs0PiuqggmwItBIcAG4z6w\"")},
            {xorstr_("mooze.fun"), xorstr_("Visited Mooze Website Since Restart \"mooze.fun\"")},
            {xorstr_("hastebin.skyra.pw"), xorstr_("Visited Config Website Since Restart \"hastebin.skyra.pw\"")},
            {xorstr_("vapevoidware.xyz"), xorstr_("Visited Voidware Website Since Restart \"vapevoidware.xyz\"")},
            {xorstr_("voxlis.net"), xorstr_("Visited Voxlis Website Since Restart \"voxlis.net\"")},
            {xorstr_("voltbz.net"), xorstr_("Visited Volt Website Since Restart \"voltbz.net\"")},
            {xorstr_("potassium.pro"), xorstr_("Visited Potassium Website Since Restart \"potassium.pro\"")},
            {xorstr_("getwave.gg"), xorstr_("Visited Wave Website Since Restart \"getwave.gg\"")},
            {xorstr_("z.synapse.do"), xorstr_("Visited Synapse Z Website Since Restart \"z.synapse.do\"")},
            {xorstr_("seliware.com"), xorstr_("Visited Seliware Website Since Restart \"seliware.com\"")},
            {xorstr_("getmadium.net"), xorstr_("Visited Madium Website Since Restart \"getmadium.net\"")},
            {xorstr_("realvelocity.xyz"), xorstr_("Visited Velocity Website Since Restart \"realvelocity.xyz\"")},
            {xorstr_("sirhurt.net"), xorstr_("Visited SirHurt Website Since Restart \"sirhurt.net\"")},
            {xorstr_("getsolara.dev"), xorstr_("Visited Solara Website Since Restart \"getsolara.dev\"")},
            {xorstr_("xeno.now"), xorstr_("Visited Xeno Website Since Restart \"xeno.now\"")},
            {xorstr_("raptor.fun"), xorstr_("Visited MacSploit Website Since Restart \"raptor.fun\"")},
            {xorstr_("deltaexploits.gg"), xorstr_("Visited Delta Exploits Website Since Restart \"deltaexploits.gg\"")},
            {xorstr_("getcryptic.net"), xorstr_("Visited Cryptic Website Since Restart \"getcryptic.net\"")},
            {xorstr_("vegax.gg"), xorstr_("Visited Vega X Website Since Restart \"vegax.gg\"")},
            {xorstr_("codex.lol"), xorstr_("Visited Codex Website Since Restart \"codex.lol\"")},
            {xorstr_("serotonin.win"), xorstr_("Visited Serotonin Website Since Restart \"serotonin.win\"")},
            {xorstr_("matcha-latte.win"), xorstr_("Visited Matcha Website Since Restart \"matcha-latte.win\"")},
            {xorstr_("photonsys.sellpass.io"), xorstr_("Visited Photon Website Since Restart \"photonsys.sellpass.io\"")},
            {xorstr_("cultofintellect.com"), xorstr_("Visited DX9WARE V2 Website Since Restart \"cultofintellect.com\"")},
            {xorstr_("vexor.wtf"), xorstr_("Visited Vexor Website Since Restart \"vexor.wtf\"")},

            #elif DETECT_RUST

            {xorstr_("onestopcheats"), xorstr_("Visited Onestopcheats Website Since Restart \"onestopcheats\"")},

            #elif DETECT_FORTNITE
            {xorstr_("skycheats"), xorstr_("Visited Skycheats Website Since Restart \"skycheats\"")},
            {xorstr_("SkyCheats.com"), xorstr_("Visited SkyCheats.com Website Since Restart \"SkyCheats.com\"")},
            {xorstr_("battlelog.co"), xorstr_("Visited battlelog Website Since Restart \"battlelog.co\"")},
            {xorstr_("aimclub.io"), xorstr_("Visited aimclub Website Since Restart \"aimclub.io\"")},
            {xorstr_("uniquehacks.store"), xorstr_("Visited uniquehacks Website Since Restart \"uniquehacks.store\"")},
            {xorstr_("privatecheatz.com"), xorstr_("Visited privatecheatz Website Since Restart \"privatecheatz.com\"")},
            {xorstr_("colossalcheats.com"), xorstr_("Visited colossalcheats Website Since Restart \"colossalcheats.com\"")},
            {xorstr_("hackerbot.net"), xorstr_("Visited hackerbot Website Since Restart \"hackerbot.net\"")},
            {xorstr_("army-cheats.com"), xorstr_("Visited army-cheats Website Since Restart \"army-cheats.com\"")},
            {xorstr_("spycheats.net"), xorstr_("Visited spycheats Website Since Restart \"spycheats.net\"")},
            {xorstr_("santana-tech.com/"), xorstr_("Visited santana-tech Website Since Restart \"santana-tech.com/\"")},
            {xorstr_("aimhax.net"), xorstr_("Visited aimhax Website Since Restart \"aimhax.net\"")},
            {xorstr_("kernelcheats.to"), xorstr_("Visited kernelcheats Website Since Restart \"kernelcheats.to\"")},
            {xorstr_("infinitycheats.net"), xorstr_("Visited infinitycheats Website Since Restart \"infinitycheats.net\"")},
            {xorstr_("xera-cheats.com"), xorstr_("Visited xera-cheats Website Since Restart \"xera-cheats.com\"")},
            {xorstr_("zeta-cheats.com"), xorstr_("Visited zeta-cheats Website Since Restart \"zeta-cheats.com\"")},
            {xorstr_("neo-cheats.com"), xorstr_("Visited neo-cheats Website Since Restart \"neo-cheats.com\"")},
            {xorstr_("Lavicheats.com"), xorstr_("Visited Lavicheats Website Since Restart \"Lavicheats.com\"")},
            {xorstr_("cheating.gg"), xorstr_("Visited Cheating Website Since Restart \"cheating.gg\"")},
            {xorstr_("ventro.tech"), xorstr_("Visited Solaris Website Since Restart \"ventro.tech\"")},
            {xorstr_("sceptre.pro"), xorstr_("Visited Sceptre Website Since Restart \"sceptre.pro\"")},
            {xorstr_("185.236.228.154"), xorstr_("Visited FLK Website Since Restart \"185.236.228.154\"")},
            {xorstr_("flkstore.com"), xorstr_("Visited FLK Website Since Restart \"flkstore.com\"")},
            {xorstr_("flk-uhq.xyz"), xorstr_("Visited FLK Website Since Restart \"flk-uhq.xyz\"")},
            {xorstr_("5.206.224.37"), xorstr_("Visited FLK Website Since Restart \"5.206.224.37\"")},
            {xorstr_("keyser-lts.com"), xorstr_("Visited Keyser Website Since Restart \"keyser-lts.com\"")},
            {xorstr_("keyser.gg"), xorstr_("Visited Keyser Website Since Restart \"keyser.gg\"")},
            {xorstr_("zombiecheats.com"), xorstr_("Visited Zombie Cheats Website Since Restart \"zombiecheats.com\"")},
            {xorstr_("hypervision.gg"), xorstr_("Visited Hypervision Website Since Restart \"hypervision.gg\"")},
            {xorstr_("elocarry.net"), xorstr_("Visited Elocarry Website Since Restart \"elocarry.net\"")},
            {xorstr_("engineowning.su"), xorstr_("Visited EngineOwning Website Since Restart \"engineowning.su\"")},
            {xorstr_("uzuimarket.xyz"), xorstr_("Visited Uzui Market Website Since Restart \"uzuimarket.xyz\"")},
            {xorstr_("exodus.fun"), xorstr_("Visited Exodus Cheats Website Since Restart \"exodus.fun\"")},
            {xorstr_("195.59.67.101"), xorstr_("Visited ICanHaZip Since Restart \"195.59.67.101\"")},
            {xorstr_("icanhazip.com"), xorstr_("Visited ICanHaZip Since Restart \"icanhazip.com\"")},
            {xorstr_("udsoftwares.com"), xorstr_("Visited UD Softwares Since Restart \"udsoftwares.com\"")},
            {xorstr_("crythosbackend-production.up.railway.app"), xorstr_("Visited Crythos Since Restart \"crythosbackend-production.up.railway.app\"")},

            #elif DETECT_DAYZ

            {xorstr_("stugware.com"), xorstr_("Visited Stugwware Website Since Restart \"stugware.com\"")},
            {xorstr_("cheatseller.com"), xorstr_("Visited Cheatseller Website Since Restart \"cheatseller.com\"")},
            {xorstr_("elitehacks.ru"), xorstr_("Visited Elite Hacks Website Since Restart \"elitehacks.ru\"")},
            {xorstr_("smgcheats.com"), xorstr_("Visited SMG Cheats Website Since Restart \"smgcheats.com\"")},
            {xorstr_("battlelog.co"), xorstr_("Visited Battlelog Website Since Restart \"battlelog.co\"")},
            {xorstr_("ducks-services.com"), xorstr_("Visited Ducks Services Website Since Restart \"ducks-services.com\"")},
            {xorstr_("skycheats.com"), xorstr_("Visited Sky Cheats Website Since Restart \"skycheats.com\"")},
            {xorstr_("elitepvpers.com"), xorstr_("Visited ElitePVPers Website Since Restart \"elitepvpers.com\"")},
            {xorstr_("kernaim.to"), xorstr_("Visited Kernaim Website Since Restart \"kernaim.to\"")},
            {xorstr_("ciroscript.com"), xorstr_("Visited CiroScript Website Since Restart \"ciroscript.com\"")},
            {xorstr_("wh-satano.ru"), xorstr_("Visited WH Satano Website Since Restart \"wh-satano.ru\"")},
            {xorstr_("blast.hk"), xorstr_("Visited Blast Website Since Restart \"blast.hk\"")},
            {xorstr_("cheatseller.ru"), xorstr_("Visited Cheatseller RU Website Since Restart \"cheatseller.ru\"")},
            {xorstr_("cheat.bz"), xorstr_("Visited Cheat BZ Website Since Restart \"cheat.bz\"")},
            {xorstr_("clutch-solution.com"), xorstr_("Visited Clutch Solution Website Since Restart \"clutch-solution.com\"")},
            {xorstr_("715team.ru"), xorstr_("Visited 715 Team Website Since Restart \"715team.ru\"")},
            {xorstr_("labcorecheats.com"), xorstr_("Visited Labcore Cheats Website Since Restart \"labcorecheats.com\"")},
            {xorstr_("byster.one"), xorstr_("Visited Byster Website Since Restart \"byster.one\"")},
            {xorstr_("up-game.pro"), xorstr_("Visited Up Game Website Since Restart \"up-game.pro\"")},
            {xorstr_("zsoft.store"), xorstr_("Visited ZSoft Website Since Restart \"zsoft.store\"")},
            {xorstr_("dayzradar.715team.ru"), xorstr_("Visited DayZ Radar 715 Team Website Since Restart \"dayzradar.715team.ru\"")},

            #elif DETECT_SIEGE

            { xorstr_("skreechware.com"), xorstr_("Visited Skreechware Website Since Restart \"skreechware.com\"") },
            { xorstr_("cosmocheats.com"), xorstr_("Visited Cosmocheats Website Since Restart \"cosmocheats.com\"") },
            { xorstr_("nyronai.com"), xorstr_("Visited Nyronai Website Since Restart \"nyronai.com\"") },
            { xorstr_("aptitude.pub"), xorstr_("Visited Aptitude Website Since Restart \"aptitude.pub\"") },
            { xorstr_("visuals.gg"), xorstr_("Visited Visuals Website Since Restart \"visuals.gg\"") },
            { xorstr_("battlelog.com"), xorstr_("Visited Battlelog Website Since Restart \"battlelog.com\"") },
            { xorstr_("connerzon.com"), xorstr_("Visited Connerzon Website Since Restart \"connerzon.com\"") },
            { xorstr_("r6needs.store"), xorstr_("Visited R6Needs Website Since Restart \"r6needs.store\"") },
            { xorstr_("edaters.store"), xorstr_("Visited Edaters Website Since Restart \"edaters.store\"") },
            { xorstr_("beatbct.com"), xorstr_("Visited BeatBCT Website Since Restart \"beatbct.com\"") },
            { xorstr_("xerus.cc"), xorstr_("Visited Xerus Website Since Restart \"xerus.cc\"") },
            { xorstr_("overdose.support"), xorstr_("Visited Overdose Website Since Restart \"overdose.support\"") },
            { xorstr_("veylo.io"), xorstr_("Visited Veylo Website Since Restart \"veylo.io\"") },
            { xorstr_("chudvision.net"), xorstr_("Visited Chudvision Website Since Restart \"chudvision.net\"") },
            { xorstr_("exloader.net"), xorstr_("Visited ExLoader Website Since Restart \"exloader.net\"") },
            { xorstr_("battlelog.co"), xorstr_("Visited Battlelog CO Website Since Restart \"battlelog.co\"") },
            { xorstr_("sinfulexp.net"), xorstr_("Visited SinfulExp Website Since Restart \"sinfulexp.net\"") },
            { xorstr_("ancient.su"), xorstr_("Visited Ancient Website Since Restart \"ancient.su\"") },
            { xorstr_("enhancedsolutions.cc"), xorstr_("Visited Enhanced Solutions Website Since Restart \"enhancedsolutions.cc\"") },
            { xorstr_("closetware.store"), xorstr_("Visited Closetware Website Since Restart \"closetware.store\"") },
            { xorstr_("ghostware.cc"), xorstr_("Visited Ghostware Website Since Restart \"ghostware.cc\"") },
            { xorstr_("deception.gg"), xorstr_("Visited Deception Website Since Restart \"deception.gg\"") },
            { xorstr_("hexdma.com"), xorstr_("Visited HexDMA Website Since Restart \"hexdma.com\"") },
            { xorstr_("aquacheats.cc"), xorstr_("Visited AquaCheats Website Since Restart \"aquacheats.cc\"") },
            { xorstr_("calamari.lol"), xorstr_("Visited Calamari Website Since Restart \"calamari.lol\"") },
            { xorstr_("elocarry.net"), xorstr_("Visited EloCarry Website Since Restart \"elocarry.net\"") },
            { xorstr_("lavicheats.com"), xorstr_("Visited LaviCheats Website Since Restart \"lavicheats.com\"") },
            { xorstr_("gear5.sellpass.io"), xorstr_("Visited Gear5 Website Since Restart \"gear5.sellpass.io\"") },
            { xorstr_("reportedcheats.com"), xorstr_("Visited ReportedCheats Website Since Restart \"reportedcheats.com\"") },
            { xorstr_("outkastcheats.com"), xorstr_("Visited OutkastCheats Website Since Restart \"outkastcheats.com\"") },
            { xorstr_("kernelsight.com"), xorstr_("Visited KernelSight Website Since Restart \"kernelsight.com\"") },
            { xorstr_("klar.gg"), xorstr_("Visited Klar Website Since Restart \"klar.gg\"") },
            { xorstr_("lethalcheats.net"), xorstr_("Visited LethalCheats Website Since Restart \"lethalcheats.net\"") },
            { xorstr_("lynxtech.pro"), xorstr_("Visited LynxTech Website Since Restart \"lynxtech.pro\"") },
            { xorstr_("unknowncheats.me"), xorstr_("Visited UnknownCheats Website Since Restart \"unknowncheats.me\"") },
            { xorstr_("playsharp.io"), xorstr_("Visited PlaySharp Website Since Restart \"playsharp.io\"") },
            { xorstr_("1nvituscheats.com"), xorstr_("Visited 1nvitus Cheats Website Since Restart \"1nvituscheats.com\"") },
            { xorstr_("shopring1nvitus.com"), xorstr_("Visited ShopRing 1nvitus Website Since Restart \"shopring1nvitus.com\"") },
            {xorstr_("red-xservices.com"), xorstr_("Visited Red X Services Website Since Restart \"red-xservices.com\"")},

            #elif DETECT_COD

            {xorstr_("streckaio.com"), xorstr_("Visited Strecka.io Website Since Restart \"streckaio.com\"")},

            #elif DETECT_CS

            {xorstr_("memesense.gg"), xorstr_("Visited Memesense Website Since Restart \"memesense.gg\"")},
            {xorstr_("midnight.im"), xorstr_("Visited Midnight Website Since Restart \"midnight.im\"")},
            {xorstr_("gamesense.vip"), xorstr_("Visited GameSense Website Since Restart \"gamesense.vip\"")},

            #endif

            {xorstr_("auth.gg"), xorstr_("Visited Auth.gg Website Since Restart \"auth.gg\"")},
            {xorstr_("keyauth.com"), xorstr_("Visited KeyAuth Website Since Restart \"keyauth.com\"")},
            {xorstr_("aimjunkies.com"), xorstr_("Visited AimJunkies Website Since Restart \"aimjunkies.com\"")},
            {xorstr_("systemcheats.net"), xorstr_("Visited SystemCheats Website Since Restart \"systemcheats.net\"")},
            {xorstr_("engineowning.to"), xorstr_("Visited EngineOwning Website Since Restart \"engineowning.to\"")},
            {xorstr_("skeet.cc"), xorstr_("Visited Skeet Website Since Restart \"skeet.cc\"")},
            {xorstr_("gamesense.pub"), xorstr_("Visited GameSense Website Since Restart \"gamesense.pub\"")},
            {xorstr_("primordial.dev"), xorstr_("Visited Primordial Website Since Restart \"primordial.dev\"")},
            {xorstr_("neverlose.cc"), xorstr_("Visited Neverlose Website Since Restart \"neverlose.cc\"")},
            {xorstr_("fatality.win"), xorstr_("Visited Fatality Website Since Restart \"fatality.win\"")},
            {xorstr_("onetap.com"), xorstr_("Visited OneTap Website Since Restart \"onetap.com\"")},
            {xorstr_("onetap.su"), xorstr_("Visited OneTap Website Since Restart \"onetap.su\"")},
            {xorstr_("skreech.gg"), xorstr_("Visited Skreech Website Since Restart \"skreech.gg\"")},
            {xorstr_("cheatsense.sellhub.cx"), xorstr_("Visited CheatSense Website Since Restart \"cheatsense.sellhub.cx\"")},
            {xorstr_("r6hibania.cc"), xorstr_("Visited R6 Hibania Website Since Restart \"r6hibania.cc\"")},
            {xorstr_("chair.wtf"), xorstr_("Visited Chair Website Since Restart \"chair.wtf\"")},
            {xorstr_("tomware.cc"), xorstr_("Visited Tomware Website Since Restart \"tomware.cc\"")},
            {xorstr_("rankuen.com"), xorstr_("Visited Rankuen Website Since Restart \"rankuen.com\"")},
            {xorstr_("shop.deception.gg"), xorstr_("Visited Deception Shop Website Since Restart \"shop.deception.gg\"")},
            {xorstr_("phoenixlabstore.com"), xorstr_("Visited Phoenix Lab Website Since Restart \"phoenixlabstore.com\"")},
            {xorstr_("oxxscheats.com"), xorstr_("Visited OxxsCheats Website Since Restart \"oxxscheats.com\"")},
            {xorstr_("vega.sell.app"), xorstr_("Visited Vega Website Since Restart \"vega.sell.app\"")},
            {xorstr_("cheats.love"), xorstr_("Visited Cheats.love Website Since Restart \"cheats.love\"")},
            {xorstr_("chamscheats.com"), xorstr_("Visited ChamsCheats Website Since Restart \"chamscheats.com\"")},
            {xorstr_("whyyoucheating.sellhub.cx"), xorstr_("Visited WhyYouCheating Website Since Restart \"whyyoucheating.sellhub.cx\"")},
            {xorstr_("tgmodz.com"), xorstr_("Visited TGModz Website Since Restart \"tgmodz.com\"")},
            {xorstr_("ezmod.vip"), xorstr_("Visited EzMod Website Since Restart \"ezmod.vip\"")},
            {xorstr_("ssz.gg"), xorstr_("Visited SSZ Website Since Restart \"ssz.gg\"")},
            {xorstr_("download.antarcticacheats.xyz"), xorstr_("Visited Antarctica Cheats Website Since Restart \"download.antarcticacheats.xyz\"")},
            {xorstr_("antarctica.sellpass.io"), xorstr_("Visited Antarctica Cheats Website Since Restart \"antarctica.sellpass.io\"")},
            {xorstr_("antarcticacheats.xyz"), xorstr_("Visited Antarctica Cheats Website Since Restart \"antarcticacheats.xyz\"")},
            {xorstr_("perc.gg"), xorstr_("Visited Perc Website Since Restart \"perc.gg\"")},
            {xorstr_("pcileech.com"), xorstr_("Visited PCILeech Website Since Restart \"pcileech.com\"")},
            {xorstr_("memprocfs.com"), xorstr_("Visited MemProcFS Website Since Restart \"memprocfs.com\"")},
            {xorstr_("dma-shop.com"), xorstr_("Visited DMA Shop Website Since Restart \"dma-shop.com\"")},
            {xorstr_("fpgacheats.com"), xorstr_("Visited FPGA Cheats Website Since Restart \"fpgacheats.com\"")},
            {xorstr_("dmastore.gg"), xorstr_("Visited DMA Store Website Since Restart \"dmastore.gg\"")},
            {xorstr_("squirreldma.com"), xorstr_("Visited Squirrel DMA Website Since Restart \"squirreldma.com\"")},
            {xorstr_("leechcore.com"), xorstr_("Visited LeechCore Website Since Restart \"leechcore.com\"")},
            {xorstr_("kmboxb.com"), xorstr_("Visited KMBox B Website Since Restart \"kmboxb.com\"")},
            {xorstr_("kmbox.pro"), xorstr_("Visited KMBox Website Since Restart \"kmbox.pro\"")},
            {xorstr_("arduino-cheat.com"), xorstr_("Visited Arduino Cheat Website Since Restart \"arduino-cheat.com\"")},
            {xorstr_("guided-hacking.com"), xorstr_("Visited Guided Hacking Website Since Restart \"guided-hacking.com\"")},
            {xorstr_("hackforums.net"), xorstr_("Visited HackForums Website Since Restart \"hackforums.net\"")},
            {xorstr_("mpgh.net"), xorstr_("Visited MPGH Website Since Restart \"mpgh.net\"")},
            {xorstr_("cheatautomation.com"), xorstr_("Visited Cheat Automation Website Since Restart \"cheatautomation.com\"")},
            {xorstr_("aimware.net"), xorstr_("Visited Aimware Website Since Restart \"aimware.net\"")},
            {xorstr_("interwebz.cc"), xorstr_("Visited Interwebz Website Since Restart \"interwebz.cc\"")},
            {xorstr_("lmaobox.net"), xorstr_("Visited LMAOBox Website Since Restart \"lmaobox.net\"")},
            {xorstr_("streamline-cheats.com"), xorstr_("Visited Streamline Cheats Website Since Restart \"streamline-cheats.com\"")},
            {xorstr_("nixware.cc"), xorstr_("Visited Nixware Website Since Restart \"nixware.cc\"")},
            {xorstr_("pandora-cheats.com"), xorstr_("Visited Pandora Cheats Website Since Restart \"pandora-cheats.com\"")},
            {xorstr_("hyperion-cheats.com"), xorstr_("Visited Hyperion Cheats Website Since Restart \"hyperion-cheats.com\"")},
            {xorstr_("cobracheats.com"), xorstr_("Visited Cobra Cheats Website Since Restart \"cobracheats.com\"")},
            {xorstr_("sellpass.io"), xorstr_("Visited Sellpass Website Since Restart \"sellpass.io\"")},
            {xorstr_("whop.com"), xorstr_("Visited Whop Website Since Restart \"whop.com\"")},
            {xorstr_("enigmadma.com"), xorstr_("Visited Enigma DMA Website Since Restart \"enigmadma.com\"")},
            {xorstr_("dma-fw.com"), xorstr_("Visited DMA Firmware Website Since Restart \"dma-fw.com\"")},
            {xorstr_("fpga-cheats.com"), xorstr_("Visited FPGA Cheats Website Since Restart \"fpga-cheats.com\"")},
            {xorstr_("lambdaconcept.com"), xorstr_("Visited LambdaConcept Website Since Restart \"lambdaconcept.com\"")},
            {xorstr_("squirreldma.gg"), xorstr_("Visited Squirrel DMA Website Since Restart \"squirreldma.gg\"")},
            {xorstr_("pcileech.io"), xorstr_("Visited PCILeech Website Since Restart \"pcileech.io\"")},
            {xorstr_("dmatools.net"), xorstr_("Visited DMA Tools Website Since Restart \"dmatools.net\"")},
            {xorstr_("hwid-spoofer.com"), xorstr_("Visited HWID Spoofer Website Since Restart \"hwid-spoofer.com\"")},
            {xorstr_("hwid-ban.com"), xorstr_("Visited HWID Ban Website Since Restart \"hwid-ban.com\"")},
            {xorstr_("rena.lol"), xorstr_("Visited Rena Website Since Restart \"rena.lol\"")},
            {xorstr_("keyauth.win"), xorstr_("Visited KeyAuth Website Since Restart \"keyauth.win\"")},
            {xorstr_("keyauth.cc"), xorstr_("Visited KeyAuth Website Since Restart \"keyauth.cc\"")},
            {xorstr_("keyauth"), xorstr_("Visited KeyAuth Website Since Restart \"keyauth\"")},
            {xorstr_("2.56.246.3"), xorstr_("Visited Revuelto Website Since Restart \"2.56.246.3\"")},
            {xorstr_("Localhost:"), xorstr_("Visited Localhost Since Restart")},

};

std::vector<std::pair<std::string, std::string>> dnsscan::get_custom_filters_only() {
    try {
        static std::vector<std::pair<std::string, std::string>> filters;
        static bool initialized = false;
        if (initialized) return filters;
        filters.clear();

        std::string json_data = custom_strings::fetch_json(xorstr_("https://detect.ac/auth/user/strings/getstrings/") + detect.pin);
        if (!json_data.empty()) {
            try {
                nlohmann::json parsed_json = nlohmann::json::parse(json_data);
                if (parsed_json.contains(xorstr_("customStrings")) && parsed_json[xorstr_("customStrings")].is_array()) {
                    for (auto& entry : parsed_json[xorstr_("customStrings")]) {
                        if (entry.contains(xorstr_("processName")) && entry.contains(xorstr_("strings"))) {
                            std::string process_name = entry[xorstr_("processName")].get<std::string>();
                            std::string raw_strings = entry[xorstr_("strings")].get<std::string>();
                            if (process_name == xorstr_("Dnscache")) {
                                size_t pos = 0;
                                while (pos < raw_strings.size()) {
                                    size_t next = raw_strings.find(xorstr_("\r\n"), pos);
                                    std::string line;
                                    if (next == std::string::npos) { line = raw_strings.substr(pos); pos = raw_strings.size(); }
                                    else { line = raw_strings.substr(pos, next - pos); pos = next + 2; }

                                    line = sanitize_ascii_printable(line);
                                    if (line.empty()) continue;

                                    auto parts = split_custom_string(line);
                                    std::string name = sanitize_ascii_printable(parts.first);
                                    std::string value = sanitize_ascii_printable(parts.second);
                                    if (!value.empty() && !name.empty()) filters.emplace_back(value, name);
                                }
                            }
                        }
                    }
                }
            }
            catch (...) {}
        }

        initialized = true;
        return filters;
    }
    catch (...) { return {}; }
    return {};
}

bool dnsscan::apply_filter(const std::string& memory_string, const std::pair<std::string, std::string>& filter, bool is_custom) {
    try {
        if (filter.first.empty() || memory_string.empty()) return false;

        std::string mem_lower = memory_string;
        for (char& c : mem_lower) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }
        std::string value_lower = filter.first;
        for (char& c : value_lower) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }

        if (mem_lower.find(value_lower) == std::string::npos) return false;

        static std::unordered_set<std::string> detected_strings;
        std::string unique_key = memory_string + filter.second;
        if (detected_strings.insert(unique_key).second) {
            if (is_custom)
                LOG(WARNING, xorstr_("N/A")) << xorstr_("Custom String ") + filter.second + xorstr_(" Found:") + memory_string;
            else
                LOG(WARNING, xorstr_("N/A")) << filter.second << xorstr_(" Found In Dnscache:") << memory_string;
        }
        return true;
    }
    catch (...) { return false; }
}

void dnsscan::scan_process_memory(HANDLE h_process) {
    try {
        auto custom_filters     = get_custom_filters_only();
        auto hardcoded_snapshot = hardcoded_filters;
        if (custom_filters.empty() && hardcoded_snapshot.empty()) return;

        static custom_strings::fast_matcher matcher;
        static bool                         matcher_ready = false;
        if (!matcher_ready) {
            matcher.prepare(custom_filters, hardcoded_snapshot);
            matcher_ready = true;
        }
        if (matcher.empty()) return;

        auto emit = [](const custom_strings::fast_matcher::entry& e,
                       const std::string& original)
        {
            if (e.is_custom)
                LOG(WARNING, xorstr_("N/A")) << xorstr_("Custom String ") + e.name + xorstr_(" Found:") + original;
            else
                LOG(WARNING, xorstr_("N/A")) << e.name << xorstr_(" Found In Dnscache:") << original;
        };

        MEMORY_BASIC_INFORMATION mbi;
        constexpr SIZE_T BUF_SIZE = 65536;
        unsigned char buffer[BUF_SIZE];
        SIZE_T bytes_read;

        std::string ascii_string;
        std::string utf16_ascii;
        ascii_string.reserve(1024);
        utf16_ascii.reserve(1024);

        for (PBYTE address = 0;
             VirtualQueryEx(h_process, address, &mbi, sizeof(mbi)) == sizeof(mbi);
             address += mbi.RegionSize)
        {
            if (mbi.State != MEM_COMMIT ||
                !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                continue;

            for (PBYTE addr = (PBYTE)mbi.BaseAddress;
                 addr < (PBYTE)mbi.BaseAddress + mbi.RegionSize;
                 addr += BUF_SIZE)
            {
                if (!ReadProcessMemory(h_process, addr, buffer, BUF_SIZE, &bytes_read)) continue;

                ascii_string.clear();
                for (SIZE_T i = 0; i < bytes_read; ++i) {
                    const unsigned char c = buffer[i];
                    if (c >= 0x20 && c <= 0x7E) {
                        ascii_string.push_back(static_cast<char>(c));
                    } else {
                        if (ascii_string.size() >= MIN_STRING_LENGTH) matcher.scan(ascii_string, emit);
                        ascii_string.clear();
                    }
                }
                if (ascii_string.size() >= MIN_STRING_LENGTH) matcher.scan(ascii_string, emit);

                utf16_ascii.clear();
                for (SIZE_T i = 0; i + 1 < bytes_read; i += 2) {
                    const unsigned char lo = buffer[i];
                    const unsigned char hi = buffer[i + 1];
                    if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
                        utf16_ascii.push_back(static_cast<char>(lo));
                    } else {
                        if (utf16_ascii.size() >= MIN_STRING_LENGTH) matcher.scan(utf16_ascii, emit);
                        utf16_ascii.clear();
                    }
                }
                if (utf16_ascii.size() >= MIN_STRING_LENGTH) matcher.scan(utf16_ascii, emit);
            }
        }
    }
    catch (...) {}
}

void dnsscan::start_dns_scan() {
    try {
        if (!dnsscan::enable_debug_privilege()) return;

        DWORD process_id = dnsscan::get_process_id_by_name(xorstr_("Dnscache"));
        if (process_id == 0) return;

        HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
        if (!h_process) return;

        dnsscan::scan_process_memory(h_process);

        CloseHandle(h_process);
    }
    catch (...) {}
}
