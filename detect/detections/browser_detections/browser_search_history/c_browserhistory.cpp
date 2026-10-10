#include "c_browserhistory.h"

namespace fs = std::filesystem;

namespace {
    struct ScopedTempFile {
        std::string path;
        explicit ScopedTempFile(const char* prefix) {
            char dir[MAX_PATH] = { 0 };
            char file[MAX_PATH] = { 0 };
            DWORD n = GetTempPathA(MAX_PATH, dir);
            if (n == 0 || n > MAX_PATH) return;
            if (GetTempFileNameA(dir, prefix, 0, file) == 0) return;
            path = file;
        }
        ~ScopedTempFile() {
            if (path.empty()) return;
            for (int attempt = 0; attempt < 5; ++attempt) {
                if (DeleteFileA(path.c_str())) return;
                const DWORD err = GetLastError();
                if (err != ERROR_SHARING_VIOLATION && err != ERROR_ACCESS_DENIED) return;
                Sleep(20);
            }
        }
        ScopedTempFile(const ScopedTempFile&)            = delete;
        ScopedTempFile& operator=(const ScopedTempFile&) = delete;
    };
}

static std::string ChromeTimeToLocal(int64_t chromeTime) {
    if (chromeTime <= 0) return "";
    ULARGE_INTEGER uli;
    uli.QuadPart = static_cast<ULONGLONG>(chromeTime) * 10;
    FILETIME ft;
    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;
    SYSTEMTIME stUTC = { 0 }, stLocal = { 0 };
    if (!FileTimeToSystemTime(&ft, &stUTC) || !SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal))
        return "";
    char buf[64];
    snprintf(buf, sizeof(buf), xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    return buf;
}

static std::string FirefoxTimeToLocal(int64_t firefoxTime) {
    if (firefoxTime <= 0) return "";
    time_t unixTime = static_cast<time_t>(firefoxTime / 1000000);
    struct tm localTm;
    if (localtime_s(&localTm, &unixTime) != 0) return "";
    char buf[64];
    snprintf(buf, sizeof(buf), xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
        localTm.tm_year + 1900, localTm.tm_mon + 1, localTm.tm_mday,
        localTm.tm_hour, localTm.tm_min, localTm.tm_sec);
    return buf;
}

static std::map<std::string, std::string> keywords = {

#ifdef DETECT_FIVEM

{xorstr_("skript.gg"), xorstr_("Visited Skript Website")},
{xorstr_("tzproject.com"), xorstr_("Visited TZ Project Website")},
{xorstr_("hxcheats.tech"), xorstr_("Visited Hx Cheats Website")},
{xorstr_("gosth.gg"), xorstr_("Visited Gosth Website")},
{xorstr_("ghostesportpanel.com"), xorstr_("Visited Gosth Website")},
{xorstr_("eulencheats.com"), xorstr_("Visited Eulen Website")},
{xorstr_("eulen.cc"), xorstr_("Visited Eulen Website")},
{xorstr_("luamenu.xyz"), xorstr_("Visited Lua (RedEngine) Website")},
{xorstr_("redengine.eu"), xorstr_("Visited RedEngine Website")},
{xorstr_("redengine.net"), xorstr_("Visited RedEngine Website")},
{xorstr_("susano.re"), xorstr_("Visited Susano Website")},
{xorstr_("machocheats.com"), xorstr_("Visited Macho Cheats Website")},
{xorstr_("88-cheats.xyz"), xorstr_("Visited 88 Cheats Website")},
{xorstr_("testo.gg"), xorstr_("Visited Testo Cheats Website")},
{xorstr_("blackout.wtf"), xorstr_("Visited Blackout Cheats Website")},
{xorstr_("monstermenu.cc"), xorstr_("Visited Monster Menu Website")},
{xorstr_("9zproject.xyz"), xorstr_("Visited 9z Project Website")},
{xorstr_("sergiu.pro"), xorstr_("Visited Spotless Website")},
{xorstr_("projectdow.com"), xorstr_("Visited Dow Website")},
{xorstr_("api.shilav2.shop"), xorstr_("Visited Wexless Website")},
{xorstr_("193.23.160.168"), xorstr_("Visited Signer Website")},
{xorstr_("orbit.signer.cc"), xorstr_("Visited Signer Website")},
{xorstr_("signer.cc"), xorstr_("Visited Signer Website")},
{xorstr_("bypass.fun"), xorstr_("Visited Bypass.Fun Website")},
{xorstr_("keyser-lts.com"), xorstr_("Visited Keyser Website")},
{xorstr_("keyser.gg"), xorstr_("Visited Keyser Website")},
{xorstr_("185.236.228.154"), xorstr_("Visited FLK Website")},
{xorstr_("flkstore.com"), xorstr_("Visited FLK Website")},
{xorstr_("flk-uhq.xyz"), xorstr_("Visited FLK Website")},
{xorstr_("5.206.224.37"), xorstr_("Visited FLK Website")},
{xorstr_("bebetter-fivem"), xorstr_("Visited Be-better Website")},
{xorstr_("venacy.club"), xorstr_("Visited Venacy Website")},
{xorstr_("antiecho.xyz"), xorstr_("Visited Ant-Echo Website")},
{xorstr_("203.159.90.127"), xorstr_("Visited Lethality Script Website")},
{xorstr_("leet-cheats.ru"), xorstr_("Visited Leet Cheats Website")},
{xorstr_("hydrogen.ac"), xorstr_("Visited Hydrogen Cheats Website")},
{xorstr_("trinitas.top"), xorstr_("Visited Trinitas Cheats Website")},
{xorstr_("blurred.gg"), xorstr_("Visited Blurred.gg Website")},
{ xorstr_("captaindma.com"), xorstr_("Visite Captain DMA Website") },
{ xorstr_("pulsedma.com"), xorstr_("Visited Pulse DMA Website") },
{ xorstr_("makcu.com"), xorstr_("Visited Makcu Website") },
{ xorstr_("vanish-cheat.com"), xorstr_("Visited Vanish Website") },
{ xorstr_("91.218.66.77"), xorstr_("Visited Forte Website") },
{ xorstr_("uzuimarket.xyz"), xorstr_("Visited Uzui Market Website") },
{ xorstr_("spotless.gg"), xorstr_("Visited Spotless Bypass Website") },
{xorstr_("https://download2300.mediafire.com/20hagb9obougVGckfHglHU-VIz_NiaJVFd7H_-5DICs4CLBnZdqHeuuhiERvcK-ae58m7NxAgHHF4mddiYAPoMSvS9HsVJ2oKP2xBXWj9-JFybxVGYBkBhoDd9sAqkDIHuJCm_J16MiE33kZtWSTTRxE_VfF3xAqS80tvnnKVPLukw/duru9jadxca89fy/Povika+Hitbox.zip"), xorstr_("Visited Povika Hitbox Website")},
{xorstr_("https://download2389.mediafire.com/jj92lf2hy1ogqRVYSzLw_suPpYUPBsKK2ri5ZF6l8j4PDqBR2B8-jz6Vm3OqUZyUPVYTGX9NCO4HJu7DnoaACZamv5TWiefUF28SRqj_XNYw8k7s9eeskXBEqza5W6ETXeef-KXimrKcjFj1LQFaDRTVyb1MDbkAMIlujMAJypvqcg/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip"), xorstr_("Visited CustomH1itb0x3s Website")},
{xorstr_("https://takeout-download-drive-eu.usercontent.google.com/download/drive-download-20250820T093435Z-1-001.zip?j=a527cd61-807b-4987-9bd7-381e2ed43797&i=0&user=37111652107&authuser=0"), xorstr_("Visited ShenanigansHitbox Website")},
{xorstr_("https://drive.usercontent.google.com/download?id=1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm&export=download&authuser=0&confirm=t&uuid=0e3b40f5-f404-46b3-9255-720e0c5d00a5&at=AN8xHooRPecdZg_qEx2RN_wv8Gn-%3A1755682572030"), xorstr_("Visited Aimbot Redux Website")},
{xorstr_("https://drive.usercontent.google.com/download?id=1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7&export=download&authuser=0&confirm=t&uuid=f1ba70dd-9fe5-4de7-bf7c-0b5dcdfc7a33&at=AN8xHoq-0-1eyiz5Ekw1pv0ml9fL%3A1755682613990"), xorstr_("Visited Redux Cheat Website")},
{xorstr_("https://drive.usercontent.google.com/download?id=1YJ0SNGLQiR-dD4w5gMYFZCq0cpIqkyHQ&export=download&authuser=0&confirm=t&uuid=cc723d0c-1b99-4cd5-b7ad-9ceaed267d1e&at=AN8xHooIObZI-qg9wbKhxuCmUrq5%3A1755686597792"), xorstr_("Visited Redux Hacks Website")},
{xorstr_("https://socialwolvez.com/app/l/fwOQWj"), xorstr_("Visited Povika Hitbox Website")},
{xorstr_("https://www.mediafire.com/file/duru9jadxca89fy/Povika+Hitbox.zip/file"), xorstr_("Visited Povika Hitbox Website")},
{xorstr_("https://sub4unlock.io/4cWyE"), xorstr_("Visited CustomH1itb0x3s Website")},
{xorstr_("https://www.mediafire.com/file/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip/file"), xorstr_("Visited CustomH1itb0x3s Website")},
{xorstr_("https://drive.google.com/drive/folders/1qUtxrVbDP2S5mZcXISrcMcs4dsHWtj4g?usp=sharing"), xorstr_("Visited ShenanigansHitboxDrive Website")},
{xorstr_("https://drive.google.com/file/d/1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm/view"), xorstr_("Visited Ro9anAimDrive Website")},
{xorstr_("https://drive.google.com/file/d/1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7/view"), xorstr_("Visited Ro9anReduxDrive Website")},
{xorstr_("https://workupload.com/file/BxAnEw56J9N"), xorstr_("Visited ShaxFreeCheat Website")},
{xorstr_("https://sub4unlock.com/SL/1528315"), xorstr_("Visited ShaxCheatReduxV7 Website")},
{xorstr_("traceless.wtf"), xorstr_("Visited Traceless Bypass Website")},
{xorstr_("a.pomf.cat/glNyzpV"), xorstr_("Visited 9Z Bypass Website")},
{xorstr_("a.pomf.cat/UgdZcKh"), xorstr_("Visited 9Z Bypass Website")},
{xorstr_("serapi.mom"), xorstr_("Visited Spotless/Binary Bypass Website")},
{xorstr_("freshbypass.xyz"), xorstr_("Visited Fresh Bypass Website")},
{xorstr_("designcraft.xyz"), xorstr_("Visited Response Bypass Website")},
{xorstr_("snowbp.xyz"), xorstr_("Visited Snow Bypass Website")},
{xorstr_("87.120.191.29"), xorstr_("Visited Quanta Website")},
{xorstr_("club44.lol"), xorstr_("Visited Club44 Website")},
{xorstr_("catatau.xyz"), xorstr_("Visited XYZ DMA Website")},
{xorstr_("auis.binaryy.top"), xorstr_("Visited Binary Bypass Website")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co"), xorstr_("Visited Binary Bypass")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/auth-login"), xorstr_("Visited Binary Bypass Login Page")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/vpn-check"), xorstr_("Visited Binary Bypass VPN Check Page")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co/rest/v1/rpc/get_maintenance_mode"), xorstr_("Visited Binary Bypass Maintinence Page")},
{xorstr_("serotonin.win"), xorstr_("Visited Serotonin Bypass")},
{xorstr_("181.215.45.13"), xorstr_("Visited Club44 Bypass")},
{xorstr_("93.127.215.67"), xorstr_("Visited Club44 Bypass")},
{xorstr_("severance.today"), xorstr_("Visited Severance Bypass")},
{xorstr_("gnomus.lol/mefedron/ziolo/ukrainski_igraszki/"), xorstr_("Visited FiveM Enjoyer Website")},
{xorstr_("gnomus.lol"), xorstr_("Visited FiveM Enjoyer Website")},
{xorstr_("pub-047df53bbd524128a2b8f1477ec0e316.r2.dev"), xorstr_("Visited Severance Bypass Website")},
{xorstr_("45.156.87.118"), xorstr_("Visited Unknown Bypass Website")},
{xorstr_("16.171.254.8"), xorstr_("Visited Bypass.fun Website")},
{xorstr_("certificate.wtf"), xorstr_("Visited certificate.wtf Website")},
{xorstr_("cosmos.pm"), xorstr_("Visited Cosmos Website")},
{xorstr_("rxmenu.shop"), xorstr_("Visited RX Menu Website")},
{xorstr_("omertasoftware.com"), xorstr_("Visited Omerta Software Website")},
{xorstr_("xentro.xyz"), xorstr_("Visited Xentro Website")},
{xorstr_("titanbypass.com"), xorstr_("Visited Titan Bypass Website")},
{xorstr_("us1.phase.uno"), xorstr_("Visited Phase Uno")},
{xorstr_("phase.uno"), xorstr_("Visited Phase Uno")},
{xorstr_("104.21.82.227"), xorstr_("Visited Phase Uno")},
{xorstr_("104.18.2.36"), xorstr_("Visited Phase Uno")},
{xorstr_("wizardbypass.com"), xorstr_("Visited Wizard Bypass Website")},
{xorstr_("loginlive.cloud"), xorstr_("Visited Wizard Bypass Website")},
{xorstr_("54.39.67.23"), xorstr_("Visited Rolex Bypass")},
{xorstr_("richh.lol"), xorstr_("Visited Rolex Bypass Website")},
{xorstr_("antiscan.xyz"), xorstr_("Visited Rolex Bypass Website")},
{xorstr_("evora.pw"), xorstr_("Visited Evora Website")},
{xorstr_("45.143.196.213"), xorstr_("Visited Bytecode Bypass Website")},
{xorstr_("Sirius.lv"), xorstr_("Visited Sirius Bypass Website")},

#elif DETECT_MINECRAFT

{xorstr_("drip.gg"), xorstr_("Visited Drip Website")},
{xorstr_("karma.rip"), xorstr_("Visited Karma Website")},
{xorstr_("vape.gg"), xorstr_("Visited Vape Website")},
{xorstr_("sunset.rip"), xorstr_("Visited Sunset Website")},
{xorstr_("doomsdayclient.com"), xorstr_("Visited Doomsday Website")},
{xorstr_("neverlack.in"), xorstr_("Visited Drip Website")},
{xorstr_("akiraghost.com"), xorstr_("Visited Akira Website")},
{xorstr_("entropy.club"), xorstr_("Visited Entropy Website")},
{xorstr_("dreamclient.xyz"), xorstr_("Visited Dream Website")},
{xorstr_("crypp.in"), xorstr_("Visited Dream Website")},
{xorstr_("dopp.in"), xorstr_("Visited Dopp Website")},
{xorstr_("slapp.in"), xorstr_("Visited Slatt Website")},
{xorstr_("unicorn-hacks.net"), xorstr_("Visited Unicorn Website")},
{xorstr_("prestigeclient.vip"), xorstr_("Visited Prestigeclient Website")},
{xorstr_("api.prestigeclient.vip"), xorstr_("Visited Prestigeclient API Website")},
{xorstr_("bypassing.gg"), xorstr_("Visited Cold Bypassing Website")},
{xorstr_("grimclient.eu"), xorstr_("Visited Grim Website")},
{xorstr_("axen.lol"), xorstr_("Visited Axen Website")},
{xorstr_("aristois.net"), xorstr_("Visited Aristois Website")},
{xorstr_("catlean.su"), xorstr_("Visited Catlean Website")},
{xorstr_("client-analytics.dev"), xorstr_("Visited Cold Bypass Website")},

#elif DETECT_ROBLOX

{xorstr_("robloxcheatz.com"), xorstr_("Visited Robloxcheatz Website")},
{xorstr_("radiant.cc"), xorstr_("Visited Radiant Website")},
{xorstr_("eternalproduct.com"), xorstr_("Visited Eternal Product Website")},
{xorstr_("matrixhubs.shop"), xorstr_("Visited Matrix Website")},
{xorstr_("buymtx.online"), xorstr_("Visited Matrix Website")},
{xorstr_("buymtx"), xorstr_("Visited Matrix Website")},
{xorstr_("mega.nz/folder/KehEhLzB#Cs0PiuqggmwItBIcAG4z6w"), xorstr_("Visited Mooze MegaFolder")},
{xorstr_("mooze.fun"), xorstr_("Visited Mooze Website")},
{xorstr_("hastebin.skyra.pw"), xorstr_("Visited Config Website")},
{xorstr_("vapevoidware.xyz"), xorstr_("Visited Voidware Website")},
{xorstr_("voxlis.net"), xorstr_("Visited Voxlis Website")},
{xorstr_("github.com/dutchpsycho/Roblox-TITAN-Spoofer-Hyperion"), xorstr_("Visited Titan Spoofer Github Repository")},
{xorstr_("voltbz.net"), xorstr_("Visited Volt Website")},
{xorstr_("potassium.pro"), xorstr_("Visited Potassium Website")},
{xorstr_("getwave.gg"), xorstr_("Visited Wave Website")},
{xorstr_("z.synapse.do"), xorstr_("Visited Synapse Z Website")},
{xorstr_("seliware.com"), xorstr_("Visited Seliware Website")},
{xorstr_("getmadium.net"), xorstr_("Visited Madium Website")},
{xorstr_("realvelocity.xyz"), xorstr_("Visited Velocity Website")},
{xorstr_("sirhurt.net"), xorstr_("Visited SirHurt Website")},
{xorstr_("getsolara.dev"), xorstr_("Visited Solara Website")},
{xorstr_("xeno.now"), xorstr_("Visited Xeno Website")},
{xorstr_("raptor.fun"), xorstr_("Visited MacSploit Website")},
{xorstr_("deltaexploits.gg"), xorstr_("Visited Delta Exploits Website")},
{xorstr_("getcryptic.net"), xorstr_("Visited Cryptic Website")},
{xorstr_("vegax.gg"), xorstr_("Visited Vega X Website")},
{xorstr_("codex.lol"), xorstr_("Visited Codex Website")},
{xorstr_("serotonin.win"), xorstr_("Visited Serotonin Website")},
{xorstr_("matcha-latte.win"), xorstr_("Visited Matcha Website")},
{xorstr_("photonsys.sellpass.io"), xorstr_("Visited Photon Website")},
{xorstr_("cultofintellect.com"), xorstr_("Visited DX9WARE V2 Website")},
{xorstr_("vexor.wtf"), xorstr_("Visited Vexor Website")},

#elif DETECT_RUST

{xorstr_("onestopcheats"), xorstr_("Visited Onestopcheats Website")},
{xorstr_("blurred.gg"), xorstr_("Visited Blurred.gg Website")},
{ xorstr_("captaindma.com"), xorstr_("Visite Captain DMA Website") },
{ xorstr_("pulsedma.com"), xorstr_("Visited Pulse DMA Website") },
{ xorstr_("makcu.com"), xorstr_("Visited Makcu Website") },

#elif DETECT_FORTNITE

{xorstr_("skycheats"), xorstr_("Visited Skycheats Website")},
{xorstr_("SkyCheats.com"), xorstr_("Visited SkyCheats.com Website")},
{xorstr_("battlelog.co"), xorstr_("Visited battlelog Website")},
{xorstr_("aimclub.io"), xorstr_("Visited aimclub Website")},
{xorstr_("uniquehacks.store"), xorstr_("Visited uniquehacks Website")},
{xorstr_("privatecheatz.com"), xorstr_("Visited privatecheatz Website")},
{xorstr_("colossalcheats.com"), xorstr_("Visited colossalcheats Website")},
{xorstr_("hackerbot.net"), xorstr_("Visited hackerbot Website")},
{xorstr_("army-cheats.com"), xorstr_("Visited army-cheats Website")},
{xorstr_("spycheats.net"), xorstr_("Visited spycheats Website")},
{xorstr_("santana-tech.com/"), xorstr_("Visited santana-tech Website")},
{xorstr_("aimhax.net"), xorstr_("Visited aimhax Website")},
{xorstr_("kernelcheats.to"), xorstr_("Visited kernelcheats Website")},
{xorstr_("infinitycheats.net"), xorstr_("Visited infinitycheats Website")},
{xorstr_("xera-cheats.com"), xorstr_("Visited xera-cheats Website")},
{xorstr_("zeta-cheats.com"), xorstr_("Visited zeta-cheats Website")},
{xorstr_("neo-cheats.com"), xorstr_("Visited neo-cheats Website")},
{xorstr_("Lavicheats.com"), xorstr_("Visited Lavicheats Website")},
{xorstr_("cheating.gg"), xorstr_("Visited Cheating Website")},
{xorstr_("ventro.tech"), xorstr_("Visited Solaris Website")},
{xorstr_("sceptre.pro"), xorstr_("Visited Sceptre Website")},
{xorstr_("185.236.228.154"), xorstr_("Visited FLK Website")},
{xorstr_("flkstore.com"), xorstr_("Visited FLK Website")},
{xorstr_("flk-uhq.xyz"), xorstr_("Visited FLK Website")},
{xorstr_("5.206.224.37"), xorstr_("Visited FLK Website")},
{xorstr_("blurred.gg"), xorstr_("Visited Blurred.gg Website")},
{ xorstr_("captaindma.com"), xorstr_("Visite Captain DMA Website") },
{ xorstr_("pulsedma.com"), xorstr_("Visited Pulse DMA Website") },
{ xorstr_("makcu.com"), xorstr_("Visited Makcu Website") },
{ xorstr_("keyser-lts.com"), xorstr_("Visited Keyser Website") },
{ xorstr_("keyser.gg"), xorstr_("Visited Keyser Website") },
{ xorstr_("zombiecheats.com"), xorstr_("Visited Zombie Cheats Website") },
{ xorstr_("hypervision.gg"), xorstr_("Visited Hypervision Website") },
{ xorstr_("elocarry.net"), xorstr_("Visited Elocarry Website") },
{ xorstr_("engineowning.su"), xorstr_("Visited EngineOwning Website") },
{ xorstr_("uzuimarket.xyz"), xorstr_("Visited Uzui Market Website") },
{ xorstr_("exodus.fun"), xorstr_("Visited Exodus Cheats Website") },
{xorstr_("195.59.67.101"), xorstr_("Visited ICanHaZip Website")},
{xorstr_("icanhazip.com"), xorstr_("Visited ICanHaZip Website")},
{xorstr_("udsoftwares.com"), xorstr_("Visited UD Softwares Website")},
{xorstr_("crythosbackend-production.up.railway.app"), xorstr_("Visited Crythos Website")},

#elif DETECT_DAYZ

{xorstr_("stugware.com"), xorstr_("Visited Stugwware Website")},
{xorstr_("cheatseller.com"), xorstr_("Visited Cheatseller Website")},
{xorstr_("elitehacks.ru"), xorstr_("Visited Elite Hacks Website")},
{xorstr_("smgcheats.com"), xorstr_("Visited SMG Cheats Website")},
{xorstr_("battlelog.co"), xorstr_("Visited Battlelog Website")},
{xorstr_("ducks-services.com"), xorstr_("Visited Ducks Services Website")},
{xorstr_("skycheats.com"), xorstr_("Visited Sky Cheats Website")},
{xorstr_("elitepvpers.com"), xorstr_("Visited ElitePVPers Website")},
{xorstr_("kernaim.to"), xorstr_("Visited Kernaim Website")},
{xorstr_("ciroscript.com"), xorstr_("Visited CiroScript Website")},
{xorstr_("wh-satano.ru"), xorstr_("Visited WH Satano Website")},
{xorstr_("blast.hk"), xorstr_("Visited Blast Website")},
{xorstr_("cheatseller.ru"), xorstr_("Visited Cheatseller RU Website")},
{xorstr_("cheat.bz"), xorstr_("Visited Cheat BZ Website")},
{xorstr_("clutch-solution.com"), xorstr_("Visited Clutch Solution Website")},
{xorstr_("715team.ru"), xorstr_("Visited 715 Team Website")},
{xorstr_("labcorecheats.com"), xorstr_("Visited Labcore Cheats Website")},
{xorstr_("byster.one"), xorstr_("Visited Byster Website")},
{xorstr_("up-game.pro"), xorstr_("Visited Up Game Website")},
{xorstr_("zsoft.store"), xorstr_("Visited ZSoft Website")},
{xorstr_("dayzradar.715team.ru"), xorstr_("Visited DayZ Radar 715 Team Website")},

#elif DETECT_SIEGE

{ xorstr_("skreechware.com"), xorstr_("Visited Skreechware Website") },
{ xorstr_("cosmocheats.com"), xorstr_("Visited Cosmocheats Website") },
{ xorstr_("nyronai.com"), xorstr_("Visited Nyronai Website") },
{ xorstr_("aptitude.pub"), xorstr_("Visited Aptitude Website") },
{ xorstr_("visuals.gg"), xorstr_("Visited Visuals Website") },
{ xorstr_("battlelog.com"), xorstr_("Visited Battlelog Website") },
{ xorstr_("blurred.gg"), xorstr_("Visited Blurred.gg Website") },
{ xorstr_("captaindma.com"), xorstr_("Visite Captain DMA Website") },
{ xorstr_("pulsedma.com"), xorstr_("Visited Pulse DMA Website") },
{ xorstr_("makcu.com"), xorstr_("Visited Makcu Website") },
{ xorstr_("connerzon.com"), xorstr_("Visited Connerzon Website") },
{ xorstr_("r6needs.store"), xorstr_("Visited R6Needs Website") },
{ xorstr_("edaters.store"), xorstr_("Visited Edaters Website") },
{ xorstr_("beatbct.com"), xorstr_("Visited BeatBCT Website") },
{ xorstr_("xerus.cc"), xorstr_("Visited Xerus Website") },
{ xorstr_("overdose.support"), xorstr_("Visited Overdose Website") },
{ xorstr_("veylo.io"), xorstr_("Visited Veylo Website") },
{ xorstr_("chudvision.net"), xorstr_("Visited Chudvision Website") },
{ xorstr_("exloader.net"), xorstr_("Visited ExLoader Website") },
{ xorstr_("battlelog.co"), xorstr_("Visited Battlelog CO Website") },
{ xorstr_("sinfulexp.net"), xorstr_("Visited SinfulExp Website") },
{ xorstr_("ancient.su"), xorstr_("Visited Ancient Website") },
{ xorstr_("enhancedsolutions.cc"), xorstr_("Visited Enhanced Solutions Website") },
{ xorstr_("closetware.store"), xorstr_("Visited Closetware Website") },
{ xorstr_("ghostware.cc"), xorstr_("Visited Ghostware Website") },
{ xorstr_("deception.gg"), xorstr_("Visited Deception Website") },
{ xorstr_("hexdma.com"), xorstr_("Visited HexDMA Website") },
{ xorstr_("aquacheats.cc"), xorstr_("Visited AquaCheats Website") },
{ xorstr_("calamari.lol"), xorstr_("Visited Calamari Website") },
{ xorstr_("elocarry.net"), xorstr_("Visited EloCarry Website") },
{ xorstr_("lavicheats.com"), xorstr_("Visited LaviCheats Website") },
{ xorstr_("gear5.sellpass.io"), xorstr_("Visited Gear5 Website") },
{ xorstr_("reportedcheats.com"), xorstr_("Visited ReportedCheats Website") },
{ xorstr_("outkastcheats.com"), xorstr_("Visited OutkastCheats Website") },
{ xorstr_("kernelsight.com"), xorstr_("Visited KernelSight Website") },
{ xorstr_("klar.gg"), xorstr_("Visited Klar Website") },
{ xorstr_("lethalcheats.net"), xorstr_("Visited LethalCheats Website") },
{ xorstr_("lynxtech.pro"), xorstr_("Visited LynxTech Website") },
{ xorstr_("unknowncheats.me"), xorstr_("Visited UnknownCheats Website") },
{ xorstr_("playsharp.io"), xorstr_("Visited PlaySharp Website") },
{ xorstr_("1nvituscheats.com"), xorstr_("Visited 1nvitus Cheats Website") },
{ xorstr_("shopring1nvitus.com"), xorstr_("Visited ShopRing 1nvitus Website") },
{ xorstr_("red-xservices.com"), xorstr_("Visited Red X Services Website") },

#elif DETECT_COD

{ xorstr_("streckaio.com"), xorstr_("Visited Strecka.io Website") },

#elif DETECT_CS

{xorstr_("memesense.gg"), xorstr_("Visited Memesense Website")},
{xorstr_("midnight.im"), xorstr_("Visited Midnight Website")},
{xorstr_("gamesense.vip"), xorstr_("Visited GameSense Website")},

#endif

{xorstr_("auth.gg"), xorstr_("Visited Auth.gg Website")},
{xorstr_("keyauth.com"), xorstr_("Visited KeyAuth Website")},
{xorstr_("aimjunkies.com"), xorstr_("Visited AimJunkies Website")},
{xorstr_("systemcheats.net"), xorstr_("Visited SystemCheats Website")},
{xorstr_("engineowning.to"), xorstr_("Visited EngineOwning Website")},
{xorstr_("skeet.cc"), xorstr_("Visited Skeet Website")},
{xorstr_("gamesense.pub"), xorstr_("Visited GameSense Website")},
{xorstr_("primordial.dev"), xorstr_("Visited Primordial Website")},
{xorstr_("neverlose.cc"), xorstr_("Visited Neverlose Website")},
{xorstr_("fatality.win"), xorstr_("Visited Fatality Website")},
{xorstr_("onetap.com"), xorstr_("Visited OneTap Website")},
{xorstr_("onetap.su"), xorstr_("Visited OneTap Website")},
{xorstr_("skreech.gg"), xorstr_("Visited Skreech Website")},
{xorstr_("cheatsense.sellhub.cx"), xorstr_("Visited CheatSense Website")},
{xorstr_("r6hibania.cc"), xorstr_("Visited R6 Hibania Website")},
{xorstr_("chair.wtf"), xorstr_("Visited Chair Website")},
{xorstr_("tomware.cc"), xorstr_("Visited Tomware Website")},
{xorstr_("rankuen.com"), xorstr_("Visited Rankuen Website")},
{xorstr_("shop.deception.gg"), xorstr_("Visited Deception Shop Website")},
{xorstr_("phoenixlabstore.com"), xorstr_("Visited Phoenix Lab Website")},
{xorstr_("oxxscheats.com"), xorstr_("Visited OxxsCheats Website")},
{xorstr_("vega.sell.app"), xorstr_("Visited Vega Website")},
{xorstr_("cheats.love"), xorstr_("Visited Cheats.love Website")},
{xorstr_("chamscheats.com"), xorstr_("Visited ChamsCheats Website")},
{xorstr_("whyyoucheating.sellhub.cx"), xorstr_("Visited WhyYouCheating Website")},
{xorstr_("tgmodz.com"), xorstr_("Visited TGModz Website")},
{xorstr_("ezmod.vip"), xorstr_("Visited EzMod Website")},
{xorstr_("ssz.gg"), xorstr_("Visited SSZ Website")},
{xorstr_("download.antarcticacheats.xyz"), xorstr_("Visited Antarctica Cheats Website")},
{xorstr_("antarctica.sellpass.io"), xorstr_("Visited Antarctica Cheats Website")},
{xorstr_("antarcticacheats.xyz"), xorstr_("Visited Antarctica Cheats Website")},
{xorstr_("perc.gg"), xorstr_("Visited Perc Website")},
{xorstr_("pcileech.com"), xorstr_("Visited PCILeech Website")},
{xorstr_("memprocfs.com"), xorstr_("Visited MemProcFS Website")},
{xorstr_("dma-shop.com"), xorstr_("Visited DMA Shop Website")},
{xorstr_("fpgacheats.com"), xorstr_("Visited FPGA Cheats Website")},
{xorstr_("dmastore.gg"), xorstr_("Visited DMA Store Website")},
{xorstr_("squirreldma.com"), xorstr_("Visited Squirrel DMA Website")},
{xorstr_("leechcore.com"), xorstr_("Visited LeechCore Website")},
{xorstr_("kmboxb.com"), xorstr_("Visited KMBox B Website")},
{xorstr_("kmbox.pro"), xorstr_("Visited KMBox Website")},
{xorstr_("arduino-cheat.com"), xorstr_("Visited Arduino Cheat Website")},
{xorstr_("guided-hacking.com"), xorstr_("Visited Guided Hacking Website")},
{xorstr_("hackforums.net"), xorstr_("Visited HackForums Website")},
{xorstr_("mpgh.net"), xorstr_("Visited MPGH Website")},
{xorstr_("cheatautomation.com"), xorstr_("Visited Cheat Automation Website")},
{xorstr_("aimware.net"), xorstr_("Visited Aimware Website")},
{xorstr_("interwebz.cc"), xorstr_("Visited Interwebz Website")},
{xorstr_("lmaobox.net"), xorstr_("Visited LMAOBox Website")},
{xorstr_("streamline-cheats.com"), xorstr_("Visited Streamline Cheats Website")},
{xorstr_("nixware.cc"), xorstr_("Visited Nixware Website")},
{xorstr_("pandora-cheats.com"), xorstr_("Visited Pandora Cheats Website")},
{xorstr_("hyperion-cheats.com"), xorstr_("Visited Hyperion Cheats Website")},
{xorstr_("cobracheats.com"), xorstr_("Visited Cobra Cheats Website")},
{xorstr_("sellpass.io"), xorstr_("Visited Sellpass Website")},
{xorstr_("whop.com"), xorstr_("Visited Whop Website")},
{xorstr_("enigmadma.com"), xorstr_("Visited Enigma DMA Website")},
{xorstr_("dma-fw.com"), xorstr_("Visited DMA Firmware Website")},
{xorstr_("fpga-cheats.com"), xorstr_("Visited FPGA Cheats Website")},
{xorstr_("lambdaconcept.com"), xorstr_("Visited LambdaConcept Website")},
{xorstr_("squirreldma.gg"), xorstr_("Visited Squirrel DMA Website")},
{xorstr_("pcileech.io"), xorstr_("Visited PCILeech Website")},
{xorstr_("dmatools.net"), xorstr_("Visited DMA Tools Website")},
{xorstr_("hwid-spoofer.com"), xorstr_("Visited HWID Spoofer Website")},
{xorstr_("hwid-ban.com"), xorstr_("Visited HWID Ban Website")},
{xorstr_("rena.lol"), xorstr_("Visited Rena Website")},
{xorstr_("keyauth.win"), xorstr_("Visited KeyAuth Website")},
{xorstr_("keyauth.cc"), xorstr_("Visited KeyAuth Website")},
{xorstr_("2.56.246.3"), xorstr_("Visited Revuelto Website")},
{xorstr_("Localhost:"), xorstr_("Visited Localhost")},
};

static std::map<std::string, std::string> browser_paths = {

    {xorstr_("Chrome"), xorstr_("\\Google\\Chrome\\User Data\\Default\\History")},
    {xorstr_("Edge"), xorstr_("\\Microsoft\\Edge\\User Data\\Default\\History")},
    {xorstr_("Brave"), xorstr_("\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History")},
    {xorstr_("Opera"), xorstr_("\\Opera Software\\Opera Stable\\History")},
    {xorstr_("OperaGX"), xorstr_("\\Opera Software\\Opera GX Stable\\History")},
    {xorstr_("Vivaldi"), xorstr_("\\Vivaldi\\User Data\\Default\\History")},
    {xorstr_("Yandex"), xorstr_("\\Yandex\\YandexBrowser\\User Data\\Default\\History")},
    {xorstr_("Chromium"), xorstr_("\\Chromium\\User Data\\Default\\History")},
    {xorstr_("AVG"), xorstr_("\\AVGBrowser\\User Data\\Default\\History")},
    {xorstr_("Avast"), xorstr_("\\AVAST Software\\Browser\\User Data\\Default\\History")},
    {xorstr_("Comodo"), xorstr_("\\Comodo\\Dragon\\User Data\\Default\\History")},
    {xorstr_("Torch"), xorstr_("\\Torch\\User Data\\Default\\History")}

};

void BrowserHistoryScanner::start_history_checks() {
    try{


    {
        wchar_t exe_pathw[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, exe_pathw, MAX_PATH) > 0) {
            fs::path exe_dir = fs::path(exe_pathw).parent_path();
            std::error_code _ec;
            if (!exe_dir.empty() && fs::exists(exe_dir, _ec) && !_ec) {
                for (auto it = fs::directory_iterator(exe_dir, fs::directory_options::skip_permission_denied, _ec);
                     !_ec && it != fs::directory_iterator();
                     it.increment(_ec))
                {
                    if (_ec) { _ec.clear(); continue; }
                    const auto& entry = *it;
                    if (!entry.is_regular_file(_ec) || _ec) { _ec.clear(); continue; }
                    auto name = c_utils::path_to_utf8(entry.path().filename());
                    bool match = false;
                    if (name.rfind(xorstr_("temp_"), 0) == 0) {
                        if (name.size() >= 12 &&
                            name.compare(name.size() - 11, 11, xorstr_("_history.db")) == 0) match = true;
                        if (name == xorstr_("temp_firefox.db")) match = true;
                    }
                    if (match) {
                        std::error_code ec;
                        fs::remove(entry.path(), ec);
                    }
                }
            }
        }
    }

    std::string base_local = GetLocalAppData();
    for (const auto& [browser, relative_path] : browser_paths) {
        std::string full_path = base_local + relative_path;
        if (FileExists(full_path)) {
            ScanHistory(full_path, browser);
        }
    }

    ScanFirefox();
    }
    catch (...) {}
}

void BrowserHistoryScanner::TerminateChromeProcesses() {
    try{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, xorstr_("chrome.exe")) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    }
    catch (...) {}
}

std::string BrowserHistoryScanner::GetLocalAppData() {
    try{
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, NULL, &path))) {
        char charPath[MAX_PATH];
        wcstombs_s(nullptr, charPath, path, MAX_PATH);
        std::string result(charPath);
        CoTaskMemFree(path);
        return result;
    }
    return "";
    }
    catch (...) { return ""; }
}

std::string BrowserHistoryScanner::GetRoamingAppData() {
    try{
    PWSTR path = nullptr;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, NULL, &path))) {
        char charPath[MAX_PATH];
        wcstombs_s(nullptr, charPath, path, MAX_PATH);
        std::string result(charPath);
        CoTaskMemFree(path);
        return result;
    }
    return "";
    }
    catch (...) { return ""; }
}

bool BrowserHistoryScanner::CopyFFile(const std::string& src, const std::string& dest) {
    try{
    std::ifstream source(src, std::ios::binary);
    std::ofstream destination(dest, std::ios::binary);
    if (!source || !destination) return false;
    destination << source.rdbuf();
    return source.good() && destination.good();
    }
    catch (...) { return false; }
}

bool BrowserHistoryScanner::FileExists(const std::string& path) {
    try{
    std::error_code ec;
    return fs::exists(path, ec) && !ec;
    }
    catch (...) { return false; }
}

std::string BrowserHistoryScanner::GetDomain(const std::string& url) {
    try{
    std::regex domain_regex(xorstr_(R"(^(?:https?:\/\/)?(?:www\.)?([^\/]+))"));
    std::smatch match;
    if (std::regex_search(url, match, domain_regex)) {
        return match[1];
    }
    return url;
    }
    catch (...) { return url; }
}

void BrowserHistoryScanner::ScanHistory(const std::string& db_path, const std::string& browser_name) {
    try{
    std::unordered_set<std::string> printed_base_urls;
    ScopedTempFile tmp(xorstr_("dsh"));
    if (tmp.path.empty()) return;
    if (!CopyFFile(db_path, tmp.path)) return;

    sqlite3* db = nullptr;
    sqlite3_stmt* stmt = nullptr;

    if (sqlite3_open(tmp.path.c_str(), &db) == SQLITE_OK) {
        const char* query = xorstr_("SELECT url, last_visit_time FROM urls ORDER BY last_visit_time DESC");
        if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const unsigned char* url = sqlite3_column_text(stmt, 0);
                if (url) {
                    std::string url_str(reinterpret_cast<const char*>(url));
                    std::string base_url = GetDomain(url_str);
                    if (printed_base_urls.count(base_url)) continue;

                    for (const auto& [keyword, custom_message] : keywords) {
                        if (url_str.find(keyword) != std::string::npos) {
                            int64_t visitTime = sqlite3_column_int64(stmt, 1);
                            std::string timestamp = ChromeTimeToLocal(visitTime);
                            std::string ts = timestamp.empty() ? "" : timestamp;
                            LOG(WARNING, ts) << xorstr_("User ") << custom_message << xorstr_(":") << url_str;
                            printed_base_urls.insert(base_url);
                            break;
                        }
                    }
                }
            }
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_close_v2(db);
    (void)browser_name;
    }
    catch (...) {}
}

void BrowserHistoryScanner::ScanFirefox() {
    try{
    std::unordered_set<std::string> printed_base_urls;
    std::string roaming = GetRoamingAppData();
    std::string profiles_path = roaming + xorstr_("\\Mozilla\\Firefox\\Profiles");
    std::error_code _ff_ec;
    if (!fs::exists(profiles_path, _ff_ec) || _ff_ec) return;

    for (auto it = fs::directory_iterator(profiles_path, fs::directory_options::skip_permission_denied, _ff_ec);
         !_ff_ec && it != fs::directory_iterator();
         it.increment(_ff_ec))
    {
        if (_ff_ec) { _ff_ec.clear(); continue; }
        const auto& dir_entry = *it;
        std::string path = c_utils::path_to_utf8(dir_entry.path());
        std::string db_file = path + xorstr_("\\places.sqlite");
        if (!FileExists(db_file)) continue;

        ScopedTempFile tmp(xorstr_("dff"));
        if (tmp.path.empty()) continue;
        if (!CopyFFile(db_file, tmp.path)) continue;

        sqlite3* db = nullptr;
        sqlite3_stmt* stmt = nullptr;

        if (sqlite3_open(tmp.path.c_str(), &db) == SQLITE_OK) {
            const char* query = xorstr_("SELECT url, last_visit_date FROM moz_places ORDER BY last_visit_date DESC");
            if (sqlite3_prepare_v2(db, query, -1, &stmt, 0) == SQLITE_OK) {
                while (sqlite3_step(stmt) == SQLITE_ROW) {
                    const unsigned char* url = sqlite3_column_text(stmt, 0);
                    if (url) {
                        std::string url_str(reinterpret_cast<const char*>(url));
                        std::string base_url = GetDomain(url_str);
                        if (printed_base_urls.count(base_url)) continue;

                        for (const auto& [keyword, custom_message] : keywords) {
                            if (url_str.find(keyword) != std::string::npos) {
                                int64_t visitDate = sqlite3_column_int64(stmt, 1);
                                std::string timestamp = FirefoxTimeToLocal(visitDate);
                                std::string ts = timestamp.empty() ? "" : timestamp;
                                LOG(WARNING, ts) << xorstr_("User ") << custom_message << xorstr_(":") << url_str;
                                printed_base_urls.insert(base_url);
                                break;
                            }
                        }
                    }
                }
                sqlite3_finalize(stmt);
            }
        }
        sqlite3_close_v2(db);
    }
    }
    catch (...) {}
}
