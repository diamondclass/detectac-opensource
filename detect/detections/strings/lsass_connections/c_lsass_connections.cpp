#include "c_lsass_connections.h"

#define MIN_STRING_LENGTH 4

bool lsass_scan::enable_debug_privilege() {
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

DWORD lsass_scan::get_pid_by_process_name(const std::string& proc_name) {
    try {
        DWORD pid = 0;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(snapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, proc_name.c_str()) == 0) {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &pe));
        }
        CloseHandle(snapshot);
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

        { xorstr_("ghostesportpanel.com"), xorstr_("Gosth Ran Since Logon \"ghostesportpanel.com\"") },
        { xorstr_("tzproject"), xorstr_("TzProject Ran Since Logon \"tzproject\"") },
        { xorstr_("api.tzproject.com"), xorstr_("TzProject Ran Since Logon \"api.tzproject.com\"") },
        { xorstr_("tzproject.com"), xorstr_("TzProject Ran Since Logon \"tzproject.com\"") },
        { xorstr_("ec2-3-235-182-72.compute-1.amazonaws.com"), xorstr_("Eulen Ran Since Logon \"ec2-3-235-182-72.compute-1.amazonaws.com\"") },
        { xorstr_("ec2-3-235-182-75.compute-1.amazonaws.com"), xorstr_("Eulen Ran Since Logon \"ec2-3-235-182-75.compute-1.amazonaws.com\"") },
        { xorstr_("ec2-3-235-182-71.compute-1.amazonaws.com"), xorstr_("Eulen Ran Since Logon \"ec2-3-235-182-71.compute-1.amazonaws.com\"") },
        { xorstr_("ec2-3-235-182-74.compute-1.amazonaws.com"), xorstr_("Eulen Ran Since Logon \"ec2-3-235-182-74.compute-1.amazonaws.com\"") },
        { xorstr_("ec2-3-235-182-76.compute-1.amazonaws.com"), xorstr_("Eulen Ran Since Logon \"ec2-3-235-182-76.compute-1.amazonaws.com\"") },
        { xorstr_("ec2-3-235-182-73.compute-1.amazonaws.com"), xorstr_("Eulen Ran Since Logon \"ec2-3-235-182-73.compute-1.amazonaws.com\"") },
        { xorstr_("machocheats.com"), xorstr_("MachoCheats Ran Since Logon \"machocheats.com\"") },
        { xorstr_("api.88-cheats.xyz"), xorstr_("88Cheat Ran Since Logon \"api.88-cheats.xyz\"") },
        { xorstr_("88-cheats.xyz"), xorstr_("88Cheat Ran Since Logon \"88-cheats.xyz\"") },
        { xorstr_("testo.gg"), xorstr_("TestoCheats Ran Since Logon \"testo.gg\"") },
        { xorstr_("projectcheats"), xorstr_("ProjectCheats Ran Since Logon \"projectcheats\"") },
        { xorstr_("ezilax.com"), xorstr_("SicarioCheats Ran Since Logon \"ezilax.com\"") },
        { xorstr_("blackout.wtf"), xorstr_("BlackoutCheats Ran Since Logon \"blackout.wtf\"") },
        { xorstr_("api.blackout.wtf"), xorstr_("BlackoutCheats Ran Since Logon \"api.blackout.wtf\"") },
        { xorstr_("api.asgardreborn.com"), xorstr_("Asgard Ran Since Logon \"api.asgardreborn.com\"") },
        { xorstr_("www.degeoacademyxyz"), xorstr_("Degeo Ran Since Logon \"www.degeoacademyxyz\"") },
        { xorstr_("monstermenu.cc"), xorstr_("Moster Ran Since Logon \"monstermenu.cc\"") },
        { xorstr_("susano.re"), xorstr_("Susano Ran Since Logon \"susano.re\"") },
        { xorstr_("skript.gg"), xorstr_("Skript Ran Since Logon \"skript.gg\"") },
        { xorstr_("eauth.us.to"), xorstr_("Spotless Ran Since Logon \"eauth.us.to\"") },
        { xorstr_("password_is_eulen"), xorstr_("Eulen Ran Since Logon \"password_is_eulen\"") },
        { xorstr_("monstermenu.cc"), xorstr_("Eulen Monster Ran Since Logon \"monstermenu.cc\"") },
        { xorstr_("eulencheats.com"), xorstr_("Eulen Monster Ran Since Logon \"eulencheats.com\"") },
        { xorstr_("eulen.cc"), xorstr_("Eulen Website Ran Since Logon \"eulen.cc\"") },
        { xorstr_("fivem-projectcheats.com"), xorstr_("Project Cheats Ran Since Logon \"fivem-projectcheats.com\"") },
        { xorstr_("sauth.redengine.eu"), xorstr_("Reg Engine Ran Since Logon \"sauth.redengine.eu\"") },
        { xorstr_("hxsoftwares"), xorstr_("HxCheats Ran Since Logon \"hxsoftwares\"") },
        { xorstr_("api.hxcheats.com"), xorstr_("HxCheats Ran Since Logon \"api.hxcheats.com\"") },
        { xorstr_("hxcheats.com"), xorstr_("HxCheats Ran Since Logon \"hxcheats.com\"") },
        { xorstr_("api.hxsoftwares.com"), xorstr_("HxCheats Ran Since Logon \"api.hxsoftwares.com\"") },
        { xorstr_("hxsoftwares.com"), xorstr_("HxCheats Ran Since Logon \"hxsoftwares.com\"") },
        { xorstr_("9zproject.xyz"), xorstr_("9z Project Ran Since Logon \"9zproject.xyz\"") },
        { xorstr_("serapi.mom"), xorstr_("Spotless/Binary Ran Since Logon \"serapi.mom\"") },
        { xorstr_("projectdow.com"), xorstr_("Dow Ran Since Logon \"projectdow.com\"") },
        { xorstr_("api.shilav2.shop"), xorstr_("Wexless Bypass Ran Since Logon \"api.shilav2.shop\"") },
        { xorstr_("193.23.160.168"), xorstr_("Signer Cheat Ran Since Logon \"193.23.160.168\"") },
        { xorstr_("signer.cc"), xorstr_("Signer Cheat Ran Since Logon \"signer.cc\"") },
        { xorstr_("orbit.signer.cc"), xorstr_("Signer Cheat Ran Since Logon \"orbit.signer.cc\"") },
        { xorstr_("bypass.fun"), xorstr_("Bypass.fun Cheat Ran Since Logon \"bypass.fun\"") },
        { xorstr_("keyser-lts.com"), xorstr_("Keyser Cheat Ran Since Logon \"keyser-lts.com\"") },
        { xorstr_("keyser.gg"), xorstr_("Keyser Bypass Ran Since Logon \"keyser.gg\"") },
        { xorstr_("sergiu.pro"), xorstr_("Spotless Bypass Ran Since Logon \"sergiu.pro\"") },
        { xorstr_("185.236.228.154"), xorstr_("FLK Cheat Ran Since Logon \"185.236.228.154\"") },
        { xorstr_("flkstore.com"), xorstr_("FLK Cheat Ran Since Logon \"flkstore.com\"") },
        { xorstr_("flk-uhq.xyz"), xorstr_("FLK Cheat Ran Since Logon \"flk-uhq.xyz\"") },
        { xorstr_("5.206.224.37"), xorstr_("FLK Cheat Ran Since Logon \"5.206.224.37\"") },
        { xorstr_("bebetter-fivem"), xorstr_("Be-better Cheat Ran Since Logon \"bebetter-fivem\"") },
        { xorstr_("venacy.club"), xorstr_("Venacy Cheat Ran Since Logon \"venacy.club\"") },
        { xorstr_("antiecho.xyz"), xorstr_("Anti-Echo Cheat Ran Since Logon \"antiecho.xyz\"") },
        { xorstr_("107.189.24.38"), xorstr_("Ultracore Bypass Ran Since Logon \"107.189.24.38\"") },
        { xorstr_("203.159.90.127"), xorstr_("Lethality Script Ran Since Logon \"203.159.90.127\"") },
        { xorstr_("hydrogen.ac"), xorstr_("Hydrogen Cheat Ran Since Logon \"hydrogen.ac\"") },
        { xorstr_("leet-cheats.ru"), xorstr_("Leet Cheat Ran Since Logon \"leet-cheats.ru\"") },
        { xorstr_("trinitas.top"), xorstr_("Binary Bypass Ran Since Logon \"trinitas.top\"") },
        { xorstr_("vanish-cheat.com"), xorstr_("Vanish Cheat Ran Since Logon \"vanish-cheat.com\"") },
        { xorstr_("91.218.66.77"), xorstr_("Forte Cheat Ran Since Logon \"91.218.66.77\"") },
        { xorstr_("uzuimarket.xyz"), xorstr_("Uzui Ran Since Logon \"uzuimarket.xyz\"") },
        { xorstr_("spotless.gg"), xorstr_("Spotless Bypass Ran Since Logon \"spotless.gg\"") },
        {xorstr_("download2300.mediafire.com/duru9jadxca89fy/Povika+Hitbox.zip"), xorstr_("Povika Hitbox Ran Since Logon \"download2300.mediafire.com/duru9jadxca89fy/Povika+Hitbox.zip\"")},
        {xorstr_("download2389.mediafire.com/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip"), xorstr_("CustomH1itb0x3s Ran Since Logon \"download2389.mediafire.com/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip\"")},
        {xorstr_("takeout-download-drive-eu.usercontent.google.com/download/drive-download-20250820T093435Z-1-001.zip"), xorstr_("ShenanigansHitbox Ran Since Logon \"takeout-download-drive-eu.usercontent.google.com/download/drive-download-20250820T093435Z-1-001.zip\"")},
        {xorstr_("drive.usercontent.google.com/download?id=1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm"), xorstr_("Aimbot Redux Ran Since Logon \"drive.usercontent.google.com/download?id=1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm\"")},
        {xorstr_("drive.usercontent.google.com/download?id=1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7"), xorstr_("Redux Cheat Ran Since Logon \"drive.usercontent.google.com/download?id=1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7\"")},
        {xorstr_("drive.usercontent.google.com/download?id=1YJ0SNGLQiR-dD4w5gMYFZCq0cpIqkyHQ"), xorstr_("Redux Hacks Ran Since Logon \"drive.usercontent.google.com/download?id=1YJ0SNGLQiR-dD4w5gMYFZCq0cpIqkyHQ\"")},
        {xorstr_("socialwolvez.com/app/l/fwOQWj"), xorstr_("Povika Hitbox Ran Since Logon \"socialwolvez.com/app/l/fwOQWj\"")},
        {xorstr_("mediafire.com/file/duru9jadxca89fy/Povika+Hitbox.zip"), xorstr_("Povika Hitbox Ran Since Logon \"mediafire.com/file/duru9jadxca89fy/Povika+Hitbox.zip\"")},
        {xorstr_("sub4unlock.io/4cWyE"), xorstr_("CustomH1itb0x3s Ran Since Logon \"sub4unlock.io/4cWyE\"")},
        {xorstr_("mediafire.com/file/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip"), xorstr_("CustomH1itb0x3s Ran Since Logon \"mediafire.com/file/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip\"")},
        {xorstr_("drive.google.com/drive/folders/1qUtxrVbDP2S5mZcXISrcMcs4dsHWtj4g"), xorstr_("ShenanigansHitboxDrive Ran Since Logon \"drive.google.com/drive/folders/1qUtxrVbDP2S5mZcXISrcMcs4dsHWtj4g\"")},
        {xorstr_("drive.google.com/file/d/1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm"), xorstr_("Ro9anAimDrive Ran Since Logon \"drive.google.com/file/d/1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm\"")},
        {xorstr_("drive.google.com/file/d/1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7"), xorstr_("Ro9anReduxDrive Ran Since Logon \"drive.google.com/file/d/1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7\"")},
        {xorstr_("workupload.com/file/BxAnEw56J9N"), xorstr_("ShaxFreeCheat Ran Since Logon \"workupload.com/file/BxAnEw56J9N\"")},
        {xorstr_("sub4unlock.com/SL/1528315"), xorstr_("ShaxCheatReduxV7 Ran Since Logon \"sub4unlock.com/SL/1528315\"")},
        {xorstr_("traceless.wtf"), xorstr_("Traceless Bypass Ran Since Logon \"traceless.wtf\"")},
        {xorstr_("freshbypass.xyz"), xorstr_("Fresh Bypass Ran Since Logon \"freshbypass.xyz\"")},
        {xorstr_("designcraft.xyz"), xorstr_("Response Bypass Ran Since Logon \"designcraft.xyz\"")},
        {xorstr_("snowbp.xyz"), xorstr_("Snow Bypass Ran Since Logon \"snowbp.xyz\"")},
        {xorstr_("87.120.191.29"), xorstr_("Quanta Ran Since Logon \"87.120.191.29\"")},
        {xorstr_("club44.lol"), xorstr_("Club44 Ran Since Logon \"club44.lol\"")},
        {xorstr_("auis.binaryy.top"), xorstr_("Binary Bypass Ran Since Logon \"auis.binaryy.top\"")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co"), xorstr_("Binary Bypass Ran Since Logon")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/auth-login"), xorstr_("Binary Bypass Login Page Ran Since Logon")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/vpn-check"), xorstr_("Binary Bypass VPN Check Page Ran Since Logon")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co/rest/v1/rpc/get_maintenance_mode"), xorstr_("Binary Bypass Maintinence Page Ran Since Logon")},
        {xorstr_("serotonin.win"), xorstr_("Serotonin Bypass Ran Since Logon")},
        {xorstr_("181.215.45.13"), xorstr_("Club44 Bypass Ran Since Logon")},
        {xorstr_("93.127.215.67"), xorstr_("Club44 Bypass Ran Since Logon")},
        {xorstr_("severance.today"), xorstr_("Severance Bypass Ran Since Logon")},
        {xorstr_("gnomus.lol"), xorstr_("FiveM Enjoyer Ran Since Logon")},
        {xorstr_("pub-047df53bbd524128a2b8f1477ec0e316.r2.dev"), xorstr_("Severance Bypass Ran Since Logon")},
        {xorstr_("45.156.87.118"), xorstr_("Unknown Bypass Ran Since Logon")},
        {xorstr_("16.171.254.8"), xorstr_("Bypass.fun Bypass Ran Since Logon")},
        {xorstr_("certificate.wtf"), xorstr_("certificate.wtf Ran Since Logon \"certificate.wtf\"")},
        {xorstr_("cosmos.pm"), xorstr_("Cosmos Ran Since Logon \"cosmos.pm\"")},
        {xorstr_("rxmenu.shop"), xorstr_("RX Menu Ran Since Logon \"rxmenu.shop\"")},
        {xorstr_("omertasoftware.com"), xorstr_("Omerta Software Ran Since Logon \"omertasoftware.com\"")},
        {xorstr_("xentro.xyz"), xorstr_("Xentro Ran Since Logon \"xentro.xyz\"")},
        {xorstr_("titanbypass.com"), xorstr_("Titan Bypass Ran Since Logon \"titanbypass.com\"")},
        {xorstr_("us1.phase.uno"), xorstr_("Phase Uno Ran Since Logon \"us1.phase.uno\"")},
        {xorstr_("phase.uno"), xorstr_("Phase Uno Ran Since Logon \"phase.uno\"")},
        {xorstr_("104.21.82.227"), xorstr_("Phase Uno Ran Since Logon \"104.21.82.227\"")},
        {xorstr_("104.18.2.36"), xorstr_("Phase Uno Ran Since Logon \"104.18.2.36\"")},
        {xorstr_("wizardbypass.com"), xorstr_("Wizard Bypass Ran Since Logon \"wizardbypass.com\"")},
        {xorstr_("loginlive.cloud"), xorstr_("Wizard Bypass Ran Since Logon \"Wizard\"")},
        {xorstr_("54.39.67.23"), xorstr_("Rolex Bypass Ran Since Logon \"54.39.67.23\"")},
        {xorstr_("richh.lol"), xorstr_("Rolex Bypass Ran Since Logon \"richh.lol\"")},
        {xorstr_("antiscan.xyz"), xorstr_("Rolex Bypass Ran Since Logon \"antiscan.xyz\"")},
        { xorstr_("evora.pw"), xorstr_("Evora Ran Since Logon \"evora.pw\"") },
        { xorstr_("45.143.196.213"), xorstr_("Bytecode Bypass Ran Since Logon \"45.143.196.213\"") },
        { xorstr_("Sirius.lv"), xorstr_("Sirius Bypass Ran Since Logon \"Sirius.lv\"") },

#elif DETECT_FORTNITE
        
        {xorstr_("185.236.228.154"), xorstr_("Visited FLK Website Since Restart: \"185.236.228.154\"")},
        {xorstr_("flkstore.com"), xorstr_("FLK Cheat Ran Since Logon \"flkstore.com\"")},
        {xorstr_("flk-uhq.xyz"), xorstr_("FLK Cheat Ran Since Logon \"flk-uhq.xyz\"")},
        {xorstr_("5.206.224.37"), xorstr_("FLK Cheat Ran Since Logon \"5.206.224.37\"")},
        { xorstr_("keyser-lts.com"), xorstr_("Keyser Cheat Ran Since Logon \"keyser-lts.com\"") },
        { xorstr_("keyser.gg"), xorstr_("Keyser Bypass Ran Since Logon \"keyser.gg\"") },
        { xorstr_("zombiecheats.com"), xorstr_("Zombie Cheats Ran Since Logon \"zombiecheats.com\"") },
        { xorstr_("hypervision.gg"), xorstr_("Hypervision Ran Since Logon \"hypervision.gg\"") },
        { xorstr_("elocarry.net"), xorstr_("Elocarry Ran Since Logon \"elocarry.net\"") },
        { xorstr_("engineowning.su"), xorstr_("Engineowning Ran Since Logon \"engineowning.su\"") },
        { xorstr_("uzuimarket.xyz"), xorstr_("Uzui Ran Since Logon \"uzuimarket.xyz\"") },
        { xorstr_("195.59.67.101"), xorstr_("ICanHaZip Ran Since Logon \"195.59.67.101\"") },
        { xorstr_("icanhazip.com"), xorstr_("ICanHaZip Ran Since Logon \"icanhazip.com\"") },
        { xorstr_("udsoftwares.com"), xorstr_("UD Softwares Ran Since Logon \"udsoftwares.com\"") },
        { xorstr_("crythosbackend-production.up.railway.app"), xorstr_("Crythos Ran Since Logon \"crythosbackend-production.up.railway.app\"") },
        
#elif DETECT_MINECRAFT

        { xorstr_("grimclient"), xorstr_("Grim Client Ran Since Logon \"grimclient\"") },
        { xorstr_("prestigeclient.vip"), xorstr_("Prestige Client Ran Since Logon \"prestigeclient.vip\"") },
        { xorstr_("api.prestigeclient.vip"), xorstr_("Prestige Client Ran Since Logon \"api.prestigeclient.vip\"") },
        { xorstr_("bypassing.gg"), xorstr_("Cold Bypassing Website Ran Since Logon \"bypassing.gg\"") },
        { xorstr_("aristois.net"), xorstr_("Aristois Ran Since Logon \"aristois.net\"") },
        { xorstr_("catlean.su"), xorstr_("Catlean Ran Since Logon \"catlean.su\"") },
        { xorstr_("karma.rip"), xorstr_("Karma Ran Since Logon \"karma.rip\"") },
        { xorstr_("client-analytics.dev"), xorstr_("Cold Bypass Website Ran Since Logon \"client-analytics.dev\"") },

#elif DETECT_RUST
        { xorstr_("onestopcheats"), xorstr_("One Stop Cheats Ran Since Logon \"onestopcheats\"") },

#elif DETECT_ROBLOX

        { xorstr_("robloxcheatz.com"), xorstr_("Robloxcheatz Ran Since Logon \"robloxcheatz.com\"") },
        { xorstr_("radiant.cc"), xorstr_("Radiant Ran Since Logon \"radiant.cc\"") },
        { xorstr_("eternalproduct.com"), xorstr_("Eternal Product Ran Since Logon \"eternalproduct.com\"") },
        { xorstr_("matrixhubs.shop"), xorstr_("Matrix Ran Since Logon \"matrixhubs.shop\"") },
        { xorstr_("matrixhubs"), xorstr_("Matrix Ran Since Logon \"matrixhubs\"") },
        { xorstr_("mtxhub.online"), xorstr_("Matrix Ran Since Logon \"mtxhub.online\"") },
        { xorstr_("matrixhub.shop"), xorstr_("Matrix Ran Since Logon \"matrixhub.shop\"") },
        { xorstr_("vapevoidware.xyz"), xorstr_("Voidware Ran Since Logon \"vapevoidware.xyz\"") },
        { xorstr_("voxlis.net"), xorstr_("Voxlis Ran Since Logon \"voxlis.net\"") },
        { xorstr_("voltbz.net"), xorstr_("Volt Ran Since Logon \"voltbz.net\"") },
        { xorstr_("potassium.pro"), xorstr_("Potassium Ran Since Logon \"potassium.pro\"") },
        { xorstr_("getwave.gg"), xorstr_("Wave Ran Since Logon \"getwave.gg\"") },
        { xorstr_("z.synapse.do"), xorstr_("Synapse Z Ran Since Logon \"z.synapse.do\"") },
        { xorstr_("seliware.com"), xorstr_("Seliware Ran Since Logon \"seliware.com\"") },
        { xorstr_("getmadium.net"), xorstr_("Madium Ran Since Logon \"getmadium.net\"") },
        { xorstr_("realvelocity.xyz"), xorstr_("Velocity Ran Since Logon \"realvelocity.xyz\"") },
        { xorstr_("sirhurt.net"), xorstr_("SirHurt Ran Since Logon \"sirhurt.net\"") },
        { xorstr_("getsolara.dev"), xorstr_("Solara Ran Since Logon \"getsolara.dev\"") },
        { xorstr_("xeno.now"), xorstr_("Xeno Ran Since Logon \"xeno.now\"") },
        { xorstr_("raptor.fun"), xorstr_("MacSploit Ran Since Logon \"raptor.fun\"") },
        { xorstr_("deltaexploits.gg"), xorstr_("Delta Exploits Ran Since Logon \"deltaexploits.gg\"") },
        { xorstr_("getcryptic.net"), xorstr_("Cryptic Ran Since Logon \"getcryptic.net\"") },
        { xorstr_("vegax.gg"), xorstr_("Vega X Ran Since Logon \"vegax.gg\"") },
        { xorstr_("codex.lol"), xorstr_("Codex Ran Since Logon \"codex.lol\"") },
        { xorstr_("serotonin.win"), xorstr_("Serotonin Ran Since Logon \"serotonin.win\"") },
        { xorstr_("matcha-latte.win"), xorstr_("Matcha Ran Since Logon \"matcha-latte.win\"") },
        { xorstr_("photonsys.sellpass.io"), xorstr_("Photon Ran Since Logon \"photonsys.sellpass.io\"") },
        { xorstr_("cultofintellect.com"), xorstr_("DX9WARE V2 Ran Since Logon \"cultofintellect.com\"") },
        { xorstr_("vexor.wtf"), xorstr_("Vexor Ran Since Logon \"vexor.wtf\"") },

#elif DETECT_FREEFIRE

        { xorstr_("xerecao.com"), xorstr_("XRC Ran Since Logon \"xerecao.com\"") },

#elif DETECT_DAYZ

        { xorstr_("stugware.com"), xorstr_("Stugware Ran Since Logon \"stugware.com\"") },
        { xorstr_("cheatseller.com"), xorstr_("Cheatseller Ran Since Logon \"cheatseller.com\"") },
        { xorstr_("elitehacks.ru"), xorstr_("Elite Hacks Ran Since Logon \"elitehacks.ru\"") },
        { xorstr_("smgcheats.com"), xorstr_("SMG Cheats Ran Since Logon \"smgcheats.com\"") },
        { xorstr_("battlelog.co"), xorstr_("Battlelog Ran Since Logon \"battlelog.co\"") },
        { xorstr_("ducks-services.com"), xorstr_("Ducks Services Ran Since Logon \"ducks-services.com\"") },
        { xorstr_("skycheats.com"), xorstr_("Sky Cheats Ran Since Logon \"skycheats.com\"") },
        { xorstr_("elitepvpers.com"), xorstr_("ElitePVPers Ran Since Logon \"elitepvpers.com\"") },
        { xorstr_("kernaim.to"), xorstr_("Kernaim Ran Since Logon \"kernaim.to\"") },
        { xorstr_("ciroscript.com"), xorstr_("CiroScript Ran Since Logon \"ciroscript.com\"") },
        { xorstr_("wh-satano.ru"), xorstr_("WH Satano Ran Since Logon \"wh-satano.ru\"") },
        { xorstr_("blast.hk"), xorstr_("Blast Ran Since Logon \"blast.hk\"") },
        { xorstr_("cheatseller.ru"), xorstr_("Cheatseller RU Ran Since Logon \"cheatseller.ru\"") },
        { xorstr_("cheat.bz"), xorstr_("Cheat BZ Ran Since Logon \"cheat.bz\"") },
        { xorstr_("clutch-solution.com"), xorstr_("Clutch Solution Ran Since Logon \"clutch-solution.com\"") },
        { xorstr_("715team.ru"), xorstr_("715 Team Ran Since Logon \"715team.ru\"") },
        { xorstr_("labcorecheats.com"), xorstr_("Labcore Cheats Ran Since Logon \"labcorecheats.com\"") },
        { xorstr_("byster.one"), xorstr_("Byster Ran Since Logon \"byster.one\"") },
        { xorstr_("up-game.pro"), xorstr_("Up Game Ran Since Logon \"up-game.pro\"") },
        { xorstr_("zsoft.store"), xorstr_("ZSoft Ran Since Logon \"zsoft.store\"") },
        { xorstr_("dayzradar.715team.ru"), xorstr_("DayZ Radar 715 Team Ran Since Logon \"dayzradar.715team.ru\"") },

#elif DETECT_SIEGE

        { xorstr_("skreechware.com"), xorstr_("Skreechware Cheat Ran Since Logon \"skreechware.com\"") },
        { xorstr_("cosmocheats.com"), xorstr_("Cosmocheats Cheat Ran Since Logon \"cosmocheats.com\"") },
        { xorstr_("nyronai.com"), xorstr_("Nyronai Cheat Ran Since Logon \"nyronai.com\"") },
        { xorstr_("aptitude.pub"), xorstr_("Aptitude Cheat Ran Since Logon \"aptitude.pub\"") },
        { xorstr_("visuals.gg"), xorstr_("Visuals Cheat Ran Since Logon \"visuals.gg\"") },
        { xorstr_("battlelog.com"), xorstr_("Battlelog Cheat Ran Since Logon \"battlelog.com\"") },
        { xorstr_("connerzon.com"), xorstr_("Connerzon Cheat Ran Since Logon \"connerzon.com\"") },
        { xorstr_("r6needs.store"), xorstr_("R6Needs Cheat Ran Since Logon \"r6needs.store\"") },
        { xorstr_("edaters.store"), xorstr_("Edaters Cheat Ran Since Logon \"edaters.store\"") },
        { xorstr_("beatbct.com"), xorstr_("BeatBCT Cheat Ran Since Logon \"beatbct.com\"") },
        { xorstr_("xerus.cc"), xorstr_("Xerus Cheat Ran Since Logon \"xerus.cc\"") },
        { xorstr_("overdose.support"), xorstr_("Overdose Cheat Ran Since Logon \"overdose.support\"") },
        { xorstr_("veylo.io"), xorstr_("Veylo Cheat Ran Since Logon \"veylo.io\"") },
        { xorstr_("chudvision.net"), xorstr_("Chudvision Cheat Ran Since Logon \"chudvision.net\"") },
        { xorstr_("exloader.net"), xorstr_("ExLoader Cheat Ran Since Logon \"exloader.net\"") },
        { xorstr_("battlelog.co"), xorstr_("Battlelog CO Cheat Ran Since Logon \"battlelog.co\"") },
        { xorstr_("sinfulexp.net"), xorstr_("SinfulExp Cheat Ran Since Logon \"sinfulexp.net\"") },
        { xorstr_("ancient.su"), xorstr_("Ancient Cheat Ran Since Logon \"ancient.su\"") },
        { xorstr_("enhancedsolutions.cc"), xorstr_("Enhanced Solutions Cheat Ran Since Logon \"enhancedsolutions.cc\"") },
        { xorstr_("closetware.store"), xorstr_("Closetware Cheat Ran Since Logon \"closetware.store\"") },
        { xorstr_("ghostware.cc"), xorstr_("Ghostware Cheat Ran Since Logon \"ghostware.cc\"") },
        { xorstr_("deception.gg"), xorstr_("Deception Cheat Ran Since Logon \"deception.gg\"") },
        { xorstr_("hexdma.com"), xorstr_("HexDMA Cheat Ran Since Logon \"hexdma.com\"") },
        { xorstr_("aquacheats.cc"), xorstr_("AquaCheats Cheat Ran Since Logon \"aquacheats.cc\"") },
        { xorstr_("calamari.lol"), xorstr_("Calamari Cheat Ran Since Logon \"calamari.lol\"") },
        { xorstr_("elocarry.net"), xorstr_("EloCarry Cheat Ran Since Logon \"elocarry.net\"") },
        { xorstr_("lavicheats.com"), xorstr_("LaviCheats Cheat Ran Since Logon \"lavicheats.com\"") },
        { xorstr_("gear5.sellpass.io"), xorstr_("Gear5 Cheat Ran Since Logon \"gear5.sellpass.io\"") },
        { xorstr_("reportedcheats.com"), xorstr_("ReportedCheats Cheat Ran Since Logon \"reportedcheats.com\"") },
        { xorstr_("outkastcheats.com"), xorstr_("OutkastCheats Cheat Ran Since Logon \"outkastcheats.com\"") },
        { xorstr_("kernelsight.com"), xorstr_("KernelSight Cheat Ran Since Logon \"kernelsight.com\"") },
        { xorstr_("klar.gg"), xorstr_("Klar Cheat Ran Since Logon \"klar.gg\"") },
        { xorstr_("lethalcheats.net"), xorstr_("LethalCheats Cheat Ran Since Logon \"lethalcheats.net\"") },
        { xorstr_("lynxtech.pro"), xorstr_("LynxTech Cheat Ran Since Logon \"lynxtech.pro\"") },
        { xorstr_("unknowncheats.me"), xorstr_("UnknownCheats Cheat Ran Since Logon \"unknowncheats.me\"") },
        { xorstr_("playsharp.io"), xorstr_("PlaySharp Cheat Ran Since Logon \"playsharp.io\"") },
        { xorstr_("1nvituscheats.com"), xorstr_("1nvitus Cheats Cheat Ran Since Logon \"1nvituscheats.com\"") },
        { xorstr_("shopring1nvitus.com"), xorstr_("ShopRing 1nvitus Cheat Ran Since Logon \"shopring1nvitus.com\"") },
        { xorstr_("red-xservices.com"), xorstr_("Red X Services Ran Since Logon \"red-xservices.com\"") },

#elif DETECT_COD

        { xorstr_("streckaio.com"), xorstr_("Strecka.io Cheat Ran Since Logon \"streckaio.com\"") },

#elif DETECT_CS

        { xorstr_("memesense.gg"), xorstr_("Memesense Cheat Ran Since Logon \"memesense.gg\"") },
        { xorstr_("midnight.im"), xorstr_("Midnight Cheat Ran Since Logon \"midnight.im\"") },
        { xorstr_("gamesense.vip"), xorstr_("GameSense Cheat Ran Since Logon \"gamesense.vip\"") },

#endif

        { xorstr_("auth.gg"), xorstr_("Auth.gg Ran Since Logon \"auth.gg\"") },
        { xorstr_("keyauth.com"), xorstr_("KeyAuth Ran Since Logon \"keyauth.com\"") },
        { xorstr_("aimjunkies.com"), xorstr_("AimJunkies Ran Since Logon \"aimjunkies.com\"") },
        { xorstr_("systemcheats.net"), xorstr_("SystemCheats Ran Since Logon \"systemcheats.net\"") },
        { xorstr_("engineowning.to"), xorstr_("EngineOwning Ran Since Logon \"engineowning.to\"") },
        { xorstr_("skeet.cc"), xorstr_("Skeet Ran Since Logon \"skeet.cc\"") },
        { xorstr_("gamesense.pub"), xorstr_("GameSense Ran Since Logon \"gamesense.pub\"") },
        { xorstr_("primordial.dev"), xorstr_("Primordial Ran Since Logon \"primordial.dev\"") },
        { xorstr_("neverlose.cc"), xorstr_("Neverlose Ran Since Logon \"neverlose.cc\"") },
        { xorstr_("fatality.win"), xorstr_("Fatality Ran Since Logon \"fatality.win\"") },
        { xorstr_("onetap.com"), xorstr_("OneTap Ran Since Logon \"onetap.com\"") },
        { xorstr_("onetap.su"), xorstr_("OneTap Ran Since Logon \"onetap.su\"") },
        { xorstr_("skreech.gg"), xorstr_("Skreech Ran Since Logon \"skreech.gg\"") },
        { xorstr_("cheatsense.sellhub.cx"), xorstr_("CheatSense Ran Since Logon \"cheatsense.sellhub.cx\"") },
        { xorstr_("r6hibania.cc"), xorstr_("R6 Hibania Ran Since Logon \"r6hibania.cc\"") },
        { xorstr_("chair.wtf"), xorstr_("Chair Ran Since Logon \"chair.wtf\"") },
        { xorstr_("tomware.cc"), xorstr_("Tomware Ran Since Logon \"tomware.cc\"") },
        { xorstr_("rankuen.com"), xorstr_("Rankuen Ran Since Logon \"rankuen.com\"") },
        { xorstr_("shop.deception.gg"), xorstr_("Deception Shop Ran Since Logon \"shop.deception.gg\"") },
        { xorstr_("phoenixlabstore.com"), xorstr_("Phoenix Lab Ran Since Logon \"phoenixlabstore.com\"") },
        { xorstr_("exodus.fun"), xorstr_("Exodus Ran Since Logon \"exodus.fun\"") },
        { xorstr_("oxxscheats.com"), xorstr_("OxxsCheats Ran Since Logon \"oxxscheats.com\"") },
        { xorstr_("vega.sell.app"), xorstr_("Vega Ran Since Logon \"vega.sell.app\"") },
        { xorstr_("cheats.love"), xorstr_("Cheats.love Ran Since Logon \"cheats.love\"") },
        { xorstr_("chamscheats.com"), xorstr_("ChamsCheats Ran Since Logon \"chamscheats.com\"") },
        { xorstr_("whyyoucheating.sellhub.cx"), xorstr_("WhyYouCheating Ran Since Logon \"whyyoucheating.sellhub.cx\"") },
        { xorstr_("tgmodz.com"), xorstr_("TGModz Ran Since Logon \"tgmodz.com\"") },
        { xorstr_("ezmod.vip"), xorstr_("EzMod Ran Since Logon \"ezmod.vip\"") },
        { xorstr_("ssz.gg"), xorstr_("SSZ Ran Since Logon \"ssz.gg\"") },
        { xorstr_("download.antarcticacheats.xyz"), xorstr_("Antarctica Cheats Ran Since Logon \"download.antarcticacheats.xyz\"") },
        { xorstr_("antarctica.sellpass.io"), xorstr_("Antarctica Cheats Ran Since Logon \"antarctica.sellpass.io\"") },
        { xorstr_("antarcticacheats.xyz"), xorstr_("Antarctica Cheats Ran Since Logon \"antarcticacheats.xyz\"") },
        { xorstr_("perc.gg"), xorstr_("Perc Ran Since Logon \"perc.gg\"") },
        { xorstr_("pcileech.com"), xorstr_("PCILeech Ran Since Logon \"pcileech.com\"") },
        { xorstr_("memprocfs.com"), xorstr_("MemProcFS Ran Since Logon \"memprocfs.com\"") },
        { xorstr_("dma-shop.com"), xorstr_("DMA Shop Ran Since Logon \"dma-shop.com\"") },
        { xorstr_("fpgacheats.com"), xorstr_("FPGA Cheats Ran Since Logon \"fpgacheats.com\"") },
        { xorstr_("dmastore.gg"), xorstr_("DMA Store Ran Since Logon \"dmastore.gg\"") },
        { xorstr_("squirreldma.com"), xorstr_("Squirrel DMA Ran Since Logon \"squirreldma.com\"") },
        { xorstr_("leechcore.com"), xorstr_("LeechCore Ran Since Logon \"leechcore.com\"") },
        { xorstr_("kmboxb.com"), xorstr_("KMBox B Ran Since Logon \"kmboxb.com\"") },
        { xorstr_("kmbox.pro"), xorstr_("KMBox Ran Since Logon \"kmbox.pro\"") },
        { xorstr_("arduino-cheat.com"), xorstr_("Arduino Cheat Ran Since Logon \"arduino-cheat.com\"") },
        { xorstr_("guided-hacking.com"), xorstr_("Guided Hacking Ran Since Logon \"guided-hacking.com\"") },
        { xorstr_("hackforums.net"), xorstr_("HackForums Ran Since Logon \"hackforums.net\"") },
        { xorstr_("mpgh.net"), xorstr_("MPGH Ran Since Logon \"mpgh.net\"") },
        { xorstr_("cheatautomation.com"), xorstr_("Cheat Automation Ran Since Logon \"cheatautomation.com\"") },
        { xorstr_("aimware.net"), xorstr_("Aimware Ran Since Logon \"aimware.net\"") },
        { xorstr_("interwebz.cc"), xorstr_("Interwebz Ran Since Logon \"interwebz.cc\"") },
        { xorstr_("lmaobox.net"), xorstr_("LMAOBox Ran Since Logon \"lmaobox.net\"") },
        { xorstr_("streamline-cheats.com"), xorstr_("Streamline Cheats Ran Since Logon \"streamline-cheats.com\"") },
        { xorstr_("nixware.cc"), xorstr_("Nixware Ran Since Logon \"nixware.cc\"") },
        { xorstr_("pandora-cheats.com"), xorstr_("Pandora Cheats Ran Since Logon \"pandora-cheats.com\"") },
        { xorstr_("hyperion-cheats.com"), xorstr_("Hyperion Cheats Ran Since Logon \"hyperion-cheats.com\"") },
        { xorstr_("cobracheats.com"), xorstr_("Cobra Cheats Ran Since Logon \"cobracheats.com\"") },
        { xorstr_("sellpass.io"), xorstr_("Sellpass Ran Since Logon \"sellpass.io\"") },
        { xorstr_("whop.com"), xorstr_("Whop Ran Since Logon \"whop.com\"") },
        { xorstr_("enigmadma.com"), xorstr_("Enigma DMA Ran Since Logon \"enigmadma.com\"") },
        { xorstr_("dma-fw.com"), xorstr_("DMA Firmware Ran Since Logon \"dma-fw.com\"") },
        { xorstr_("fpga-cheats.com"), xorstr_("FPGA Cheats Ran Since Logon \"fpga-cheats.com\"") },
        { xorstr_("lambdaconcept.com"), xorstr_("LambdaConcept Ran Since Logon \"lambdaconcept.com\"") },
        { xorstr_("squirreldma.gg"), xorstr_("Squirrel DMA Ran Since Logon \"squirreldma.gg\"") },
        { xorstr_("pcileech.io"), xorstr_("PCILeech Ran Since Logon \"pcileech.io\"") },
        { xorstr_("dmatools.net"), xorstr_("DMA Tools Ran Since Logon \"dmatools.net\"") },
        { xorstr_("hwid-spoofer.com"), xorstr_("HWID Spoofer Ran Since Logon \"hwid-spoofer.com\"") },
        { xorstr_("hwid-ban.com"), xorstr_("HWID Ban Ran Since Logon \"hwid-ban.com\"") },
        { xorstr_("rena.lol"), xorstr_("Rena Ran Since Logon \"rena.lol\"") },
        { xorstr_("keyauth.cc"), xorstr_("KeyAuth File Ran Since Logon \"keyauth.cc\"") },
        { xorstr_("keyauth.win"), xorstr_("KeyAuth File Ran Since Logon \"keyauth.win\"") },
        { xorstr_("2.56.246.3"), xorstr_("Revuelto Ran Since Logon \"2.56.246.3\"") },

};

std::vector<std::pair<std::string, std::string>> lsass_scan::get_custom_filters_only() {
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
                            if (process_name == xorstr_("Lsass.exe")) {
                                size_t pos = 0;
                                while (pos < raw_strings.size()) {
                                    size_t next = raw_strings.find(xorstr_("\r\n"), pos);
                                    std::string line;
                                    if (next == std::string::npos) {
                                        line = raw_strings.substr(pos);
                                        pos = raw_strings.size();
                                    }
                                    else {
                                        line = raw_strings.substr(pos, next - pos);
                                        pos = next + 2;
                                    }
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

bool lsass_scan::apply_filter(const std::string& memory_string, const std::pair<std::string, std::string>& filter, bool is_custom) {
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
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("Custom String ") + filter.second + xorstr_(" Found:") + memory_string;
            else
                LOG(DETECTION, xorstr_("N/A")) << filter.second << xorstr_(" Found In Lsass.exe:") << memory_string;
        }
        return true;
    }
    catch (...) { return false; }
}

void lsass_scan::scan_process_memory(HANDLE h_process) {
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
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("Custom String ") + e.name + xorstr_(" Found:") + original;
            else
                LOG(DETECTION, xorstr_("N/A")) << e.name << xorstr_(" Found In Lsass.exe:") << original;
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

void lsass_scan::start_lsass_scan() {
    try {
        if (!lsass_scan::enable_debug_privilege()) return;

        DWORD process_id = lsass_scan::get_pid_by_process_name(xorstr_("Lsass.exe"));
        if (process_id == 0) return;

        HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
        if (!h_process) return;

        lsass_scan::scan_process_memory(h_process);

        CloseHandle(h_process);
    }
    catch (...) {}
}
