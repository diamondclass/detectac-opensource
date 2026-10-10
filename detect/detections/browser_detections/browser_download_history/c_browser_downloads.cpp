#include "c_browser_downloads.h"

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

const std::vector<BrowserDownloadScanner::FilterRule> BrowserDownloadScanner::filters = {

#ifdef DETECT_FIVEM

{xorstr_("skript.gg"), xorstr_("File Downloaded From Skript")},
{xorstr_("tzproject.com"), xorstr_("File Downloaded From TZ Project")},
{xorstr_("hxcheats.tech"), xorstr_("File Downloaded From Hx Cheats")},
{xorstr_("gosth.gg"), xorstr_("File Downloaded From Gosth")},
{xorstr_("ghostesportpanel.com"), xorstr_("File Downloaded From Gosth")},
{xorstr_("eulencheats.com"), xorstr_("File Downloaded From Eulen")},
{xorstr_("eulen.cc"), xorstr_("File Downloaded From Eulen Website")},
{xorstr_("luamenu.xyz"), xorstr_("File Downloaded From Lua (RedEngine)")},
{xorstr_("redengine.eu"), xorstr_("File Downloaded From RedEngine")},
{xorstr_("redengine.net"), xorstr_("File Downloaded From RedEngine")},
{xorstr_("susano.re"), xorstr_("File Downloaded From Susano")},
{xorstr_("machocheats.com"), xorstr_("File Downloaded From Macho Cheats")},
{xorstr_("88-cheats.xyz"), xorstr_("File Downloaded From 88 Cheats")},
{xorstr_("testo.gg"), xorstr_("File Downloaded From Testo Cheats")},
{xorstr_("blackout.wtf"), xorstr_("File Downloaded From Blackout Cheats")},
{xorstr_("monstermenu.cc"), xorstr_("File Downloaded From Monster Menu")},
{xorstr_("9zproject.xyz"), xorstr_("File Downloaded From 9z Project")},
{xorstr_("sergiu.pro"), xorstr_("File Downloaded From Spotless")},
{xorstr_("projectdow.com"), xorstr_("File Downloaded From Dow")},
{xorstr_("api.shilav2.shop"), xorstr_("File Downloaded From Wexless")},
{xorstr_("193.23.160.168"), xorstr_("File Downloaded From Signer")},
{xorstr_("orbit.signer.cc"), xorstr_("File Downloaded From Signer")},
{xorstr_("signer.cc"), xorstr_("File Downloaded From Signer")},
{xorstr_("bypass.fun"), xorstr_("File Downloaded From Bypass.Fun")},
{xorstr_("keyser-lts.com"), xorstr_("File Downloaded From Keyser")},
{xorstr_("keyser.gg"), xorstr_("File Downloaded From Keyser")},
{xorstr_("185.236.228.154"), xorstr_("File Downloaded From FLK")},
{xorstr_("flkstore.com"), xorstr_("File Downloaded From FLK")},
{xorstr_("flk-uhq.xyz"), xorstr_("File Downloaded From FLK")},
{xorstr_("5.206.224.37"), xorstr_("File Downloaded From FLK")},
{xorstr_("bebetter-fivem"), xorstr_("File Downloaded From Be-better")},
{xorstr_("venacy.club"), xorstr_("File Downloaded From Venacy")},
{xorstr_("antiecho.xyz"), xorstr_("File Downloaded From Ant-Echo")},
{xorstr_("203.159.90.127"), xorstr_("File Downloaded From Lethality Script")},
{xorstr_("leet-cheats.ru"), xorstr_("File Downloaded From Leet Cheats")},
{xorstr_("hydrogen.ac"), xorstr_("File Downloaded From Hydrogen Cheats")},
{xorstr_("trinitas.top"), xorstr_("File Downloaded From Trinitas Cheats")},
{xorstr_("blurred.gg"), xorstr_("File Downloaded From Blurred Cheats")},
{ xorstr_("captaindma.com"), xorstr_("File Downloaded From Captain DMA Cheats") },
{ xorstr_("pulsedma.com"), xorstr_("File Downloaded From Pulse DMA Cheats") },
{ xorstr_("makcu.com"), xorstr_("File Downloaded From Makcu Cheats") },
{ xorstr_("vanish-cheat.com"), xorstr_("File Downloaded From Vanish Cheats") },
{ xorstr_("91.218.66.77"), xorstr_("File Downloaded From Forte") },
{ xorstr_("uzuimarket.xyz"), xorstr_("File Downloaded From Uzui Market") },
{ xorstr_("spotless.gg"), xorstr_("File Downloaded From Spotless Bypass") },
{xorstr_("https://download2300.mediafire.com/20hagb9obougVGckfHglHU-VIz_NiaJVFd7H_-5DICs4CLBnZdqHeuuhiERvcK-ae58m7NxAgHHF4mddiYAPoMSvS9HsVJ2oKP2xBXWj9-JFybxVGYBkBhoDd9sAqkDIHuJCm_J16MiE33kZtWSTTRxE_VfF3xAqS80tvnnKVPLukw/duru9jadxca89fy/Povika+Hitbox.zip"), xorstr_("File Downloaded From Povika Hitbox")},
{xorstr_("https://download2389.mediafire.com/jj92lf2hy1ogqRVYSzLw_suPpYUPBsKK2ri5ZF6l8j4PDqBR2B8-jz6Vm3OqUZyUPVYTGX9NCO4HJu7DnoaACZamv5TWiefUF28SRqj_XNYw8k7s9eeskXBEqza5W6ETXeef-KXimrKcjFj1LQFaDRTVyb1MDbkAMIlujMAJypvqcg/4ujmntlr0j5yhhe/CustomH1itb0x3s.zip"), xorstr_("File Downloaded From CustomH1itb0x3s")},
{xorstr_("https://takeout-download-drive-eu.usercontent.google.com/download/drive-download-20250820T093435Z-1-001.zip?j=a527cd61-807b-4987-9bd7-381e2ed43797&i=0&user=37111652107&authuser=0"), xorstr_("File Downloaded From ShenanigansHitbox")},
{xorstr_("https://drive.usercontent.google.com/download?id=1AYITb1cfiFa4UFFYtXXPa2cDHgG8uPsm&export=download&authuser=0&confirm=t&uuid=0e3b40f5-f404-46b3-9255-720e0c5d00a5&at=AN8xHooRPecdZg_qEx2RN_wv8Gn-%3A1755682572030"), xorstr_("File Downloaded From Aimbot Redux")},
{xorstr_("https://drive.usercontent.google.com/download?id=1w3_dj_OQbu-OfNzcasFkT6GRtu6E-bt7&export=download&authuser=0&confirm=t&uuid=f1ba70dd-9fe5-4de7-bf7c-0b5dcdfc7a33&at=AN8xHoq-0-1eyiz5Ekw1pv0ml9fL%3A1755682613990"), xorstr_("File Downloaded From Redux Cheat")},
{xorstr_("https://drive.usercontent.google.com/download?id=1YJ0SNGLQiR-dD4w5gMYFZCq0cpIqkyHQ&export=download&authuser=0&confirm=t&uuid=cc723d0c-1b99-4cd5-b7ad-9ceaed267d1e&at=AN8xHooIObZI-qg9wbKhxuCmUrq5%3A1755686597792"), xorstr_("File Downloaded From Redux Hacks")},
{xorstr_("traceless.wtf"), xorstr_("File Downloaded From Traceless Bypass")},
{xorstr_("a.pomf.cat/glNyzpV"), xorstr_("File Downloaded From 9Z Bypass")},
{xorstr_("a.pomf.cat/UgdZcKh"), xorstr_("File Downloaded From 9Z Bypass")},
{xorstr_("serapi.mom"), xorstr_("File Downloaded From Spotless/Binary Bypass")},
{xorstr_("freshbypass.xyz"), xorstr_("File Downloaded From Fresh Bypass")},
{xorstr_("designcraft.xyz"), xorstr_("File Downloaded From Response Bypass")},
{xorstr_("snowbp.xyz"), xorstr_("File Downloaded From Snow Bypass")},
{xorstr_("87.120.191.29"), xorstr_("File Downloaded From Quanta")},
{xorstr_("club44.lol"), xorstr_("File Downloaded From Club44")},
{xorstr_("catatau.xyz"), xorstr_("File Downloaded From XYZ DMA")},
{xorstr_("auis.binaryy.top"), xorstr_("File Downloaded From Binary Bypass")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co"), xorstr_("File Downloaded From Binary Bypass")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/auth-login"), xorstr_("File Downloaded From Binary Bypass Login Page")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/vpn-check"), xorstr_("File Downloaded From Binary Bypass VPN Check Page")},
{xorstr_("etezmdkyybdrsczqfjky.supabase.co/rest/v1/rpc/get_maintenance_mode"), xorstr_("File Downloaded From Binary Bypass Maintinence Page")},
{xorstr_("serotonin.win"), xorstr_("File Downloaded From Seotonin Bypass")},
{xorstr_("181.215.45.13"), xorstr_("File Downloaded From Club44 Bypass")},
{xorstr_("93.127.215.67"), xorstr_("File Downloaded From Club44 Bypass")},
{xorstr_("severance.today"), xorstr_("File Downloaded From Severance Bypass")},
{xorstr_("gnomus.lol/mefedron/ziolo/ukrainski_igraszki/"), xorstr_("File Downloaded From FiveM Enjoyer")},
{xorstr_("gnomus.lol"), xorstr_("File Downloaded From FiveM Enjoyer")},
{xorstr_("pub-047df53bbd524128a2b8f1477ec0e316.r2.dev"), xorstr_("File Downloaded From Severance Bypass")},
{xorstr_("45.156.87.118"), xorstr_("File Downloaded From Unknown Bypass")},
{xorstr_("16.171.254.8"), xorstr_("File Downloaded From Bypass.fun Bypass")},
{xorstr_("certificate.wtf"), xorstr_("File Downloaded From certificate.wtf")},
{xorstr_("cosmos.pm"), xorstr_("File Downloaded From Cosmos")},
{xorstr_("rxmenu.shop"), xorstr_("File Downloaded From RX Menu")},
{xorstr_("omertasoftware.com"), xorstr_("File Downloaded From Omerta Software")},
{xorstr_("xentro.xyz"), xorstr_("File Downloaded From Xentro")},
{xorstr_("titanbypass.com"), xorstr_("File Downloaded From Titan Bypass")},
{xorstr_("us1.phase.uno"), xorstr_("File Downloaded From Phase Uno")},
{xorstr_("phase.uno"), xorstr_("File Downloaded From Phase Uno")},
{xorstr_("104.21.82.227"), xorstr_("File Downloaded From Phase Uno")},
{xorstr_("104.18.2.36"), xorstr_("File Downloaded From Phase Uno")},
{xorstr_("wizardbypass.com"), xorstr_("File Downloaded From Wizard Bypass")},
{xorstr_("loginlive.cloud"), xorstr_("File Downloaded From Wizard Bypass")},
{xorstr_("54.39.67.23"), xorstr_("File Downloaded From Rolex Bypass")},
{xorstr_("richh.lol"), xorstr_("File Downloaded From Rolex Bypass")},
{xorstr_("antiscan.xyz"), xorstr_("File Downloaded From Rolex Bypass")},
{xorstr_("evora.pw"), xorstr_("File Downloaded From Evora")},
{xorstr_("45.143.196.213"), xorstr_("File Downloaded From Bytecode Bypass")},
{xorstr_("Sirius.lv"), xorstr_("File Downloaded From Sirius Bypass")},


#elif DETECT_MINECRAFT

{xorstr_("drip.gg"), xorstr_("File Downloaded From Drip")},
{xorstr_("karma.rip"), xorstr_("File Downloaded From Karma")},
{xorstr_("vape.gg"), xorstr_("File Downloaded From Vape")},
{xorstr_("sunset.rip"), xorstr_("File Downloaded From Sunset")},
{xorstr_("doomsdayclient.com"), xorstr_("File Downloaded From Doomsday")},
{xorstr_("neverlack.in"), xorstr_("File Downloaded From Drip")},
{xorstr_("akiraghost.com"), xorstr_("File Downloaded From Akira")},
{xorstr_("entropy.club"), xorstr_("File Downloaded From Entropy")},
{xorstr_("dreamclient.xyz"), xorstr_("File Downloaded From Dream")},
{xorstr_("crypp.in"), xorstr_("File Downloaded From Dream")},
{xorstr_("dopp.in"), xorstr_("File Downloaded From Dopp")},
{xorstr_("slapp.in"), xorstr_("File Downloaded From Slapp")},
{xorstr_("unicorn-hacks.net"), xorstr_("File Downloaded From Unicorn")},
{xorstr_("prestigeclient.vip"), xorstr_("File Downloaded From Prestigeclient")},
{xorstr_("api.prestigeclient.vip"), xorstr_("File Downloaded From Prestigeclient API")},
{xorstr_("bypassing.gg"), xorstr_("File Downloaded From Cold Bypassing Website")},
{xorstr_("grimclient.eu"), xorstr_("File Downloaded From Grim")},
{xorstr_("axen.lol"), xorstr_("File Downloaded From Axen")},
{xorstr_("aristois.net"), xorstr_("File Downloaded From Aristois")},
{xorstr_("catlean.su"), xorstr_("File Downloaded From Catlean")},
{xorstr_("client-analytics.dev"), xorstr_("File Downloaded From Cold Bypass Website")},

#elif DETECT_ROBLOX

{xorstr_("robloxcheatz.com"), xorstr_("File Downloaded From Robloxcheatz")},
{xorstr_("radiant.cc"), xorstr_("File Downloaded From Radiant")},
{xorstr_("eternalproduct.com"), xorstr_("File Downloaded From Eternal Product")},
{xorstr_("matrixhubs.shop"), xorstr_("File Downloaded From Matrix")},
{xorstr_("buymtx.online"), xorstr_("File Downloaded From Matrix")},
{xorstr_("buymtx"), xorstr_("File Downloaded From Matrix")},
{xorstr_("mega.nz/folder/KehEhLzB#Cs0PiuqggmwItBIcAG4z6w"), xorstr_("File Downloaded From Mooze MegaFolder")},
{xorstr_("mooze.fun"), xorstr_("File Downloaded From Mooze")},
{xorstr_("hastebin.skyra.pw"), xorstr_("File Downloaded From Config")},
{xorstr_("vapevoidware.xyz"), xorstr_("File Downloaded From Voidware")},
{xorstr_("voxlis.net"), xorstr_("File Downloaded From Voxlis")},
{xorstr_("voltbz.net"), xorstr_("File Downloaded From Volt")},
{xorstr_("potassium.pro"), xorstr_("File Downloaded From Potassium")},
{xorstr_("getwave.gg"), xorstr_("File Downloaded From Wave")},
{xorstr_("z.synapse.do"), xorstr_("File Downloaded From Synapse Z")},
{xorstr_("seliware.com"), xorstr_("File Downloaded From Seliware")},
{xorstr_("getmadium.net"), xorstr_("File Downloaded From Madium")},
{xorstr_("realvelocity.xyz"), xorstr_("File Downloaded From Velocity")},
{xorstr_("sirhurt.net"), xorstr_("File Downloaded From SirHurt")},
{xorstr_("getsolara.dev"), xorstr_("File Downloaded From Solara")},
{xorstr_("xeno.now"), xorstr_("File Downloaded From Xeno")},
{xorstr_("raptor.fun"), xorstr_("File Downloaded From MacSploit")},
{xorstr_("deltaexploits.gg"), xorstr_("File Downloaded From Delta Exploits")},
{xorstr_("getcryptic.net"), xorstr_("File Downloaded From Cryptic")},
{xorstr_("vegax.gg"), xorstr_("File Downloaded From Vega X")},
{xorstr_("codex.lol"), xorstr_("File Downloaded From Codex")},
{xorstr_("serotonin.win"), xorstr_("File Downloaded From Serotonin")},
{xorstr_("matcha-latte.win"), xorstr_("File Downloaded From Matcha")},
{xorstr_("photonsys.sellpass.io"), xorstr_("File Downloaded From Photon")},
{xorstr_("cultofintellect.com"), xorstr_("File Downloaded From DX9WARE V2")},
{xorstr_("vexor.wtf"), xorstr_("File Downloaded From Vexor")},

#elif DETECT_RUST

{xorstr_("onestopcheats"), xorstr_("File Downloaded From Onestopcheats")},
{xorstr_("blurred.gg"), xorstr_("File Downloaded From Blurred Cheats")},
{ xorstr_("captaindma.com"), xorstr_("File Downloaded From Captain DMA Cheats") },
{ xorstr_("pulsedma.com"), xorstr_("File Downloaded From Pulse DMA Cheats") },
{ xorstr_("makcu.com"), xorstr_("File Downloaded From Makcu Cheats") },

#elif DETECT_FORTNITE

{xorstr_("skycheats"), xorstr_("File Downloaded From Skycheats")},
{xorstr_("SkyCheats.com"), xorstr_("File Downloaded From SkyCheats.com")},
{xorstr_("battlelog.co"), xorstr_("File Downloaded From battlelog")},
{xorstr_("aimclub.io"), xorstr_("File Downloaded From aimclub")},
{xorstr_("uniquehacks.store"), xorstr_("File Downloaded From uniquehacks")},
{xorstr_("privatecheatz.com"), xorstr_("File Downloaded From privatecheatz")},
{xorstr_("colossalcheats.com"), xorstr_("File Downloaded From colossalcheats")},
{xorstr_("hackerbot.net"), xorstr_("File Downloaded From hackerbot")},
{xorstr_("army-cheats.com"), xorstr_("File Downloaded From army-cheats")},
{xorstr_("spycheats.net"), xorstr_("File Downloaded From spycheats")},
{xorstr_("santana-tech.com/"), xorstr_("File Downloaded From santana-tech")},
{xorstr_("aimhax.net"), xorstr_("File Downloaded From aimhax")},
{xorstr_("kernelcheats.to"), xorstr_("File Downloaded From kernelcheats")},
{xorstr_("infinitycheats.net"), xorstr_("File Downloaded From infinitycheats")},
{xorstr_("xera-cheats.com"), xorstr_("File Downloaded From xera-cheats")},
{xorstr_("zeta-cheats.com"), xorstr_("File Downloaded From zeta-cheats")},
{xorstr_("neo-cheats.com"), xorstr_("File Downloaded From neo-cheats")},
{xorstr_("Lavicheats.com"), xorstr_("File Downloaded From Lavicheats")},
{xorstr_("cheating.gg"), xorstr_("File Downloaded From Cheating")},
{xorstr_("ventro.tech"), xorstr_("File Downloaded From Solaris")},
{xorstr_("sceptre.pro"), xorstr_("File Downloaded From Sceptre")},
{xorstr_("185.236.228.154"), xorstr_("File Downloaded From FLK")},
{xorstr_("flkstore.com"), xorstr_("File Downloaded From FLK")},
{xorstr_("flk-uhq.xyz"), xorstr_("File Downloaded From FLK")},
{xorstr_("5.206.224.37"), xorstr_("File Downloaded From FLK")},
{xorstr_("blurred.gg"), xorstr_("File Downloaded From Blurred Cheats")},
{xorstr_("ednersoftware.com"), xorstr_("File Downloaded From Ender Cheats")},
{xorstr_("aquacheats.cc"), xorstr_("File Downloaded From Aqua Cheats")},
{xorstr_("avx.sellhub.cx"), xorstr_("File Downloaded From AVX Cheats")},
{xorstr_("kartoxa.com"), xorstr_("File Downloaded From Kartoxa Cheats")},
{xorstr_("captaindma.com"), xorstr_("File Downloaded From Captain DMA Cheats")},
{ xorstr_("pulsedma.com"), xorstr_("File Downloaded From Pulse DMA Cheats") },
{ xorstr_("makcu.com"), xorstr_("File Downloaded From Makcu Cheats") },
{ xorstr_("keyser-lts.com"), xorstr_("File Downloaded From Keyser") },
{ xorstr_("keyser.gg"), xorstr_("File Downloaded From Keyser") },
{ xorstr_("zombiecheats.com"), xorstr_("File Downloaded From Zombie Cheats") },
{ xorstr_("hypervision.gg"), xorstr_("File Downloaded From hypervision Cheats") },
{ xorstr_("elocarry.net"), xorstr_("File Downloaded From Elocarry") },
{ xorstr_("engineowning.su"), xorstr_("File Downloaded From EngineOwning") },
{ xorstr_("uzuimarket.xyz"), xorstr_("File Downloaded From Uzui Market") },
{ xorstr_("exodus.fun"), xorstr_("File Downloaded From Exodus Cheats") },
{xorstr_("195.59.67.101"), xorstr_("File Downloaded From ICanHaZip")},
{xorstr_("icanhazip.com"), xorstr_("File Downloaded From ICanHaZip")},
{xorstr_("udsoftwares.com"), xorstr_("File Downloaded From UD Softwares")},
{xorstr_("crythosbackend-production.up.railway.app"), xorstr_("File Downloaded From Crythos")},

#elif DETECT_DAYZ

{xorstr_("stugware.com"), xorstr_("File Downloaded From Stugwware")},
{xorstr_("cheatseller.com"), xorstr_("File Downloaded From Cheatseller")},
{xorstr_("elitehacks.ru"), xorstr_("File Downloaded From Elite Hacks")},
{xorstr_("smgcheats.com"), xorstr_("File Downloaded From SMG Cheats")},
{xorstr_("battlelog.co"), xorstr_("File Downloaded From Battlelog")},
{xorstr_("ducks-services.com"), xorstr_("File Downloaded From Ducks Services")},
{xorstr_("skycheats.com"), xorstr_("File Downloaded From Sky Cheats")},
{xorstr_("elitepvpers.com"), xorstr_("File Downloaded From ElitePVPers")},
{xorstr_("kernaim.to"), xorstr_("File Downloaded From Kernaim")},
{xorstr_("ciroscript.com"), xorstr_("File Downloaded From CiroScript")},
{xorstr_("wh-satano.ru"), xorstr_("File Downloaded From WH Satano")},
{xorstr_("blast.hk"), xorstr_("File Downloaded From Blast")},
{xorstr_("cheatseller.ru"), xorstr_("File Downloaded From Cheatseller RU")},
{xorstr_("cheat.bz"), xorstr_("File Downloaded From Cheat BZ")},
{xorstr_("clutch-solution.com"), xorstr_("File Downloaded From Clutch Solution")},
{xorstr_("715team.ru"), xorstr_("File Downloaded From 715 Team")},
{xorstr_("labcorecheats.com"), xorstr_("File Downloaded From Labcore Cheats")},
{xorstr_("byster.one"), xorstr_("File Downloaded From Byster")},
{xorstr_("up-game.pro"), xorstr_("File Downloaded From Up Game")},
{xorstr_("zsoft.store"), xorstr_("File Downloaded From ZSoft")},
{xorstr_("dayzradar.715team.ru"), xorstr_("File Downloaded From DayZ Radar 715 Team")},

#elif DETECT_SIEGE

{xorstr_("skreechware.com"), xorstr_("File Downloaded From Skreechware")},
{xorstr_("cosmocheats.com"), xorstr_("File Downloaded From Cosmocheats")},
{xorstr_("nyronai.com"), xorstr_("File Downloaded From Nyronai")},
{xorstr_("aptitude.pub"), xorstr_("File Downloaded From Aptitude")},
{xorstr_("visuals.gg"), xorstr_("File Downloaded From Visuals")},
{xorstr_("battlelog.com"), xorstr_("File Downloaded From Battlelog")},
{ xorstr_("blurred.gg"), xorstr_("File Downloaded From Blurred Cheats") },
{ xorstr_("captaindma.com"), xorstr_("File Downloaded From Captain DMA Cheats") },
{ xorstr_("pulsedma.com"), xorstr_("File Downloaded From Pulse DMA Cheats") },
{ xorstr_("makcu.com"), xorstr_("File Downloaded From Makcu Cheats") },
{xorstr_("connerzon.com"), xorstr_("File Downloaded From Connerzon")},
{xorstr_("r6needs.store"), xorstr_("File Downloaded From R6Needs")},
{xorstr_("edaters.store"), xorstr_("File Downloaded From Edaters")},
{xorstr_("beatbct.com"), xorstr_("File Downloaded From BeatBCT")},
{xorstr_("xerus.cc"), xorstr_("File Downloaded From Xerus")},
{xorstr_("overdose.support"), xorstr_("File Downloaded From Overdose")},
{xorstr_("veylo.io"), xorstr_("File Downloaded From Veylo")},
{xorstr_("chudvision.net"), xorstr_("File Downloaded From Chudvision")},
{xorstr_("exloader.net"), xorstr_("File Downloaded From ExLoader")},
{xorstr_("battlelog.co"), xorstr_("File Downloaded From Battlelog CO")},
{xorstr_("sinfulexp.net"), xorstr_("File Downloaded From SinfulExp")},
{xorstr_("ancient.su"), xorstr_("File Downloaded From Ancient")},
{xorstr_("enhancedsolutions.cc"), xorstr_("File Downloaded From Enhanced Solutions")},
{xorstr_("closetware.store"), xorstr_("File Downloaded From Closetware")},
{xorstr_("ghostware.cc"), xorstr_("File Downloaded From Ghostware")},
{xorstr_("deception.gg"), xorstr_("File Downloaded From Deception")},
{xorstr_("hexdma.com"), xorstr_("File Downloaded From HexDMA")},
{xorstr_("aquacheats.cc"), xorstr_("File Downloaded From AquaCheats")},
{xorstr_("calamari.lol"), xorstr_("File Downloaded From Calamari")},
{xorstr_("elocarry.net"), xorstr_("File Downloaded From EloCarry")},
{xorstr_("lavicheats.com"), xorstr_("File Downloaded From LaviCheats")},
{xorstr_("gear5.sellpass.io"), xorstr_("File Downloaded From Gear5")},
{xorstr_("reportedcheats.com"), xorstr_("File Downloaded From ReportedCheats")},
{xorstr_("outkastcheats.com"), xorstr_("File Downloaded From OutkastCheats")},
{xorstr_("kernelsight.com"), xorstr_("File Downloaded From KernelSight")},
{xorstr_("klar.gg"), xorstr_("File Downloaded From Klar")},
{xorstr_("lethalcheats.net"), xorstr_("File Downloaded From LethalCheats")},
{xorstr_("lynxtech.pro"), xorstr_("File Downloaded From LynxTech")},
{xorstr_("unknowncheats.me"), xorstr_("File Downloaded From UnknownCheats")},
{xorstr_("playsharp.io"), xorstr_("File Downloaded From PlaySharp")},
{xorstr_("1nvituscheats.com"), xorstr_("File Downloaded From 1nvitus Cheats")},
{xorstr_("shopring1nvitus.com"), xorstr_("File Downloaded From ShopRing 1nvitus")},
{xorstr_("red-xservices.com"), xorstr_("File Downloaded From Red X Services")},

#elif DETECT_COD

{xorstr_("streckaio.com"), xorstr_("File Downloaded From Strecka.io")},

#elif DETECT_CS

{xorstr_("memesense.gg"), xorstr_("File Downloaded From Memesense")},
{xorstr_("midnight.im"), xorstr_("File Downloaded From Midnight")},
{xorstr_("gamesense.vip"), xorstr_("File Downloaded From GameSense")},

#endif

{xorstr_("aimjunkies.com"), xorstr_("File Downloaded From AimJunkies")},
{xorstr_("systemcheats.net"), xorstr_("File Downloaded From SystemCheats")},
{xorstr_("engineowning.to"), xorstr_("File Downloaded From EngineOwning")},
{xorstr_("skeet.cc"), xorstr_("File Downloaded From Skeet")},
{xorstr_("gamesense.pub"), xorstr_("File Downloaded From GameSense")},
{xorstr_("primordial.dev"), xorstr_("File Downloaded From Primordial")},
{xorstr_("neverlose.cc"), xorstr_("File Downloaded From Neverlose")},
{xorstr_("fatality.win"), xorstr_("File Downloaded From Fatality")},
{xorstr_("onetap.com"), xorstr_("File Downloaded From OneTap")},
{xorstr_("onetap.su"), xorstr_("File Downloaded From OneTap")},
{xorstr_("skreech.gg"), xorstr_("File Downloaded From Skreech")},
{xorstr_("cheatsense.sellhub.cx"), xorstr_("File Downloaded From CheatSense")},
{xorstr_("r6hibania.cc"), xorstr_("File Downloaded From R6 Hibania")},
{xorstr_("chair.wtf"), xorstr_("File Downloaded From Chair")},
{xorstr_("tomware.cc"), xorstr_("File Downloaded From Tomware")},
{xorstr_("rankuen.com"), xorstr_("File Downloaded From Rankuen")},
{xorstr_("shop.deception.gg"), xorstr_("File Downloaded From Deception Shop")},
{xorstr_("phoenixlabstore.com"), xorstr_("File Downloaded From Phoenix Lab")},
{xorstr_("oxxscheats.com"), xorstr_("File Downloaded From OxxsCheats")},
{xorstr_("vega.sell.app"), xorstr_("File Downloaded From Vega")},
{xorstr_("cheats.love"), xorstr_("File Downloaded From Cheats.love")},
{xorstr_("chamscheats.com"), xorstr_("File Downloaded From ChamsCheats")},
{xorstr_("whyyoucheating.sellhub.cx"), xorstr_("File Downloaded From WhyYouCheating")},
{xorstr_("tgmodz.com"), xorstr_("File Downloaded From TGModz")},
{xorstr_("ezmod.vip"), xorstr_("File Downloaded From EzMod")},
{xorstr_("ssz.gg"), xorstr_("File Downloaded From SSZ")},
{xorstr_("download.antarcticacheats.xyz"), xorstr_("File Downloaded From Antarctica Cheats")},
{xorstr_("antarctica.sellpass.io"), xorstr_("File Downloaded From Antarctica Cheats")},
{xorstr_("antarcticacheats.xyz"), xorstr_("File Downloaded From Antarctica Cheats")},
{xorstr_("perc.gg"), xorstr_("File Downloaded From Perc")},
{xorstr_("pcileech.com"), xorstr_("File Downloaded From PCILeech")},
{xorstr_("memprocfs.com"), xorstr_("File Downloaded From MemProcFS")},
{xorstr_("dma-shop.com"), xorstr_("File Downloaded From DMA Shop")},
{xorstr_("fpgacheats.com"), xorstr_("File Downloaded From FPGA Cheats")},
{xorstr_("dmastore.gg"), xorstr_("File Downloaded From DMA Store")},
{xorstr_("squirreldma.com"), xorstr_("File Downloaded From Squirrel DMA")},
{xorstr_("leechcore.com"), xorstr_("File Downloaded From LeechCore")},
{xorstr_("kmboxb.com"), xorstr_("File Downloaded From KMBox B")},
{xorstr_("kmbox.pro"), xorstr_("File Downloaded From KMBox")},
{xorstr_("arduino-cheat.com"), xorstr_("File Downloaded From Arduino Cheat")},
{xorstr_("guided-hacking.com"), xorstr_("File Downloaded From Guided Hacking")},
{xorstr_("hackforums.net"), xorstr_("File Downloaded From HackForums")},
{xorstr_("mpgh.net"), xorstr_("File Downloaded From MPGH")},
{xorstr_("cheatautomation.com"), xorstr_("File Downloaded From Cheat Automation")},
{xorstr_("aimware.net"), xorstr_("File Downloaded From Aimware")},
{xorstr_("interwebz.cc"), xorstr_("File Downloaded From Interwebz")},
{xorstr_("lmaobox.net"), xorstr_("File Downloaded From LMAOBox")},
{xorstr_("streamline-cheats.com"), xorstr_("File Downloaded From Streamline Cheats")},
{xorstr_("nixware.cc"), xorstr_("File Downloaded From Nixware")},
{xorstr_("pandora-cheats.com"), xorstr_("File Downloaded From Pandora Cheats")},
{xorstr_("hyperion-cheats.com"), xorstr_("File Downloaded From Hyperion Cheats")},
{xorstr_("cobracheats.com"), xorstr_("File Downloaded From Cobra Cheats")},
{xorstr_("sellpass.io"), xorstr_("File Downloaded From Sellpass")},
{xorstr_("whop.com"), xorstr_("File Downloaded From Whop")},
{xorstr_("enigmadma.com"), xorstr_("File Downloaded From Enigma DMA")},
{xorstr_("dma-fw.com"), xorstr_("File Downloaded From DMA Firmware")},
{xorstr_("fpga-cheats.com"), xorstr_("File Downloaded From FPGA Cheats")},
{xorstr_("lambdaconcept.com"), xorstr_("File Downloaded From LambdaConcept")},
{xorstr_("squirreldma.gg"), xorstr_("File Downloaded From Squirrel DMA")},
{xorstr_("pcileech.io"), xorstr_("File Downloaded From PCILeech")},
{xorstr_("dmatools.net"), xorstr_("File Downloaded From DMA Tools")},
{xorstr_("hwid-spoofer.com"), xorstr_("File Downloaded From HWID Spoofer")},
{xorstr_("hwid-ban.com"), xorstr_("File Downloaded From HWID Ban")},
{xorstr_("rena.lol"), xorstr_("File Downloaded From Rena")},
{xorstr_("2.56.246.3"), xorstr_("File Downloaded From Revuelto")},
{xorstr_("cdn.discordapp.com"), xorstr_("File Downloaded From Discord")},
{xorstr_("localhost:"), xorstr_("File Downloaded From Localhost")},

};

std::string BrowserDownloadScanner::GetLocalAppData() {
    try{
    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path);
    return std::string(path);
    }
    catch (...) { return ""; }
}

std::string BrowserDownloadScanner::GetAppData() {
    try{
    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path);
    return std::string(path);
    }
    catch (...) { return ""; }
}

bool BrowserDownloadScanner::FileExists(const std::string& path) {
    try{
    return std::filesystem::exists(path);
    }
    catch (...) { return false; }
}

bool BrowserDownloadScanner::MatchesFilter(const std::string& url, std::string& messageOut) {
    try{
    for (const auto& filter : filters) {
        if (url.find(filter.urlSubstring) != std::string::npos) {
            messageOut = filter.customMessage;
            return true;
        }
    }
    return false;
    }
    catch (...) { return false; }
}

void BrowserDownloadScanner::ExtractDownloadsFromHistory(const std::string& dbPath, const std::string& browserName) {
    try{
    sqlite3* db;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        return;
    }

    std::string sql = xorstr_("SELECT downloads_url_chains.url, downloads.target_path, downloads.start_time FROM downloads INNER JOIN downloads_url_chains ON downloads.id = downloads_url_chains.id;");

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* url_c = (const char*)sqlite3_column_text(stmt, 0);
            const char* path_c = (const char*)sqlite3_column_text(stmt, 1);
            int64_t startTime = sqlite3_column_int64(stmt, 2);
            std::string url = url_c ? url_c : xorstr_("");
            std::string path = path_c ? path_c : xorstr_("");
            std::string timestamp = ChromeTimeToLocal(startTime);

            std::string customMessage;
            if (MatchesFilter(url, customMessage)) {
                std::string ts = timestamp.empty() ? "" : timestamp;

                if (customMessage == xorstr_("File Downloaded From Discord")) {
                    if (!path.empty()) {
                        LOG(WARNING, ts) << customMessage << xorstr_(":") << path;
                    }
                }
                else {
                    LOG(WARNING, ts) << customMessage << xorstr_(":") << path << xorstr_(" | ") << url;
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);
    }
    catch (...) {}
}

void BrowserDownloadScanner::start_download_history() {
    try{
    std::vector<std::pair<std::string, std::string>> browsers = {
        {xorstr_("Chrome"), GetLocalAppData() + xorstr_("\\Google\\Chrome\\User Data\\Default\\History")},
        {xorstr_("Edge"), GetLocalAppData() + xorstr_("\\Microsoft\\Edge\\User Data\\Default\\History")},
        {xorstr_("Brave"), GetLocalAppData() + xorstr_("\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History")},
        {xorstr_("Opera"), GetAppData() + xorstr_("\\Opera Software\\Opera Stable\\History")}
    };

    for (const auto& browser : browsers) {
        if (FileExists(browser.second)) {
            std::string tempPath = browser.second + xorstr_("_copy");
            std::filesystem::copy_file(browser.second, tempPath, std::filesystem::copy_options::overwrite_existing);
            ExtractDownloadsFromHistory(tempPath, browser.first);
            std::filesystem::remove(tempPath);
        }
    }
    }
    catch (...) {}
}
