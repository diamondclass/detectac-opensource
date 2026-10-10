#include "c_usnjournal.h"

std::vector<usn_scan::custom_check> usn_scan::custom_checks = {
#ifdef DETECT_FIVEM

        {xorstr_("Gosth Created On Disk:"), xorstr_("File Created"), xorstr_(L"settings.cock")},
        {xorstr_("Gosth Created On Disk:"), xorstr_("File Created"), xorstr_(L"abc.abc")},
        {xorstr_("TDLoader Created On Disk:"), xorstr_("File Created"), xorstr_(L"TDLoader.exe")},
        {xorstr_("TDPremium Created On Disk:"), xorstr_("File Created"), xorstr_(L"TDPremium.exe")},
        {xorstr_("FXCheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"FXCheat.exe")},
        {xorstr_("d3d10 Created On Disk:"), xorstr_("File Created"), xorstr_(L"d3d10.dll")},
        {xorstr_("Free Cobra Loader Created On Disk:"), xorstr_("File Created"), xorstr_(L"Free Cobra Loader.exe")},
        {xorstr_("External Created On Disk:"), xorstr_("File Created"), xorstr_(L"external.exe")},
        {xorstr_("Trashcrack Created On Disk:"), xorstr_("File Created"), xorstr_(L"Tutoriaal.txt")},
        {xorstr_("TZ Created On Disk:"), xorstr_("File Created"), xorstr_(L"readMe_EN.txt")},
        {xorstr_("TZ Created On Disk:"), xorstr_("File Created"), xorstr_(L"readMe_FR.txt")},
        {xorstr_("TZ Created On Disk:"), xorstr_("File Created"), xorstr_(L"TZ.zip")},
        {xorstr_("TZX Created On Disk:"), xorstr_("File Created"), xorstr_(L"TZX.zip")},
        {xorstr_("ViperX Created On Disk:"), xorstr_("File Created"), xorstr_(L"Fivem-External.exe")},
        {xorstr_("Void Created On Disk:"), xorstr_("File Created"), xorstr_(L"Mod Menu Void")},
        {xorstr_("Eulen Created On Disk:"), xorstr_("File Created"), xorstr_(L"password_is_eulen")},
        {xorstr_("TZX Created On Disk:"), xorstr_("File Created"), xorstr_(L"svhost.exe")},
        {xorstr_("Eulen Created On Disk:"), xorstr_("File Created"), xorstr_(L"loader.cfg")},
        {xorstr_("Eulen Created On Disk:"), xorstr_("File Created"), xorstr_(L"loader_prod")},
        {xorstr_("RPF Spawn Weapon Created On Disk:"), xorstr_("File Created"), xorstr_(L"ZC-loadout")},
        {xorstr_("Susano Created On Disk:"), xorstr_("File Created"), xorstr_(L"cfg.latest")},
        {xorstr_("9z Project Created On Disk:"), xorstr_("File Created"), xorstr_(L"SETUPQ.exe")},
        {xorstr_("Sinister Created On Disk:"), xorstr_("File Created"), xorstr_(L"unpacked_wup3.dll")},
        {xorstr_("Response Created On Disk:"), xorstr_("File Created"), xorstr_(L"MsSecHealth.exe")},
        {xorstr_("Opium Created On Disk:"), xorstr_("File Created"), xorstr_(L"cfe2ee.exe")},
        {xorstr_("Anti-Echo Created On Disk:"), xorstr_("File Created"), xorstr_(L"unsecap.exe")},
        {xorstr_("Spotless Created On Disk:"), xorstr_("File Created"), xorstr_(L"cum.sys")},
        {xorstr_("Spotless Created On Disk:"), xorstr_("File Created"), xorstr_(L"edgA9BE.tmp")},
        {xorstr_("DC Created On Disk:"), xorstr_("File Created"), xorstr_(L"DC_FREE.exe")},
        {xorstr_("Apateon Created On Disk:"), xorstr_("File Created"), xorstr_(L"symsrv2.dll")},
        {xorstr_("Macho Created On Disk:"), xorstr_("File Created"), xorstr_(L"0CFWz.exe")},
        {xorstr_("Macho Ran On Disk:"), xorstr_("File Created"), xorstr_(L"40bdab0.dll")},
        {xorstr_("Macho Ran On Disk:"), xorstr_("File Created"), xorstr_(L"40bdab1.dll")},
        {xorstr_("Macho Ran On Disk:"), xorstr_("File Created"), xorstr_(L"40bdab2.dll")},
        {xorstr_("Susano Created On Disk:"), xorstr_("File Created"), xorstr_(L"cactus.exe")},
        {xorstr_("TZX Created On Disk:"), xorstr_("File Created"), xorstr_(L"taskthow.exe")},
        {xorstr_("Susano Created On Disk:"), xorstr_("File Created"), xorstr_(L"iguanodon.exe")},
        {xorstr_("Spotless Created On Disk:"), xorstr_("File Created"), xorstr_(L"comctl64.dll.mui")},
        {xorstr_("Keyser Cracked Created On Disk:"), xorstr_("File Created"), xorstr_(L"keycheese.exe")},
        {xorstr_("Strecing Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"bombo.sys")},
        {xorstr_("Mem Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"D3929EA309077DD3D66C1D7A51A164C5.exe")},
        {xorstr_("Unique Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"favicon.json")},
        {xorstr_("9z Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"thum.png")},
        {xorstr_("Binary Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"dxmessaging_01124.ocx")},
        {xorstr_("Moose Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"2rw1kr.bat")},
        {xorstr_("Cracked Forte Created On Disk:"), xorstr_("File Created"), xorstr_(L"crack forte.rar")},
        {xorstr_("Binary Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"mscomctl_69004.ocx")},
        {xorstr_("SirketpdfV3 Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"SirketpdfV3")},
        {xorstr_("Blurred Installer Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"Blurred Installer")},
        {xorstr_("Severance Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"severance.cfg")},
        {xorstr_("MWFree Created On Disk:"), xorstr_("File Created"), xorstr_(L"MWFree+_Cheat_x64")},
        {xorstr_("FLK Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"srk.vbs")},


        //deleted
        {xorstr_("Gosth Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"settings.cock")},
        {xorstr_("Gosth Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"abc.abc")},
        {xorstr_("TDLoader Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"TDLoader.exe")},
        {xorstr_("TDPremium Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"TDPremium.exe")},
        {xorstr_("FXCheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"FXCheat.exe")},
        {xorstr_("d3d10 Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"d3d10.dll")},
        {xorstr_("Free Cobra Loader Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Free Cobra Loader.exe")},
        {xorstr_("Trashcrack Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Tutoriaal.txt")},
        {xorstr_("TZ Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"readMe_EN.txt")},
        {xorstr_("TZ Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"readMe_FR.txt")},
        {xorstr_("TZ Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"TZ.zip")},
        {xorstr_("TZX Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"TZX.zip")},
        {xorstr_("ViperX Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Fivem-External.exe")},
        {xorstr_("Void Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Mod Menu Void")},
        {xorstr_("Eulen Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"password_is_eulen")},
        {xorstr_("TZX Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"svhost.exe")},
        {xorstr_("Eulen Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"loader.cfg")},
        {xorstr_("Eulen Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"loader_prod")},
        {xorstr_("RPF Spawn Weapon Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"ZC-loadout")},
        {xorstr_("Susano Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"cfg.latest")},
        {xorstr_("9z Project Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"SETUPQ.exe")},
        {xorstr_("Response Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"MsSecHealth.exe")},
        {xorstr_("Sinister Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"unpacked_wup3.dll")},
        {xorstr_("Opium Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"cfe2ee.exe")},
        {xorstr_("Anti-Echo Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"unsecap.exe")},
        {xorstr_("Spotless Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"cum.sys")},
        {xorstr_("Spotless Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"edgA9BE.tmp")},
        {xorstr_("DC Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"DC_FREE.exe")},
        {xorstr_("Apateon Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"symsrv2.dll")},
        {xorstr_("Macho Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"0CFWz.exe")},
        {xorstr_("Macho Ran On Disk:"), xorstr_("File Deleted"), xorstr_(L"40bdab0.dll")},
        {xorstr_("Macho Ran On Disk:"), xorstr_("File Deleted"), xorstr_(L"40bdab1.dll")},
        {xorstr_("Macho Ran On Disk:"), xorstr_("File Deleted"), xorstr_(L"40bdab2.dll")},
        {xorstr_("Susano Deleted Off Disk"), xorstr_("File Deleted"), xorstr_(L"cactus.exe")},
        {xorstr_("TZX Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"taskthow.exe")},
        {xorstr_("Mwbyte Cheat Ran Since Logon:"), xorstr_("File Deleted"), xorstr_(L"steamwebhelper.exe.10568.dmp")},
        {xorstr_("Susano Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"iguanodon.exe")},
        {xorstr_("Spotless Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"comctl64.dll.mui")},
        {xorstr_("Keyser Cracked Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"keycheese.exe")},
        {xorstr_("Strecing Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"bombo.sys")},
        {xorstr_("Mem Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"D3929EA309077DD3D66C1D7A51A164C5.exe")},
        {xorstr_("Unique Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"favicon.json")},
        {xorstr_("9z Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"thum.png")},
        {xorstr_("Binary Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"dxmessaging_01124.ocx")},
        {xorstr_("Moose Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"2rw1kr.bat")},
        { xorstr_("Cracked Forte Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"crack forte.rar") },
        { xorstr_("Binary Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"mscomctl_69004.ocx") },
        { xorstr_("MWFree Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"MWFree+_Cheat_x64") },
        {xorstr_("FLK Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"srk.vbs")},

        //skript
        { xorstr_("Skript Modified:"), xorstr_("Data Overwrite"), xorstr_(L"USBDeview.dll") },
        { xorstr_("Skript Modified:"), xorstr_("Data Truncation"), xorstr_(L"USBDeview.dll") },
        { xorstr_("Skript Modified:"), xorstr_("File Changed"), xorstr_(L"USBDeview.dll") },
        { xorstr_("Skript Deleted:"), xorstr_("File Deleted"), xorstr_(L"USBDeview.dll") },
        { xorstr_("Skript Created:"), xorstr_("File Created"), xorstr_(L"USBDeview.dll") },
        { xorstr_("Skript Modified:"), xorstr_("File Renamed Old Name"), xorstr_(L"USBDeview.dll") },
        { xorstr_("Skript Modified:"), xorstr_("Data Overwrite"), xorstr_(L"usbdeview-x64.zip") },
        { xorstr_("Skript Modified:"), xorstr_("Data Truncation"), xorstr_(L"usbdeview-x64.zip") },
        { xorstr_("Skript Modified:"), xorstr_("File Changed"), xorstr_(L"usbdeview-x64.zip") },
        { xorstr_("Skript Deleted:"), xorstr_("File Deleted"), xorstr_(L"usbdeview-x64.zip") },
        { xorstr_("Skript Created:"), xorstr_("File Created"), xorstr_(L"usbdeview-x64.zip") },
        { xorstr_("Skript Modified:"), xorstr_("File Renamed Old Name"), xorstr_(L"usbdeview-x64.zip") },
        { xorstr_("Possible Skript Modified (Name):"), xorstr_("Data Overwrite"), xorstr_(L"USBDeview.exe") },
        { xorstr_("Possible Skript Modified (Name):"), xorstr_("Data Truncation"), xorstr_(L"USBDeview.exe") },
        { xorstr_("Possible Skript Modified (Name):"), xorstr_("File Changed"), xorstr_(L"USBDeview.exe") },
        { xorstr_("Possible Skript Deleted (Name):"), xorstr_("File Deleted"), xorstr_(L"USBDeview.exe") },
        { xorstr_("Possible Skript Created (Name):"), xorstr_("File Created"), xorstr_(L"USBDeview.exe") },
        { xorstr_("Possible Skript Modified (Name):"), xorstr_("File Renamed Old Name"), xorstr_(L"USBDeview.exe") },

        //created
        { xorstr_("0xCheats.exe Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"0xCheats.exe") },
        { xorstr_("Unic.exe Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Unic.exe") },
        { xorstr_("Ret9fun.exe Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Ret9fun.exe") },
        { xorstr_("Nightfall.exe Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Nightfall.exe") },
        { xorstr_("Binance.exe Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Binance.exe") },
        { xorstr_("1337.exe Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"1337 cheats.exe") },

        //deleted
        { xorstr_("0xCheats.exe Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"0xCheats.exe") },
        { xorstr_("Unic.exe Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Unic.exe") },
        { xorstr_("Ret9fun.exe Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Ret9fun.exe") },
        { xorstr_("Nightfall.exe Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Nightfall.exe") },
        { xorstr_("Binance.exe Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Binance.exe") },
        { xorstr_("1337.exe Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"1337 cheats.exe") },
        { xorstr_("Redengine Cheat Launched:"), xorstr_("File Deleted"), xorstr_(L"1234.exe") },

        //FLK detections

        { xorstr_("FLK Bypass Found:"), xorstr_("File Renamed New Name"), xorstr_(L"OperaSetup.exe") },

#elif DETECT_SIEGE

//created
        { xorstr_("KeyRan Created On Disk:"), xorstr_("File Created"), xorstr_(L"KeyRan.exe") },
        { xorstr_("ChatSpam Created On Disk:"), xorstr_("File Created"), xorstr_(L"CHATSPAM.exe") },
        { xorstr_("No Recoil Created On Disk:"), xorstr_("File Created"), xorstr_(L"UniversalNoRecoil.exe") },
        { xorstr_("Dapper Created On Disk:"), xorstr_("File Created"), xorstr_(L"5I2PPoc3JQ") },
//deleted
        { xorstr_("KeyRan Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"KeyRan.exe") },
        { xorstr_("ChatSpam Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"CHATSPAM.exe") },
        { xorstr_("No Recoil Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"UniversalNoRecoil.exe") },
        { xorstr_("Dapper Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"5I2PPoc3JQ") },

#elif DETECT_MINECRAFT
        {xorstr_("Sapphire Created On Disk:"), xorstr_("File Created"), xorstr_(L"Sapphire.LITE")},
        {xorstr_("Itami Created On Disk:"), xorstr_("File Created"), xorstr_(L"itami.exe")},
        {xorstr_("Koid Created On Disk:"), xorstr_("File Created"), xorstr_(L"koid.exe")},
        {xorstr_("AutoClicker Created On Disk:"), xorstr_("File Created"), xorstr_(L"autoclicker.exe")},
        {xorstr_("AutoClicker Created On Disk:"), xorstr_("File Created"), xorstr_(L"clicker.exe")},
        {xorstr_("Doomsday Created On Disk:"), xorstr_("File Created"), xorstr_(L"doomsday.jar")},
        {xorstr_("Akira Created On Disk:"), xorstr_("File Created"), xorstr_(L"akira.exe")},
        {xorstr_("Xcap-setup Created On Disk:"), xorstr_("File Created"), xorstr_(L"xcap-setup.exe")},
        {xorstr_("Prestige-Injector Created On Disk:"), xorstr_("File Created"), xorstr_(L"Prestige-Injector")},
        {xorstr_("Elite Injector Created On Disk:"), xorstr_("File Created"), xorstr_(L"TH3233.tmp")},
        {xorstr_("Hamzee Clicker Created On Disk:"), xorstr_("File Created"), xorstr_(L"RjrbuI2.exe")},
        {xorstr_("Bruzen Bypass Created On Disk:"), xorstr_("File Created"), xorstr_(L"msadres.dll")},
        //deleted
        {xorstr_("Sapphire Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Sapphire.LITE")},
        {xorstr_("Itami Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"itami.exe")},
        {xorstr_("Koid Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"koid.exe")},
        {xorstr_("AutoClicker Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"autoclicker.exe")},
        {xorstr_("AutoClicker Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"clicker.exe")},
        {xorstr_("Doomsday Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"doomsday.jar")},
        {xorstr_("Akira Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"akira.exe")},
        {xorstr_("Xcap-setup Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"xcap-setup.exe")},
        {xorstr_("Prestige-Injector Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Prestige-Injector")},
        {xorstr_("Elite Injector Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"TH3233.tmp")},
        {xorstr_("Hamzee Clicker Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"RjrbuI2.exe")},
        {xorstr_("Bruzen Bypass Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"msadres.dll")},

        {xorstr_("Dopium Bypass Detected:"), xorstr_("Data Truncation"), xorstr_(L"0a6430e5-1177-4514-9ad1-33e41bb43746.tmp")},
        {xorstr_("Lynx Bypass Detected:"), xorstr_("Data Truncation"), xorstr_(L"icudtl.pri")},

#elif DETECT_RUST

        { xorstr_("Evilcheats Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"loginlauncher.exe") },
        { xorstr_("Evilcheats Created On Disk:"), xorstr_("File Created"), xorstr_(L"loginlauncher.exe") },

#elif DETECT_ROBLOX
        {xorstr_("Matrix Created On Disk:"), xorstr_("File Created"), xorstr_(L"matrix.exe")},
        {xorstr_("Matcha Created On Disk:"), xorstr_("File Created"), xorstr_(L"matcha.exe")},
        {xorstr_("Celex Created On Disk:"), xorstr_("File Created"), xorstr_(L"celex.exe")},
        {xorstr_("Solara Created On Disk:"), xorstr_("File Created"), xorstr_(L"solara.exe")},
        {xorstr_("AutoClicker Created On Disk:"), xorstr_("File Created"), xorstr_(L"autoclicker.exe")},
        {xorstr_("AutoClicker Created On Disk:"), xorstr_("File Created"), xorstr_(L"clicker.exe")},
        {xorstr_("Nihon Created On Disk:"), xorstr_("File Created"), xorstr_(L"Nihon.exe")},
        {xorstr_("Nihon Spoofer Created On Disk:"), xorstr_("File Created"), xorstr_(L"SynapseLauncher.exe")},
        {xorstr_("Nihon-Module Created On Disk:"), xorstr_("File Created"), xorstr_(L"Nihon-Module.dll")},
        {xorstr_("Nihon-Interface Created On Disk:"), xorstr_("File Created"), xorstr_(L"Nihon-Interface.dll")},
        {xorstr_("Bootstrapper Created On Disk:"), xorstr_("File Created"), xorstr_(L"Bootstrapper.exe")},
        {xorstr_("Xeno Created On Disk:"), xorstr_("File Created"), xorstr_(L"Xeno.exe")},
        {xorstr_("Horizon Created On Disk:"), xorstr_("File Created"), xorstr_(L"2f72786c-2596-4eeb-be30-762b576d491d.exe")},
        { xorstr_("Loomi Created On Disk:"), xorstr_("File Created"), xorstr_(L"dllhost64.exe") },
        { xorstr_("Swift Created On Disk:"), xorstr_("File Created"), xorstr_(L"Swift-Module.dll") },
        { xorstr_("Swift Created On Disk:"), xorstr_("File Created"), xorstr_(L"Swift.exe") },
        { xorstr_("Xeno Created On Disk:"), xorstr_("File Created"), xorstr_(L"Xeno.exe") },

        //deleted
        {xorstr_("Matrix Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"matrix.exe")},
        {xorstr_("Matcha Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"matcha.exe")},
        {xorstr_("Celex Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"celex.exe")},
        {xorstr_("Solara Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"solara.exe")},
        {xorstr_("AutoClicker Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"autoclicker.exe")},
        {xorstr_("AutoClicker Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"clicker.exe")},
        {xorstr_("Nihon Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Nihon.exe")},
        {xorstr_("Nihon Spoofer Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"SynapseLauncher.exe")},
        {xorstr_("Nihon-Module Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Nihon-Module.dll")},
        {xorstr_("Nihon-Interface Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Nihon-Interface.dll")},
        {xorstr_("Bootstrapper Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Bootstrapper.exe")},
        {xorstr_("Xeno Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Xeno.exe")},
        {xorstr_("Horizon Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"2f72786c-2596-4eeb-be30-762b576d491d.exe")},
        { xorstr_("Mooze Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"obs-nvenc-test.exe") },
        { xorstr_("Loomi Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"dllhost64.exe") },
        { xorstr_("Swift Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Swift-Module.dll") },
        { xorstr_("Swift Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Swift.exe") },
        { xorstr_("Xeno Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Xeno.exe") },

#elif DETECT_FORTNITE

        { xorstr_("Excel Loader Created On Disk:"), xorstr_("File Created"), xorstr_(L"Excel Loader.exe") },
        { xorstr_("Excel Loader Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Excel Loader.exe") },
        { xorstr_("Dope Config File Created On Disk:"), xorstr_("File Created"), xorstr_(L"Dope.txt") },
        { xorstr_("Dope Config File Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Dope.txt") },
        { xorstr_("Inferno Config File Created On Disk:"), xorstr_("File Created"), xorstr_(L"FN_Inferno.txt") },
        { xorstr_("Inferno Config File Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"FN_Inferno.txt") },
        { xorstr_("Inferno Folder Created On Disk:"), xorstr_("File Created"), xorstr_(L"sQS6j8h7Gj") },
        { xorstr_("Inferno Folder Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"sQS6j8h7Gj") },
        { xorstr_("Inferno Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"sQS6j8h7Gj.exe") },
        { xorstr_("Inferno Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"sQS6j8h7Gj.exe") },
        { xorstr_("Meta Config File Created On Disk:"), xorstr_("File Created"), xorstr_(L"Meta Fortnite.txt") },
        { xorstr_("Meta Config File Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Meta Fortnite.txt") },
        { xorstr_("zCheats Created On Disk:"), xorstr_("File Created"), xorstr_(L"zCheats.exe") },
        { xorstr_("zCheats Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"zCheats.exe") },
        { xorstr_("Oracle Cleaner Created On Disk:"), xorstr_("File Created"), xorstr_(L"Cleanup.bat") },
        { xorstr_("Oracle Cleaner Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Cleanup.bat") },
        { xorstr_("Oracle Config File Created On Disk:"), xorstr_("File Created"), xorstr_(L"OracleFN.txt") },
        { xorstr_("Oracle Config File Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"OracleFN.txt") },
        { xorstr_("Arcane Config File Deleted Off Disk:"), xorstr_("File Created"), xorstr_(L"FN_Arcane.txt") },
        { xorstr_("Arcane Config File Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"FN_Arcane.txt") },
        { xorstr_("Arcane Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"08TiCPX.com") },
        { xorstr_("Arcane Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"08TiCPX.com") },
        { xorstr_("Zed Config File Created On Disk:"), xorstr_("File Created"), xorstr_(L"Zed.txt") },
        { xorstr_("Zed Config Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Zed.txt") },
        { xorstr_("Zed Folder Created On Disk:"), xorstr_("File Created"), xorstr_(L"Zed.zip") },
        { xorstr_("Zed Folder Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Zed.zip") },
        { xorstr_("Zed Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Zed.exe") },
        { xorstr_("Zed Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Zed.exe") },
        { xorstr_("Omega Config File Created On Disk:"), xorstr_("File Created"), xorstr_(L"Omega (1).txt") },
        { xorstr_("Omega Config File Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Omega (1).txt") },
        { xorstr_("Omega Folder Created On Disk:"), xorstr_("File Created"), xorstr_(L"omegaFN0822a.zip") },
        { xorstr_("Omega Folder Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"omegaFN0822a.zip") },
        { xorstr_("Omega Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"omegaFN.exe") },
        { xorstr_("Omega Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"omegaFN.exe") },
        { xorstr_("KingzCheats Created On Disk:"), xorstr_("File Created"), xorstr_(L"KingzCheats.exe") },
        { xorstr_("KingzCheats Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"KingzCheats.exe") },
        { xorstr_("KingzCheats Folder Created On Disk:"), xorstr_("File Created"), xorstr_(L"KingzCheatsV1") },
        { xorstr_("KingzCheats Folder Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"KingzCheatsV1") },
        { xorstr_("Solaris EFI Folder Created On Disk:"), xorstr_("File Created"), xorstr_(L"EFI_4c7cf4521c1a61f1d.zip") },
        { xorstr_("Solaris EFI Folder Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"EFI_4c7cf4521c1a61f1d.zip") },
        { xorstr_("Solaris EFI Folder Created On Disk:"), xorstr_("File Created"), xorstr_(L"ventro-1387057f-6f7a-4fa1-afe2-f21f3e145e7d.zip") },
        { xorstr_("Solaris EFI Folder Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"ventro-1387057f-6f7a-4fa1-afe2-f21f3e145e7d.zip") },
        { xorstr_("Arcane Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"AYqa2nQFegK.com") },
        { xorstr_("Arcane Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"AYqa2nQFegK.com") },

#elif DETECT_FREEFIRE

        { xorstr_("xisfpd Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"bb3a785178f443fda931098a5a9a306b.exe") },
        { xorstr_("xisfpd Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"bb3a785178f443fda931098a5a9a306b.exe") },
        { xorstr_("Zimo Private Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"dat.pdf") },
        { xorstr_("Zimo Private Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"dat.pdf") },
        { xorstr_("XRC Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"tsf2gipcompiles.dll") },
        { xorstr_("XRC Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"tsf2gipcompiles.dll") },
        { xorstr_("Zimo Free Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Zimo Free") },
        { xorstr_("Zimo Free Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Zimo Free.exe") },
        { xorstr_("Playboy Basic Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"Launcher-Basic.exe") },
        { xorstr_("Playboy Basic Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"Launcher-Basic.exe") },
        { xorstr_("Playboy Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"playboy.exe") },
        { xorstr_("Playboy Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"playboy.exe") },

#elif DETECT_DAYZ
            //deleted

        { xorstr_("Nvidia Profile Inspector Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"nvidiaProfileInspector.zip") },
        { xorstr_("Nvidia Profile Inspector Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"nvidiaProfileInspector.exe") },
        { xorstr_("Nvidia Profile Inspector Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"nvidiaProfileInspector.exe") },
        { xorstr_("Lag Switch Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"LagSwitch - Main.exe") },
        { xorstr_("Lag Switch Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"LagSwitch - Main.py") },
        { xorstr_("Stugware Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"activation_key.txt") },
        { xorstr_("Authority Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"LOADER.com") },
        { xorstr_("Covcheg Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"SearchHoverUnifiedTileModelCache.dat_pw_infected.zip") },
        { xorstr_("BTG Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"BtgDx11.exe") },

            //created

        { xorstr_("Nvidia Profile Inspector Created On Disk:"), xorstr_("File Created"), xorstr_(L"nvidiaProfileInspector.zip") },
        { xorstr_("Nvidia Profile Inspector Created On Disk:"), xorstr_("File Created"), xorstr_(L"nvidiaProfileInspector.exe") },
        { xorstr_("Lag Switch Created On Disk:"), xorstr_("File Created"), xorstr_(L"LagSwitch - Main.exe") },
        { xorstr_("Lag Switch Created On Disk:"), xorstr_("File Created"), xorstr_(L"LagSwitch - Main.py") }, 
        { xorstr_("Stugware Created On Disk:"), xorstr_("File Created"), xorstr_(L"activation_key.txt") },
        { xorstr_("Authority Created On Disk:"), xorstr_("File Deleted"), xorstr_(L"LOADER.com") },
        { xorstr_("Covcheg Created On Disk:"), xorstr_("File Created"), xorstr_(L"SearchHoverUnifiedTileModelCache.dat_pw_infected.zip") },
        { xorstr_("BTG Created On Disk:"), xorstr_("File Created"), xorstr_(L"BtgDx11.exe") },

            //other

        { xorstr_("Authority Renamed On Disk:"), xorstr_("File Renamed Old Name"), xorstr_(L"LOADER.com") },

#elif DETECT_COD

        { xorstr_("RegOBJ Cheat Created On Disk:"), xorstr_("File Created"), xorstr_(L"regobj.exe") },
        { xorstr_("AHK Hider Created On Disk:"), xorstr_("File Created"), xorstr_(L"hyde64.dll") },

        { xorstr_("RegOBJ Cheat Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"regobj.exe") },
        { xorstr_("AHK Hider Deleted Off Disk:"), xorstr_("File Deleted"), xorstr_(L"hyde64.dll") },

#elif DETECT_CS

        // Counter-Strike cheat filenames go here.

#endif

#ifndef DETECT_FORTNITE

        { xorstr_("PowerShell History Modified:"), xorstr_("File Changed"), xorstr_(L"ConsoleHost_history.txt")},
        { xorstr_("PowerShell History Cleaned:"), xorstr_("File Deleted"), xorstr_(L"ConsoleHost_history.txt")},
        { xorstr_("PowerShell History Modified:"), xorstr_("File Renamed Old Name"), xorstr_(L"ConsoleHost_history.txt")},
        { xorstr_("PowerShell History Modified:"), xorstr_("Data Truncation"), xorstr_(L"ConsoleHost_history.txt")},
        { xorstr_("PowerShell History Modified:"), xorstr_("Data Overwrite"), xorstr_(L"ConsoleHost_history.txt")},

        { xorstr_("PowerShell History Modified:"), xorstr_("File Changed"), xorstr_(L"Windows PowerShell ISE Host_history.txt") },
        { xorstr_("PowerShell History Cleaned:"), xorstr_("File Deleted"), xorstr_(L"Windows PowerShell ISE Host_history.txt") },
        { xorstr_("PowerShell History Cleaned:"), xorstr_("File Deleted"), xorstr_(L"Windows PowerShell.evtx") },
        { xorstr_("PowerShell History Modified:"), xorstr_("File Renamed Old Name"), xorstr_(L"Windows PowerShell ISE Host_history.txt") },
        { xorstr_("PowerShell History Modified:"), xorstr_("Data Truncation"), xorstr_(L"Windows PowerShell ISE Host_history.txt") },
        { xorstr_("PowerShell History Modified:"), xorstr_("Data Overwrite"), xorstr_(L"Windows PowerShell ISE Host_history.txt") },

        { xorstr_("PowerShell Profile Modified:"), xorstr_("Data Overwrite"), xorstr_(L"Microsoft.PowerShell_profile.ps1") },
        { xorstr_("PowerShell Profile Modified:"), xorstr_("Data Truncation"), xorstr_(L"Microsoft.PowerShell_profile.ps1") },
        { xorstr_("PowerShell Profile Modified:"), xorstr_("File Changed"), xorstr_(L"Microsoft.PowerShell_profile.ps1") },
        { xorstr_("PowerShell Profile Cleaned:"), xorstr_("File Deleted"), xorstr_(L"Microsoft.PowerShell_profile.ps1") },
        { xorstr_("PowerShell Profile Created:"), xorstr_("File Created"), xorstr_(L"Microsoft.PowerShell_profile.ps1") },
        { xorstr_("PowerShell Profile Modified:"), xorstr_("File Renamed Old Name"), xorstr_(L"Microsoft.PowerShell_profile.ps1") },


        { xorstr_("PowerShell Profile Cleaned:"), xorstr_("File Deleted"), xorstr_(L"profile.ps1") },
        { xorstr_("PowerShell Profile Renamed:"), xorstr_("File Renamed Old Name"), xorstr_(L"profile.ps1") },

        { xorstr_("Anydesk Transfer File Renamed:"), xorstr_("File Changed"), xorstr_(L"file_transfer_trace.txt") },
        { xorstr_("Anydesk Transfer File Cleaned:"), xorstr_("File Deleted"), xorstr_(L"file_transfer_trace.txt") },

        { xorstr_("ImGUI (GUI Composer) File Launched:"), xorstr_("File Created"), xorstr_(L"imgui.ini") },
        { xorstr_("ImGUI (GUI Composer) File Cleaned:"), xorstr_("File Deleted"), xorstr_(L"imgui.ini") },

        { xorstr_("Crashdump File Deleted:"), xorstr_("File Deleted"), xorstr_(L"AppData\\Local\\CrashDumps") },

#endif

            //kd mapper detections

        { xorstr_("Kdmapper Created On Disk:"), xorstr_("File Created"), xorstr_(L"kdmapper-master.zip") },
        { xorstr_("Kdmapper Created On Disk:"), xorstr_("File Created"), xorstr_(L"kdmapper") },
        { xorstr_("Kdmapper Created On Disk:"), xorstr_("File Created"), xorstr_(L"kdmapper_Release") },


            //generic cheat names

        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"aimbot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"aim bot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"aim_bot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"autoclick") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"aim assist") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"aim_assist") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"autoaim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"auto aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"auto_aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"legitbot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"legit bot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"legit_bot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rageaim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rage aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rage_aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"silentaim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"silent aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"silent_aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"smoothaim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"smooth aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"smooth_aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"softaim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"soft aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"soft_aim") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"infiniteammo") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"infinite ammo") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"infinite_ammo") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"noclip") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"no clip") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"no_clip") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"norecoil") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"no recoil") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"no_recoil") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"nospread") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"no spread") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"no_spread") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"recoilcontrol") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"recoil control") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"recoil_control") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"speedhack") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"speed hack") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"speed_hack") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"triggerbot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"trigger bot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"trigger_bot") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"unlockall") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"unlock all") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"unlock_all") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"wallhack") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"wall hack") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"wall_hack") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"hwidspoofer") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"hwid spoofer") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"hwid_spoofer") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"serialchanger") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"serial changer") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"serial_changer") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"macroloader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"macro loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"macro_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"scriptloader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"script loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"script_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_hack_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb cheat loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_cheat_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb hack loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_hack_loader") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb cheat launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_cheat_launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb hack launcher") },
        { xorstr_("Generic Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_hack_launcher") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fn-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fortnite-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rb-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"roblox-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6 internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"r6-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"siege-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"rust-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"mc-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"minecraft-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fivem-internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm-external") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm_internal") },
        { xorstr_("Game Cheat File Deleted:"), xorstr_("File Deleted"), xorstr_(L"fm-internal") }

};

std::unordered_map<ULONGLONG, std::wstring> usn_scan::file_reference_cache;
std::mutex usn_scan::file_reference_cache_mtx;

std::string usn_scan::convert_wstring_to_string(const std::wstring& wstr) {
    try {
        if (wstr.empty()) return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
            static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
        if (sz <= 0) return {};
        std::string out(sz, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.data(),
            static_cast<int>(wstr.size()), out.data(), sz, nullptr, nullptr);
        return out;
    }
    catch (...) { return ""; }
}

std::string usn_scan::parse_reason(DWORD reason) {
    try {
        std::ostringstream os;
        if (reason & USN_REASON_DATA_OVERWRITE)       os << xorstr_("Data Overwrite, ");
        if (reason & USN_REASON_DATA_EXTEND)          os << xorstr_("Data Extend, ");
        if (reason & USN_REASON_DATA_TRUNCATION)      os << xorstr_("Data Truncation, ");
        if (reason & USN_REASON_FILE_CREATE)          os << xorstr_("File Created, ");
        if (reason & USN_REASON_FILE_DELETE)          os << xorstr_("File Deleted, ");
        if (reason & USN_REASON_RENAME_OLD_NAME)      os << xorstr_("File Renamed Old Name, ");
        if (reason & USN_REASON_RENAME_NEW_NAME)      os << xorstr_("File Renamed New Name, ");
        if (reason & USN_REASON_CLOSE)                os << xorstr_("File Closed, ");
        if (reason & USN_REASON_BASIC_INFO_CHANGE)    os << xorstr_("File Changed, ");
        if (reason & USN_REASON_REPARSE_POINT_CHANGE) os << xorstr_("Junction Change, ");
        std::string s = os.str();
        if (s.size() >= 2) { s.pop_back(); s.pop_back(); }
        return s;
    }
    catch (...) { return ""; }
}

std::wstring usn_scan::resolve_parent_directory(HANDLE volume_handle, ULONGLONG file_reference) {
    try {
        {
            std::lock_guard<std::mutex> lk(file_reference_cache_mtx);
            auto cache_it = file_reference_cache.find(file_reference);
            if (cache_it != file_reference_cache.end())
                return cache_it->second;
        }

        FILE_ID_DESCRIPTOR fid = {};
        fid.dwSize = sizeof(FILE_ID_DESCRIPTOR);
        fid.Type = FileIdType;
        fid.FileId.QuadPart = static_cast<LONGLONG>(file_reference);

        HANDLE fh = OpenFileById(volume_handle, &fid, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, 0);
        if (fh == INVALID_HANDLE_VALUE) {
            std::lock_guard<std::mutex> lk(file_reference_cache_mtx);
            file_reference_cache[file_reference] = std::wstring{};
            return L"";
        }

        WCHAR buf[MAX_PATH];
        DWORD r = GetFinalPathNameByHandleW(fh, buf, MAX_PATH, FILE_NAME_NORMALIZED);
        CloseHandle(fh);
        if (r == 0) {
            std::lock_guard<std::mutex> lk(file_reference_cache_mtx);
            file_reference_cache[file_reference] = std::wstring{};
            return L"";
        }

        std::wstring path(buf, r);
        if (path.size() >= 4 &&
            path[0] == L'\\' && path[1] == L'\\' &&
            path[2] == L'?' && path[3] == L'\\')
            path.erase(0, 4);

        if (!path.empty() && path.back() != L'\\')
            path += L'\\';

        std::lock_guard<std::mutex> lk(file_reference_cache_mtx);
        file_reference_cache[file_reference] = path;
        return path;
    }
    catch (...) { return L""; }
}

std::string usn_scan::convert_file_time_to_string(const LARGE_INTEGER& file_time) {
    try {
        FILETIME ft{ static_cast<DWORD>(file_time.LowPart),
                      static_cast<DWORD>(file_time.HighPart) };
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&ft, &stUTC);
        SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal);
        char buf[32];
        std::snprintf(buf, sizeof(buf), xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            stLocal.wYear, stLocal.wMonth, stLocal.wDay,
            stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        return buf;
    }
    catch (...) { return ""; }
}

bool usn_scan::ends_with_icase(const std::wstring& str, const std::wstring& suffix) {
    if (suffix.size() > str.size()) return false;
    for (size_t i = 0; i < suffix.size(); ++i) {
        if (std::towlower(str[str.size() - suffix.size() + i]) != std::towlower(suffix[i]))
            return false;
    }
    return true;
}

std::wstring usn_scan::get_user_temp_prefix() {
    try {
        wchar_t username[UNLEN + 1] = {};
        DWORD size = UNLEN + 1;
        if (!GetUserNameW(username, &size))
            return {};
        std::wstring prefix = xorstr_(L"C:\\Users\\");
        prefix += username;
        prefix += xorstr_(L"\\AppData\\Local\\Temp\\");
        for (auto& c : prefix) c = std::towlower(c);
        return prefix;
    } catch (...) {
        return {};
    }
}

static void build_reason_index(
    const std::vector<usn_scan::custom_check>& checks,
    std::unordered_map<std::string, std::vector<size_t>>& out)
{
    try {
        for (size_t i = 0; i < checks.size(); ++i)
            out[checks[i].reason].push_back(i);
    }
    catch (...) {}
}

void usn_scan::read_usn_journal(const std::string& drive_letter) {
    try {
        static std::unordered_map<std::string, std::vector<size_t>> reason_index;
        static std::once_flag index_flag;
        static std::wstring tpm_temp_prefix;

        std::call_once(index_flag, [] {
            try {
                build_reason_index(custom_checks, reason_index);
                tpm_temp_prefix = get_user_temp_prefix();
                file_reference_cache.reserve(1 << 16);
            }
            catch (...) {}
            });

        std::string volume_path = xorstr_("\\\\.\\") + drive_letter;
        HANDLE vh = CreateFileA(volume_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (vh == INVALID_HANDLE_VALUE) return;

        USN_JOURNAL_DATA jd{};
        DWORD br = 0;
        if (!DeviceIoControl(vh, FSCTL_QUERY_USN_JOURNAL,
            nullptr, 0, &jd, sizeof(jd), &br, nullptr)) {
            LOG(WARNING, xorstr_("N/A")) << xorstr_("USN Journal Not Present On Drive:") << drive_letter;
            CloseHandle(vh);
            return;
        }

        READ_USN_JOURNAL_DATA_V0 rd{};
        rd.StartUsn = jd.FirstUsn;
        rd.ReasonMask = 0xFFFFFFFF;
        rd.UsnJournalID = jd.UsnJournalID;

        std::vector<BYTE> buffer(65536);

        while (true) {
            DWORD bytes_read = 0;
            if (!DeviceIoControl(vh, FSCTL_READ_USN_JOURNAL,
                &rd, sizeof(rd),
                buffer.data(), static_cast<DWORD>(buffer.size()),
                &bytes_read, nullptr)) {
                break;
            }

            if (bytes_read <= sizeof(USN)) break;

            const BYTE* ptr = buffer.data() + sizeof(USN);
            const BYTE* end = buffer.data() + bytes_read;

            while (ptr < end) {
                const USN_RECORD* rec = reinterpret_cast<const USN_RECORD*>(ptr);
                if (rec->RecordLength == 0) break;

                const DWORD rmask = rec->Reason;
                bool maybe_match = false;

                std::string reason_str;
                auto get_reason = [&]() -> const std::string& {
                    if (reason_str.empty()) reason_str = parse_reason(rmask);
                    return reason_str;
                    };

                for (auto& [reason_key, indices] : reason_index) {
                    if (get_reason().find(reason_key) == std::string::npos) continue;

                    const int fn_len = rec->FileNameLength / sizeof(WCHAR);
                    std::wstring file_name(rec->FileName, fn_len);

                    for (auto& ch : file_name)
                        if (ch < 32 || ch > 126) ch = L'?';

                    if (ends_with_icase(file_name, xorstr_(L".lnk"))) continue;

                    for (size_t idx : indices) {
                        const auto& chk = custom_checks[idx];
                        if (file_name.find(chk.substring) == std::wstring::npos) continue;

                        std::wstring parent = resolve_parent_directory(
                            vh, rec->ParentFileReferenceNumber);

                        LOG(WARNING, convert_file_time_to_string(rec->TimeStamp))
                            << chk.description
                            << convert_wstring_to_string(parent)
                            << convert_wstring_to_string(file_name);
                    }
                }

                if (!tpm_temp_prefix.empty() && (rmask & USN_REASON_RENAME_NEW_NAME)) {
                    const int tpm_fn_len = rec->FileNameLength / sizeof(WCHAR);
                    std::wstring tpm_file_name(rec->FileName, tpm_fn_len);

                    if (ends_with_icase(tpm_file_name, xorstr_(L".tpm"))) {
                        std::wstring parent = resolve_parent_directory(
                            vh, rec->ParentFileReferenceNumber);

                        std::wstring parent_lower = parent;
                        for (auto& c : parent_lower) c = std::towlower(c);

                        if (parent_lower.find(tpm_temp_prefix) != std::wstring::npos) {
                            LOG(DETECTION, convert_file_time_to_string(rec->TimeStamp))
                                << xorstr_("FLK Bypass Detected:")
                                << convert_wstring_to_string(parent)
                                << convert_wstring_to_string(tpm_file_name);
                        }
                    }
                }

                ptr += rec->RecordLength;
            }

            rd.StartUsn = *reinterpret_cast<const USN*>(buffer.data());
        }

        CloseHandle(vh);
    }
    catch (...) {}
}

void usn_scan::start_usn_scan() {
    try {
        DWORD drives = GetLogicalDrives();
        if (!drives) return;

        std::vector<std::thread> threads;
        threads.reserve(26);

        for (char d = 'A'; d <= 'Z'; ++d) {
            if (drives & (1u << (d - 'A'))) {
                std::string dl = std::string(1, d) + xorstr_(":");
                threads.emplace_back([dl] { usn_scan::read_usn_journal(dl); });
            }
        }

        for (auto& t : threads) t.join();
    }
    catch (...) {}
}