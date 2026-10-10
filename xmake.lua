

set_project("detect")
set_version("3.0.5.0")
set_xmakever("2.8.0")

option("ccache")
    set_default(false)
    set_showmenu(true)
    set_description("Enable xmake's local build cache (faster repeat builds).")
option_end()

if has_config("ccache") then
    set_policy("build.ccache", true)
end

set_allowedplats("windows")
set_allowedarchs("x64")
set_defaultplat("windows")
set_defaultarchs("x64")

set_languages("c++20", "c17")

add_rules("mode.debug", "mode.release")

option("game")

    set_default("")
    set_showmenu(true)
    set_description("Target game variant (REQUIRED)",
        "  minecraft, siege, gmod, fivem, freefire,",
        "  roblox, fortnite, cod, rust, dayz, cs")
    set_values("minecraft", "siege", "gmod", "fivem", "freefire",
               "roblox", "fortnite", "cod", "rust", "dayz", "cs")
option_end()

local game_defines = {
    minecraft = "DETECT_MINECRAFT",
    siege     = "DETECT_SIEGE",
    gmod      = "DETECT_GMOD",
    fivem     = "DETECT_FIVEM",
    freefire  = "DETECT_FREEFIRE",
    roblox    = "DETECT_ROBLOX",
    fortnite  = "DETECT_FORTNITE",
    cod       = "DETECT_COD",
    rust      = "DETECT_RUST",
    dayz      = "DETECT_DAYZ",
    cs        = "DETECT_CS",
}

local ext_include = path.join(os.scriptdir(), "ext", "include")
local ext_lib     = path.join(os.scriptdir(), "ext", "lib")

target("sqlite3")
    set_kind("static")
    set_group("vendor")
    add_files("detect/detections/browser_detections/sqlite/sqlite3.c",
              "detect/detections/browser_detections/sqlite/shell.c")
    add_includedirs("detect/detections/browser_detections/sqlite",
                    {public = true})
    add_defines("_CRT_SECURE_NO_WARNINGS", "_LIB")
    add_cflags("/utf-8", "/MP", "/Zc:inline", {force = true})
    add_vectorexts("sse2")
    set_warnings("less")
    if is_mode("debug") then
        set_runtimes("MTd")
    else
        set_runtimes("MT")
    end
target_end()

target("detect")
    set_kind("binary")

    set_basename("detect")

    set_symbols("debug")

    if is_plat("windows") then
        add_ldflags("/SUBSYSTEM:WINDOWS", {force = true})
    end

    add_files("detect/main.cpp")

    add_files("detect/detections/**.cpp|" ..
              "client_checks/yara_scanner/c_yara_scanner.cpp|" ..
              "client_checks/yara_scanner/rule_delivery.cpp")

    add_files("detect/UI/**.cpp")
    add_files("detect/utils/detection/utils.cpp")
    add_files("detect/utils/protection/**.cpp")

    add_files("detect/detect.rc")

    add_files("detect/detections/client_checks/yara_scanner/c_yara_scanner.cpp",
              {cxflags = "/Y-"})
    add_files("detect/detections/client_checks/yara_scanner/rule_delivery.cpp",
              {cxflags = "/Y-"})
    add_files("detect/scan_api/scanapi.cpp",          {cxflags = "/Y-"})
    add_files("detect/scan_api/telemetry_v2.cpp",     {cxflags = "/Y-"})
    add_files("detect/utils/thread_pool/thread_pool.cpp", {cxflags = "/Y-"})


    set_pcxxheader("detect/pch.h")

    add_includedirs("detect")            
    add_includedirs(ext_include)         
    add_includedirs(ext_include .. "/stb")  

    add_deps("sqlite3")

    add_defines(
        "YARA_STATIC",
        "CURL_STATICLIB",
        "JM_XORSTR_DISABLE_AVX_INTRINSICS",
        "_CRT_SECURE_NO_WARNINGS",
        "_SILENCE_EXPERIMENTAL_FILESYSTEM_DEPRECATION_WARNING",
        "_SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING",
        "_CONSOLE"
    )

    on_load(function (target)
        local selected = get_config("game")
        if not selected or selected == ""
           or not game_defines[selected] then
            os.raise("--game=<name> is required.\n" ..
                     "  Available: minecraft, siege, gmod, fivem, freefire,\n" ..
                     "             roblox, fortnite, cod, rust, dayz, cs\n" ..
                     "  Example:   xmake config -m release --game=fivem")
        end
        target:add("defines", game_defines[selected])

        target:set("basename", "detect-" .. selected)
    end)

    add_cxflags(
        "/utf-8",           
        "/MP",              
        "/EHsc",            
        "/Zc:inline",       
        "/wd4005",          
        {force = true}
    )
    add_vectorexts("sse2")
    set_warnings("less")    

    if is_mode("release") then
        set_optimize("fastest")
        add_cxflags("/fp:fast", "/Gy", "/Oi", {force = true})
    else

        set_policy("build.optimization.lto", false)
        add_ldflags("/INCREMENTAL", {force = true})
    end

    if is_mode("debug") then
        set_runtimes("MTd")
    else
        set_runtimes("MT")
    end

    add_linkdirs(ext_lib)

    add_ldflags(
        "/FORCE:MULTIPLE",
        "/IGNORE:4006",
        "/IGNORE:4088",
        "/IGNORE:4099",     
        {force = true}
    )

    if is_mode("release") then
        add_ldflags("/OPT:REF", "/OPT:ICF", "/LTCG:incremental",
                    {force = true})
    end

    if is_mode("debug") then
        add_links("fmtd", "libcurl_a_debug")
    else
        add_links("fmt",  "libcurl_a")
    end

    add_links("libyara64", "libssl_static", "libcrypto_static",

              "WebView2LoaderStatic")

    add_syslinks(
        "ucrt",
        "User32", "Kernel32", "Shell32", "Ole32", "OleAut32", "Advapi32",
        "Shlwapi", "Setupapi", "DbgHelp", "Wbemuuid", "Normaliz",
        "Ws2_32", "Wldap32", "Crypt32", "Secur32", "Wintrust", "Wtsapi32",
        "WinHttp", "Dxva2", "ntdll", "Version", "esent", "comsupp",
        "comsuppw", "taskschd", "wevtapi", "d3d11", "cfgmgr32",
        
        "bcrypt", "userenv", "dwmapi", "gdi32", "ncrypt", "wintrust", "crypt32"
    )

    add_ldflags("/MANIFEST:NO", {force = true})
target_end()
