#include "c_java_injection.h"

namespace
{
    constexpr SIZE_T   kScanBufferSize   = 64 * 1024;
    constexpr SIZE_T   kMaxRegionSize    = 96ull  * 1024 * 1024;
    constexpr SIZE_T   kMaxBytesPerProc  = 768ull * 1024 * 1024;
    constexpr size_t   kMinStringLength  = 6;

    const std::vector<std::string>& weave_markers()
    {
        static const std::vector<std::string> markers = {
            xorstr_("\\.weave\\"),
            xorstr_("/.weave/"),
            xorstr_("weave-loader"),
            xorstr_("net/weavemc"),
            xorstr_("net.weavemc"),
            xorstr_("weavemc")
        };
        return markers;
    }

    std::string lower_ascii(const std::string& s)
    {
        std::string out = s;
        for (char& c : out) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }
        return out;
    }
}

bool JavaInjectionScanner::enable_debug_privilege()
{
    try {
        HANDLE h_token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) return false;

        LUID luid{};
        if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) { CloseHandle(h_token); return false; }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        const BOOL ok = AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        const bool assigned = ok && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
        CloseHandle(h_token);
        return assigned;
    } catch (...) {}
    return false;
}

void JavaInjectionScanner::scan_weave_artifacts()
{
    try {
        const std::string profile = c_utils::get_known_folder_path(FOLDERID_Profile);
        if (profile.empty()) return;

        std::filesystem::path users_root = std::filesystem::path(profile).parent_path();
        if (users_root.empty()) return;

        std::error_code ec;
        if (!std::filesystem::exists(users_root, ec)) return;

        for (const auto& user_entry : std::filesystem::directory_iterator(users_root, std::filesystem::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            if (!user_entry.is_directory(ec)) continue;

            const std::filesystem::path weave_dir = user_entry.path() / std::string(xorstr_(".weave"));
            if (!std::filesystem::exists(weave_dir, ec)) continue;

            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Weave Cheat Loader Folder Found. Weave loads cheat jars into Minecraft while the game is running: ")
                << c_utils::path_to_utf8(weave_dir);

            const std::filesystem::path mods_dir = weave_dir / std::string(xorstr_("mods"));
            if (!std::filesystem::exists(mods_dir, ec)) continue;

            for (const auto& mod_entry : std::filesystem::directory_iterator(mods_dir, std::filesystem::directory_options::skip_permission_denied, ec)) {
                if (ec) break;
                if (!mod_entry.is_regular_file(ec)) continue;

                LOG(WARNING, xorstr_("N/A"))
                    << xorstr_("Jar File Found In The Weave Cheat Loader Folder:")
                    << c_utils::path_to_utf8(mod_entry.path());
            }
        }
    } catch (...) {}
}

void JavaInjectionScanner::scan_loader_processes()
{
    try {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &pe)) {
            do {
                const std::string exe  = JvmArgScanner::wideToNarrow(pe.szExeFile);
                const std::string name = lower_ascii(exe);
                if (name.find(xorstr_("weave")) == std::string::npos) continue;

                LOG(DETECTION, xorstr_("N/A"))
                    << xorstr_("Weave Cheat Loader Is Running In Instance: It loads cheats into Minecraft automatically when the game starts | ")
                    << exe;
            } while (Process32NextW(snapshot, &pe));
        }

        CloseHandle(snapshot);
    } catch (...) {}
}

void JavaInjectionScanner::scan_attach_pipes()
{
    try {
        WIN32_FIND_DATAA find_data{};
        HANDLE h_find = FindFirstFileA(xorstr_("\\\\.\\pipe\\*"), &find_data);
        if (h_find == INVALID_HANDLE_VALUE) return;

        do {
            const std::string name = lower_ascii(find_data.cFileName);
            if (name.rfind(xorstr_("javatool"), 0) != 0) continue;

            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Live JVM Attach Channel Open In Instance (\\\\.\\pipe\\") << find_data.cFileName
                << xorstr_("):Windows only creates this while a program is loading extra code into a running Java program.");
        } while (FindNextFileA(h_find, &find_data));

        FindClose(h_find);
    } catch (...) {}
}

JavaInjectionScanner::module_findings JavaInjectionScanner::scan_process_modules(HANDLE h_process, const jvm_process_info& proc)
{
    module_findings findings;

    try {
        std::vector<HMODULE> modules(2048);
        DWORD needed = 0;

        if (!EnumProcessModulesEx(h_process, modules.data(),
                static_cast<DWORD>(modules.size() * sizeof(HMODULE)), &needed, LIST_MODULES_ALL)) {
            return findings;
        }

        const size_t count = (std::min)(modules.size(), static_cast<size_t>(needed / sizeof(HMODULE)));

        for (size_t i = 0; i < count; ++i) {
            char module_path[MAX_PATH]{};
            if (!GetModuleFileNameExA(h_process, modules[i], module_path, MAX_PATH)) continue;

            const std::string lower = lower_ascii(module_path);

            if (lower.find(xorstr_("\\instrument.dll")) != std::string::npos) findings.instrument_loaded = true;
            if (lower.find(xorstr_("\\attach.dll"))     != std::string::npos) findings.attach_loaded = true;
            if (lower.find(xorstr_("\\jdwp.dll"))       != std::string::npos) findings.jdwp_loaded = true;
        }

        if (findings.jdwp_loaded) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Remote Debugging Is Active Inside Minecraft. This lets another program run its own code inside the running game.");
        }

        if (findings.attach_loaded) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Injection Tool Loaded Inside Minecraft. This file (attach.dll) is only loaded when something is injecting code into a running Java program.");
        }
    } catch (...) {}

    return findings;
}

bool JavaInjectionScanner::scan_process_threads(const jvm_process_info& proc)
{
    try {
        typedef HRESULT (WINAPI * fn_get_thread_description)(HANDLE, PWSTR*);

        static fn_get_thread_description get_description = [] () -> fn_get_thread_description {
            HMODULE h = GetModuleHandleA(xorstr_("kernelbase.dll"));
            if (!h) h = GetModuleHandleA(xorstr_("kernel32.dll"));
            if (!h) return nullptr;
            return reinterpret_cast<fn_get_thread_description>(
                GetProcAddress(h, xorstr_("GetThreadDescription")));
        }();

        if (!get_description) return false;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        THREADENTRY32 te{};
        te.dwSize = sizeof(THREADENTRY32);
        bool found = false;

        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID != proc.pid) continue;

                HANDLE h_thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (!h_thread) continue;

                PWSTR description = nullptr;
                if (SUCCEEDED(get_description(h_thread, &description)) && description) {
                    const std::string name = lower_ascii(JvmArgScanner::wideToNarrow(description));
                    if (name.find(xorstr_("attach listener")) != std::string::npos) found = true;
                    LocalFree(description);
                }

                CloseHandle(h_thread);
            } while (Thread32Next(snapshot, &te) && !found);
        }

        CloseHandle(snapshot);
        return found;
    } catch (...) {}
    return false;
}

JavaInjectionScanner::memory_findings JavaInjectionScanner::scan_process_markers(HANDLE h_process)
{
    memory_findings findings;

    try {
        std::vector<unsigned char> buffer(kScanBufferSize);

        SIZE_T scanned_total = 0;
        MEMORY_BASIC_INFORMATION mbi{};

        std::string ascii_run;
        std::string utf16_run;
        ascii_run.reserve(2048);
        utf16_run.reserve(2048);

        auto test_run = [&](const std::string& run) {
            if (run.size() < kMinStringLength) return;
            const std::string lower = lower_ascii(run);

            for (const std::string& marker : weave_markers()) {
                if (lower.find(marker) != std::string::npos) {
                    findings.weave_marker = true;
                    return;
                }
            }
        };

        for (PBYTE address = nullptr;
             VirtualQueryEx(h_process, address, &mbi, sizeof(mbi)) == sizeof(mbi);
             address = static_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize)
        {
            if (mbi.RegionSize == 0) break;
            if (scanned_total >= kMaxBytesPerProc) break;
            if (findings.weave_marker) break;

            if (mbi.State != MEM_COMMIT) continue;
            if (mbi.Type  != MEM_PRIVATE) continue;
            if (mbi.RegionSize > kMaxRegionSize) continue;
            if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
            if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) continue;

            for (PBYTE chunk = static_cast<PBYTE>(mbi.BaseAddress);
                 chunk < static_cast<PBYTE>(mbi.BaseAddress) + mbi.RegionSize;
                 chunk += kScanBufferSize)
            {
                SIZE_T bytes_read = 0;
                if (!ReadProcessMemory(h_process, chunk, buffer.data(), kScanBufferSize, &bytes_read)) continue;
                scanned_total += bytes_read;

                ascii_run.clear();
                for (SIZE_T i = 0; i < bytes_read; ++i) {
                    const unsigned char c = buffer[i];
                    if (c >= 0x20 && c <= 0x7E) {
                        ascii_run.push_back(static_cast<char>(c));
                    } else {
                        test_run(ascii_run);
                        ascii_run.clear();
                    }
                }
                test_run(ascii_run);

                utf16_run.clear();
                for (SIZE_T i = 0; i + 1 < bytes_read; i += 2) {
                    const unsigned char lo = buffer[i];
                    const unsigned char hi = buffer[i + 1];
                    if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
                        utf16_run.push_back(static_cast<char>(lo));
                    } else {
                        test_run(utf16_run);
                        utf16_run.clear();
                    }
                }
                test_run(utf16_run);
            }
        }

    } catch (...) {}

    return findings;
}

void JavaInjectionScanner::inspect_jvm_process(const jvm_process_info& proc)
{
    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.pid);
    if (!h_process) return;

    try {
        const module_findings modules = scan_process_modules(h_process, proc);
        const memory_findings memory  = scan_process_markers(h_process);
        const bool attach_listener    = scan_process_threads(proc);

        if (memory.weave_marker) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Weave Cheat Loader Is Active Inside Minecraft. Weave traces were found in the running game's memory.");
        }

        const bool launch_agent =
            JvmArgScanner::has_launch_time_agent(proc.command_line) ||
            JvmArgScanner::environment_agent_present();

        if (launch_agent) return;

        if (attach_listener) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Something Injected Into Minecraft While The Game Was Running. Nothing extra was added when the game started, but Java shows that a program attached to it after it opened.");
            return;
        }

        if (modules.instrument_loaded) {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Extra Code Was Loaded Into Minecraft After The Game Started. Nothing extra was added when the game started, so it was injected while the game was already open.");
            return;
        }
    } catch (...) {}

    CloseHandle(h_process);
}

void JavaInjectionScanner::start_java_injection_scan()
{
    try {
        scan_weave_artifacts();
        scan_loader_processes();
        scan_attach_pipes();

        enable_debug_privilege();

        for (const jvm_process_info& proc : JvmArgScanner::collect_jvm_processes()) {
            const std::string name = lower_ascii(proc.name);
            if (name != xorstr_("javaw.exe") && name != xorstr_("java.exe")) continue;

            inspect_jvm_process(proc);
        }
    } catch (...) {
        return;
    }
}
