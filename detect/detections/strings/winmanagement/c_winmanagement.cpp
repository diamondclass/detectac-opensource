#include "c_winmanagement.h"

#define MIN_STRING_LENGTH 4

static std::vector<std::pair<std::string, std::string>> get_custom_filters()
{
    try{
    static std::vector<std::pair<std::string, std::string>> filters;
    static bool initialized = false;

    if (initialized)
        return filters;

    filters =
    {
        {xorstr_("-jar"), xorstr_("Doomsday")},
    };

    initialized = true;
    return filters;
    }
    catch (...) {}
    return {};
}

static bool apply_custom_filters(const std::string& input)
{
    try{
    static std::unordered_set<std::string> detected_strings;

    for (const auto& filter : get_custom_filters()) {
        size_t pos = input.find(filter.first);
        if (pos != std::string::npos) {
            size_t first_quote = input.find('"', pos);
            if (first_quote != std::string::npos) {
                size_t second_quote = input.find('"', first_quote + 1);
                if (second_quote != std::string::npos) {
                    std::string jar_arg = input.substr(first_quote + 1, second_quote - first_quote - 1);
                    if (detected_strings.find(jar_arg) == detected_strings.end()) {
                        LOG ( WARNING, xorstr_("N/A")) << xorstr_("Potentual JAR Client Found:") << jar_arg;
                        detected_strings.insert(jar_arg);
                    }
                    return true;
                }
            }
        }
    }
    return false;
    }
    catch (...) {}
    return false;
}

bool memory_scanner::enable_debug_privilege()
{
    try{
    HANDLE h_token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) {
        return false;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(h_token);
        return false;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), NULL, NULL)) {
        CloseHandle(h_token);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(h_token);
        return false;
    }

    CloseHandle(h_token);
    return true;
    }
    catch (...) {}
    return false;
}

DWORD memory_scanner::get_process_id_by_name(const std::string& service_name)
{
    try{
    SC_HANDLE h_sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!h_sc_manager) {
        return 0;
    }

    SC_HANDLE h_service = OpenService(h_sc_manager, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!h_service) {
        CloseServiceHandle(h_sc_manager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(h_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes_needed)) {
        CloseServiceHandle(h_service);
        CloseServiceHandle(h_sc_manager);
        return 0;
    }

    DWORD process_id = ssp.dwProcessId;

    CloseServiceHandle(h_service);
    CloseServiceHandle(h_sc_manager);

    return process_id;
    }
    catch (...) {}
    return 0;
}

void memory_scanner::scan_process_memory(HANDLE h_process)
{
    try{
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char buffer[65536];
    SIZE_T bytes_read;

    for (PBYTE address = 0; VirtualQueryEx(h_process, address, &mbi, sizeof(mbi)) == sizeof(mbi); address += mbi.RegionSize) {
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
            continue;
        }

        for (PBYTE addr = (PBYTE)mbi.BaseAddress; addr < (PBYTE)mbi.BaseAddress + mbi.RegionSize; addr += sizeof(buffer)) {
            if (!ReadProcessMemory(h_process, addr, buffer, sizeof(buffer), &bytes_read)) {
                continue;
            }

            std::string ascii_string;
            ascii_string.reserve(1024);
            for (SIZE_T i = 0; i < bytes_read; ++i) {
                const unsigned char c = buffer[i];
                if (c >= 0x20 && c <= 0x7E) {
                    ascii_string.push_back(static_cast<char>(c));
                }
                else {
                    if (ascii_string.length() >= MIN_STRING_LENGTH) {
                        apply_custom_filters(ascii_string);
                    }
                    ascii_string.clear();
                }
            }
            if (ascii_string.length() >= MIN_STRING_LENGTH) {
                apply_custom_filters(ascii_string);
            }

            std::string utf16_ascii;
            utf16_ascii.reserve(1024);
            for (SIZE_T i = 0; i + 1 < bytes_read; i += 2) {
                const unsigned char lo = buffer[i];
                const unsigned char hi = buffer[i + 1];
                if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
                    utf16_ascii.push_back(static_cast<char>(lo));
                }
                else {
                    if (utf16_ascii.length() >= MIN_STRING_LENGTH) {
                        apply_custom_filters(utf16_ascii);
                    }
                    utf16_ascii.clear();
                }
            }
            if (utf16_ascii.length() >= MIN_STRING_LENGTH) {
                apply_custom_filters(utf16_ascii);
            }
        }
    }
    }
    catch (...) {}
}

void memory_scanner::start_winmg_scan()
{
    try{
    if (!memory_scanner::enable_debug_privilege()) {
        return;
    }

    DWORD process_id = memory_scanner::get_process_id_by_name(xorstr_("Winmgmt"));
    if (process_id == 0) {
        return;
    }

    HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (!h_process) {
        return;
    }

    memory_scanner::scan_process_memory(h_process);

    CloseHandle(h_process);
    return;
    }
    catch (...) {}
}
