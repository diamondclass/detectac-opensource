#include "c_ran_modified_extension.h"

bool ran_modified_extension::enable_debug_privilege() {
    try{
    HANDLE h_token;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(h_token);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(h_token, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(h_token);
        return false;
    }

    CloseHandle(h_token);

    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }
    catch (...) {}
}

std::wstring ran_modified_extension::sanitize_string(const std::wstring& input) {
    try{
    std::wstring sanitized;
    for (wchar_t c : input) {
        if (c < 0x20 || c > 0x7E) {
            sanitized += L'?';
        }
        else {
            sanitized += c;
        }
    }
    if (sanitized.length() > 27) {
        return sanitized.substr(3, sanitized.length() - 27);
    }
    return xorstr_ ( L"" );
    }
    catch (...) {}
    return {};
}

bool ran_modified_extension::is_valid_string(const std::wstring& str) {
    try{
    return str.length() >= 25 && str.find(xorstr_(L"!0!")) != std::wstring::npos && str.substr(1, 2) == xorstr_(L"!!");
    }
    catch (...) {}
    return false;
}

std::wstring ran_modified_extension::to_lower(const std::wstring& input) {
    try{
    std::wstring result = input;
    std::transform(result.begin(), result.end(), result.begin(), towlower);
    return result;
    }
    catch (...) {}
    return {};
}

void ran_modified_extension::extract_and_check_utf16_strings(const char* buffer, size_t size) {
    try{
    const size_t min_string_length = 4;
    std::wstring current_string;

    const std::vector<std::wstring> whitelist = {
        xorstr_(L"system"), xorstr_(L"isrdpc"), xorstr_(L"memcompression"), xorstr_(L"registry"), xorstr_(L"Re??stry"), xorstr_(L"fivem_roslauncher"),
        xorstr_(L"hxdsetup.tmp"), xorstr_(L"default"), xorstr_(L"totals"), xorstr_(L"wbisleep.exe"), xorstr_(L"processhacker-2.39-setup.tmp"),
        xorstr_(L"iif49e1.tmp"), xorstr_(L"secure system"), xorstr_(L"fivem_chromebrowser"), xorstr_(L"fivem_rosservice"),
        xorstr_(L"fivem_authbrowser"), xorstr_(L"cleanup.feather"), xorstr_(L"system informer kernel"), xorstr_(L"vmmem"), xorstr_(L"vmmemwsl")
    };

    for (size_t i = 0; i < size - 1; i += 2) {
        wchar_t wchar = *reinterpret_cast<const wchar_t*>(&buffer[i]);
        current_string += wchar;

        if (wchar == 0 || i + 2 >= size) {
            if (current_string.length() >= min_string_length && is_valid_string(current_string)) {
                std::wstring sanitized = sanitize_string(current_string);
                std::wstring lower_sanitized = to_lower(sanitized);

                if (lower_sanitized.length() >= 4 &&
                    lower_sanitized.substr(lower_sanitized.length() - 4) == xorstr_(L".exe")) {
                    current_string.clear();
                    continue;
                }

                if (std::find(whitelist.begin(), whitelist.end(), lower_sanitized) != whitelist.end()) {
                    current_string.clear();
                    continue;
                }

                LOG(WARNING, xorstr_("N/A")) << xorstr_(L"File Ran With Modified Extension:") << sanitized;
            }
            current_string.clear();
        }
    }

    if (current_string.length() >= min_string_length && is_valid_string(current_string)) {
        std::wstring sanitized = sanitize_string(current_string);
        std::wstring lower_sanitized = to_lower(sanitized);

        if (!(lower_sanitized.length() >= 4 &&
            lower_sanitized.substr(lower_sanitized.length() - 4) == xorstr_(L".exe")) &&
            std::find(whitelist.begin(), whitelist.end(), lower_sanitized) == whitelist.end()) {
            LOG(WARNING, xorstr_("N/A")) << xorstr_(L"File Ran With Modified Extension:") << sanitized;
        }
    }
    }
    catch (...) {}
}

void ran_modified_extension::read_protected_memory(HANDLE h_process) {
    try{
    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    MEMORY_BASIC_INFORMATION mem_info;
    LPVOID addr = sys_info.lpMinimumApplicationAddress;
    SIZE_T bytes_read;
    std::vector<char> buffer(65536);

    while (addr < sys_info.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(h_process, addr, &mem_info, sizeof(mem_info)) == sizeof(mem_info)) {
            if (mem_info.State == MEM_COMMIT && (mem_info.Type == MEM_PRIVATE || mem_info.Type == MEM_MAPPED)) {
                LPVOID base_addr = mem_info.BaseAddress;
                SIZE_T region_size = mem_info.RegionSize;

                while (region_size > 0) {
                    SIZE_T to_read = std::min(buffer.size(), region_size);
                    if (ReadProcessMemory(h_process, base_addr, buffer.data(), to_read, &bytes_read) && bytes_read > 0) {
                        extract_and_check_utf16_strings(buffer.data(), bytes_read);
                    }

                    base_addr = (LPVOID)((SIZE_T)base_addr + to_read);
                    region_size -= to_read;
                }
            }
        }
        addr = (LPVOID)((SIZE_T)addr + mem_info.RegionSize);
    }
    }
    catch (...) {}
}

DWORD ran_modified_extension::get_service_process_id(const std::wstring& service_name) {
    try{
    SC_HANDLE h_sc_manager = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!h_sc_manager) {
        return 0;
    }

    SC_HANDLE h_service = OpenServiceW(h_sc_manager, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!h_service) {
        CloseServiceHandle(h_sc_manager);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    if (!QueryServiceStatusEx(h_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes_needed)) {
        CloseServiceHandle(h_service);
        CloseServiceHandle(h_sc_manager);
        return 0;
    }

    CloseServiceHandle(h_service);
    CloseServiceHandle(h_sc_manager);

    return ssp.dwProcessId;
    }
    catch (...) {}
}

void ran_modified_extension::start_modified_check () {
    try{
    std::wstring service_name =  xorstr_ ( L"DPS" ); 

    if (!ran_modified_extension::enable_debug_privilege()) {
        return;
    }

    DWORD process_id = ran_modified_extension::get_service_process_id(service_name);
    if (process_id == 0) {
        return;
    }

    HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (!h_process) {
        return;
    }

    ran_modified_extension::read_protected_memory(h_process);

    CloseHandle(h_process);
    return;
    }
    catch (...) {}
}