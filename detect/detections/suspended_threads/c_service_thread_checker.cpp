#include "c_service_thread_checker.h"

service_thread_checker::pfn_nt_query_information_thread service_thread_checker::nt_query_information_thread = nullptr;

bool service_thread_checker::initialize() {
    try{
    return enable_debug_privilege() && load_nt_query_information_thread();
    }
    catch (...) {}
}

bool service_thread_checker::enable_debug_privilege() {
    try{
    HANDLE token;
    TOKEN_PRIVILEGES token_priv;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &token_priv.Privileges[0].Luid);
    token_priv.PrivilegeCount = 1;
    token_priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, FALSE, &token_priv, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
        CloseHandle(token);
        return false;
    }

    CloseHandle(token);
    return true;
    }
    catch (...) {}
}

bool service_thread_checker::load_nt_query_information_thread() {
    try{
    HMODULE h_nt_dll = LoadLibraryW(xorstr_(L"ntdll.dll"));
    if (h_nt_dll == nullptr) {
        return false;
    }
    nt_query_information_thread = (pfn_nt_query_information_thread)GetProcAddress(h_nt_dll, xorstr_("NtQueryInformationThread"));
    if (nt_query_information_thread == nullptr) {
        FreeLibrary(h_nt_dll);
        return false;
    }
    return true;
    }
    catch (...) {}
}

bool service_thread_checker::is_thread_suspended(HANDLE h_thread) {
    try{
    DWORD suspend_count = SuspendThread(h_thread);
    if (suspend_count == (DWORD)-1) {
        return false;
    }

    ResumeThread(h_thread);

    return suspend_count > 0;
    }
    catch (...) {}
}

void service_thread_checker::check_process_threads(DWORD process_id, const std::wstring& service_name) {
    try{
    HANDLE h_thread_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (h_thread_snap == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 thread_entry;
    thread_entry.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(h_thread_snap, &thread_entry)) {
        do {
            if (thread_entry.th32OwnerProcessID == process_id) {
                HANDLE h_thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, thread_entry.th32ThreadID);
                if (h_thread != nullptr) {
                    if (is_thread_suspended(h_thread)) {
                        LOG (DETECTION , xorstr_("N/A") ) << xorstr_("Suspended Thread:") << service_name;
                    }
                    CloseHandle(h_thread);
                }
            }
        } while (Thread32Next(h_thread_snap, &thread_entry));
    }
    CloseHandle(h_thread_snap);
    }
    catch (...) {}
}

DWORD service_thread_checker::get_service_process_id(const std::wstring& service_name) {
    try{
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    DWORD process_id = 0;

    SC_HANDLE sc_manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!sc_manager) {
        return 0;
    }

    SC_HANDLE sc_service = OpenServiceW(sc_manager, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!sc_service) {
        CloseServiceHandle(sc_manager);
        return 0;
    }

    if (QueryServiceStatusEx(sc_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed)) {
        process_id = ssp.dwProcessId;
    }

    CloseServiceHandle(sc_service);
    CloseServiceHandle(sc_manager);
    return process_id;
    }
    catch (...) {}
}

DWORD service_thread_checker::get_process_id_by_name(const std::wstring& process_name) {
    try {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return 0;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        DWORD pid = 0;
        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
                    pid = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }
        CloseHandle(snapshot);
        return pid;
    }
    catch (...) { return 0; }
}

void service_thread_checker::check_services_for_suspended_threads(const std::vector<std::wstring>& services) {
    try{
    for (const auto& service_name : services) {
        DWORD process_id = get_service_process_id(service_name);
        if (process_id == 0) {
            continue;
        }
        check_process_threads(process_id, service_name);
    }
    }
    catch (...) {}
}

void service_thread_checker::check_processes_for_suspended_threads(const std::vector<std::wstring>& process_names) {
    try {
        for (const auto& name : process_names) {
            DWORD process_id = get_process_id_by_name(name);
            if (process_id == 0)
                continue;
            check_process_threads(process_id, name);
        }
    }
    catch (...) {}
}

void service_thread_checker::start_suspeced_threads_detection() {
    try{
    if (!service_thread_checker::initialize()) {
    }

    std::vector<std::wstring> services = {
        xorstr_(L"DusmSvc"), xorstr_(L"SysMain"), xorstr_(L"DPS"),
        xorstr_(L"EventLog"), xorstr_(L"Dnscache")
    };
    service_thread_checker::check_services_for_suspended_threads(services);

    std::vector<std::wstring> processes = {
        xorstr_(L"lsass.exe")
    };
    service_thread_checker::check_processes_for_suspended_threads(processes);
    }
    catch (...) {}
}