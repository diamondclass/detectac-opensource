#include "c_service_detection.h"

std::wstring string_to_wstring(const std::string& str)
{
    try{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
    }
    catch (...) { return L""; }
}

std::string c_service_detection::file_time_to_string(const FILETIME& ft)
{
    try{
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    char buffer[64];
    sprintf_s(buffer, xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return std::string(buffer);
    }
    catch (...) { return ""; }
}

bool c_service_detection::enable_all_privileges()
{
    try{
    HANDLE token_handle;
    TOKEN_PRIVILEGES token_privileges;
    LUID privilege_luid;

    const LPCSTR privileges[] = {
        SE_DEBUG_NAME,
        SE_TCB_NAME,
        SE_ASSIGNPRIMARYTOKEN_NAME
    };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle)) {
        return false;
    }

    for (auto& priv : privileges) {
        if (LookupPrivilegeValue(NULL, priv, &privilege_luid)) {
            token_privileges.PrivilegeCount = 1;
            token_privileges.Privileges[0].Luid = privilege_luid;
            token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            AdjustTokenPrivileges(token_handle, FALSE, &token_privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
    }

    CloseHandle(token_handle);
    return true;
    }
    catch (...) { return false; }
}

bool c_service_detection::get_process_start_time(DWORD process_id, const std::string& process_name)
{
    try{
    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process_id);
    if (h_process == nullptr) {
        return false;
    }

    FILETIME creation_time, exit_time, kernel_time, user_time;
    if (GetProcessTimes(h_process, &creation_time, &exit_time, &kernel_time, &user_time)) {

        std::string utc_time = file_time_to_string(creation_time);

        std::wstring utc_time_wstring = string_to_wstring(utc_time);

        std::wstring local_time_wstring = utils->convert_utc_to_local(utc_time_wstring);

        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        std::string local_time = converter.to_bytes(local_time_wstring);

        std::string message;

        if ( process_name == xorstr_ ( "explorer.exe") )
        {
			message = xorstr_ ( "Explorer Start Time");
            LOG ( INFO , local_time ) << message;

        }
        else if ( process_name == xorstr_ ( "lsass.exe") )
        {
            message = xorstr_ ( "Lsass Start Time");
            LOG ( INFO , local_time ) << message;
        }
        else if ( process_name == xorstr_ ( "javaw.exe") )
        {
            message = xorstr_ ( "Javaw Start Time");
            LOG ( INFO , local_time ) << message;
        }
        else if (process_name == xorstr_("FortniteClient-Win64-Shipping.exe"))
        {
            message = xorstr_("Fortnite Start Time");
            LOG(INFO, local_time) << message;
        }
        else
        {
            std::string message = xorstr_ ( "" ) + process_name + xorstr_ ( " Start Time" );
			LOG ( INFO , local_time ) << message;
        }

        CloseHandle(h_process);
        return true;
    }
    else {
        CloseHandle(h_process);
        return false;
    }
    }
    catch (...) { return false; }
}

DWORD c_service_detection::get_process_id_by_name(const std::string& process_name)
{
    try{
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (h_snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(h_snapshot, &process_entry)) {
        do {
            if (process_name == process_entry.szExeFile) {
                CloseHandle(h_snapshot);
                return process_entry.th32ProcessID;
            }
        } while (Process32Next(h_snapshot, &process_entry));
    }

    CloseHandle(h_snapshot);
    return 0;
    }
    catch (...) { return 0; }
}

void c_service_detection::get_service_start_time(const std::string& service_name)
{
    try{
    SC_HANDLE scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (scm_handle == nullptr) {
        return;
    }

    SC_HANDLE service_handle = OpenService(scm_handle, service_name.c_str(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    if (service_handle == nullptr) {
        CloseServiceHandle(scm_handle);
        return;
    }

    SERVICE_STATUS_PROCESS service_status;
    DWORD bytes_needed;
    if (QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO, (LPBYTE)&service_status, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
    {
        if (service_status.dwCurrentState == SERVICE_RUNNING)
        {
            get_process_start_time(service_status.dwProcessId, service_name);
        }
        else
        {
            std::string message = service_name + xorstr_ ( " is not running." );
            LOG ( WARNING , xorstr_("N/A") ) << message;

        }
    }

    CloseServiceHandle(service_handle);
    CloseServiceHandle(scm_handle);
    }
    catch (...) {}
}

void c_service_detection::start_service_checks()
{
    try{
    try {
        SYSTEMTIME st;
        GetLocalTime(&st);
        char buffer[64];
        sprintf_s(buffer, xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        LOG(INFO, std::string(buffer)) << xorstr_("Scan Time");
    }
    catch (...) {}

    if (!enable_all_privileges()) {}

    std::vector<std::pair<std::string, std::string>> services =
    {
        { xorstr_ ( "DusmSvc"), xorstr_ ( "DusmSvc" )},
        { xorstr_ ( "Diagnostic Policy Service"), xorstr_ ( "DPS" )},
        { xorstr_ ( "Windows Event Log"), xorstr_ ( "EventLog" )},
        { xorstr_ ( "DNS Client"), xorstr_ ( "Dnscache" )},
        { xorstr_ ( "SysMain"), xorstr_ ( "SysMain" )}
    };

    std::vector<std::string> processes =
    {
            #ifdef DETECT_MINECRAFT
            xorstr_ ( "javaw.exe" ),
        #elif DETECT_FORTNITE
            xorstr_("FortniteClient-Win64-Shipping.exe"),
        #endif
            xorstr_ ( "explorer.exe"),
            xorstr_ ( "lsass.exe")
    };

    for (const auto& service : services)
    {
        const std::string& service_name = service.second;
        get_service_start_time(service_name);
    }

    for (const std::string& process_name : processes)
    {
        DWORD process_id = get_process_id_by_name(process_name);
        if (process_id != 0)
            get_process_start_time(process_id, process_name);
        else
        {
            std::string message;

            if ( process_name == xorstr_ ( "explorer.exe") )
                message = xorstr_ ( "Explorer is not running or could not be found.");
            else if ( process_name == xorstr_ ( "lsass.exe") )
                message = xorstr_ ( "Lsass is not running or could not be found.");

            #ifdef DETECT_MINECRAFT
            else if ( process_name == xorstr_ ( "javaw.exe" ) )
                message = xorstr_ ( "Minecraft is not running or could not be found." );
           #elif DETECT_FORTNITE
            else if (process_name == xorstr_("FortniteClient-Win64-Shipping.exe"))
                message = xorstr_("Fortnite is not running or could not be found.");
        #endif

            LOG ( INFO, xorstr_( "N/A" ) ) << message;
        }
    }
    }
    catch (...) {}
}
