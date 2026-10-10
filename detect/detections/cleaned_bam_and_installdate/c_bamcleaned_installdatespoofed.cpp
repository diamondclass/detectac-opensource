#include "c_bamcleaned_installdatespoofed.h"

DWORD bam_detection::get_install_date() {
    try{
    HKEY hKey;
    std::wstring sub_key = xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    std::wstring value_name = xorstr_(L"InstallDate");
    DWORD install_date = 0;
    DWORD data_size = sizeof(install_date);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_key.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) return 0;
    if (RegQueryValueExW(hKey, value_name.c_str(), nullptr, nullptr, reinterpret_cast<LPBYTE>(&install_date), &data_size) != ERROR_SUCCESS) install_date = 0;
    RegCloseKey(hKey);
    return install_date;
    }
    catch (...) { return 0; }
}

DWORD bam_detection::get_last_logon_time() {
    try{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);

    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);

    tm t = {};
    t.tm_year = st.wYear - 1900;
    t.tm_mon = st.wMonth - 1;
    t.tm_mday = st.wDay;
    t.tm_hour = st.wHour;
    t.tm_min = st.wMinute;
    t.tm_sec = st.wSecond;

    return static_cast<DWORD>(mktime(&t));
    }
    catch (...) { return 0; }
}

std::string bam_detection::filetime_to_unix_timestamp_string(FILETIME ft) {
    try{
    ULARGE_INTEGER ull;
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    ULONGLONG time_100ns = ull.QuadPart;

    if (time_100ns < 116444736000000000ULL) {
        return xorstr_("N/A");
    }

    ULONGLONG seconds = (time_100ns / 10000000ULL) - 11644473600ULL;
    if (seconds > 32535244799ULL) {
        return xorstr_("N/A");
    }

    time_t unix_time = static_cast<time_t>(seconds);
    tm time_info;
    if (localtime_s(&time_info, &unix_time) != 0) {
        return xorstr_("N/A");
    }

    char buffer[64];
    sprintf_s(buffer, xorstr_("%04d-%02d-%02d %02d:%02d:%02d)"),
        time_info.tm_year + 1900, time_info.tm_mon + 1, time_info.tm_mday,
        time_info.tm_hour, time_info.tm_min, time_info.tm_sec);
    return std::string(buffer);
    }
    catch (...) { return ""; }
}

void bam_detection::detect_bam_cleaned() {
    try{
    DWORD install_date = get_install_date();
    time_t now = time(nullptr);

    const time_t install_skew_slack = 26 * 60 * 60;

    if (install_date <= 0 || install_date < 1000000000 ||
        static_cast<time_t>(install_date) > now + install_skew_slack) {
        LOG(WARNING, xorstr_("N/A")) << xorstr_("Spoofed Windows Install Date:") << install_date;
    }

    DWORD reference_time = get_last_logon_time();

    HKEY h_key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        xorstr_("SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings"),
        0, KEY_READ, &h_key) != ERROR_SUCCESS) return;

    char subkey_name[256];
    DWORD subkey_name_size;
    DWORD index = 0;
    bool bam_entry_before_logon = false;

    while (true) {
        subkey_name_size = sizeof(subkey_name);
        if (RegEnumKeyExA(h_key, index, subkey_name, &subkey_name_size, NULL, NULL, NULL, NULL) == ERROR_NO_MORE_ITEMS) break;

        if (subkey_name_size > 30) {
            HKEY h_user_key;
            std::string full_subkey_path = std::string(xorstr_("SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\")) + subkey_name;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, full_subkey_path.c_str(), 0, KEY_READ, &h_user_key) == ERROR_SUCCESS) {
                char value_name[256];
                DWORD value_name_size;
                DWORD type;
                BYTE data[1024];
                DWORD data_size;
                DWORD value_index = 0;

                while (true) {
                    value_name_size = sizeof(value_name);
                    data_size = sizeof(data);
                    if (RegEnumValueA(h_user_key, value_index, value_name, &value_name_size, NULL, &type, data, &data_size) == ERROR_NO_MORE_ITEMS) break;

                    if (type == REG_BINARY && data_size >= sizeof(FILETIME)) {
                        FILETIME bam_timestamp;
                        memcpy(&bam_timestamp, data, sizeof(FILETIME));

                        ULARGE_INTEGER ull;
                        ull.LowPart = bam_timestamp.dwLowDateTime;
                        ull.HighPart = bam_timestamp.dwHighDateTime;
                        ULONGLONG time_100ns = ull.QuadPart;
                        time_t unix_time = static_cast<time_t>((time_100ns / 10000000ULL) - 11644473600ULL);

                        if (unix_time < reference_time) {
                            bam_entry_before_logon = true;
                        }
                    }
                    value_index++;
                }
                RegCloseKey(h_user_key);
            }
        }
        index++;
    }

    RegCloseKey(h_key);

    if (!bam_entry_before_logon) {
        LOG(WARNING, xorstr_("N/A")) << xorstr_("BAM Has Been Cleaned:User has likely cleaned their BAM in attempt to bypass");
    }
    }
    catch (...) {}
}
