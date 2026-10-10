#include "c_windows_install_date.h"

void system_install_info::print_install_date_and_elapsed_time() {
    try{
    DWORD install_date = get_install_date();
    if (install_date == 0) {
        return;
    }

    std::string readable_date = unix_timestamp_to_readable_time(install_date);
    std::string elapsed_time = calculate_time_ago(install_date);

    LOG ( INFO , readable_date ) << xorstr_("Windows Installed:") << elapsed_time << xorstr_(" ago");
    }
    catch (...) {}
}

DWORD system_install_info::get_install_date() {
    try{
    HKEY hKey;
    std::wstring sub_key = xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    std::wstring value_name = xorstr_(L"InstallDate");
    DWORD install_date = 0;
    DWORD data_size = sizeof(install_date);

    LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub_key.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
    if (result != ERROR_SUCCESS) {
        return 0;
    }

    result = RegQueryValueExW(hKey, value_name.c_str(), nullptr, nullptr, reinterpret_cast<LPBYTE>(&install_date), &data_size);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS) {
        return 0;
    }

    return install_date;
    }
    catch (...) { return 0; }
}

std::string system_install_info::unix_timestamp_to_readable_time(DWORD timestamp) {
    try{
    time_t raw_time = static_cast<time_t>(timestamp);
    if (raw_time <= 0 || raw_time > 32535244799LL) {
        return xorstr_("N/A");
    }

    struct tm time_info;
    if (localtime_s(&time_info, &raw_time) != 0) {
        return xorstr_("N/A");
    }

    char buffer[80];
    if (strftime(buffer, sizeof(buffer), xorstr_("%Y-%m-%d %H:%M:%S"), &time_info) == 0) {
        return xorstr_("N/A");
    }
    return std::string(buffer);
    }
    catch (...) { return ""; }
}

std::string system_install_info::calculate_time_ago(DWORD timestamp) {
    try{
    time_t current_time = time(nullptr);
    time_t elapsed_time = current_time - static_cast<time_t>(timestamp);
    if (elapsed_time < 0) elapsed_time = 0;

    int minutes = static_cast<int>(elapsed_time / 60);
    int hours = minutes / 60;
    int days = hours / 24;
    int years = days / 365;
    int months = (days % 365) / 30;
    days = (days % 365) % 30;

    std::ostringstream time_ago;
    time_ago << years << (years == 1 ? xorstr_(" year, ") : xorstr_(" years, "));
    time_ago << months << (months == 1 ? xorstr_(" month, ") : xorstr_(" months, "));
    time_ago << days << (days == 1 ? xorstr_(" day, ") : xorstr_(" days, "));
    time_ago << hours % 24 << (hours % 24 == 1 ? xorstr_(" hour, ") : xorstr_(" hours, "));
    time_ago << minutes % 60 << (minutes % 60 == 1 ? xorstr_(" minute") : xorstr_(" minutes"));

    return time_ago.str();
    }
    catch (...) { return ""; }
}