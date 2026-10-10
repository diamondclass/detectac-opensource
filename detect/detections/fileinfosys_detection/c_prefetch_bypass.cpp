#include "c_prefetch_bypass.h"

bool registry_checker::start_prefetch_bypass_check()
{
    try{
    HKEY h_key;
    std::wstring key_path = xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\FileInfo");

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.c_str(), 0, KEY_READ, &h_key) != ERROR_SUCCESS)
    {
        return false;
    }

    check_last_write_time(h_key);
    check_start_value(h_key);

    RegCloseKey(h_key);
    return true;
    }
    catch (...) { return false; }
}

bool registry_checker::check_last_write_time(HKEY h_key)
{
    try {
        FILETIME ft_write;
        if (RegQueryInfoKeyW(
            h_key,
            nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr,
            nullptr,
            &ft_write) != ERROR_SUCCESS)
        {
            return false;
        }

        SYSTEMTIME st_now_utc;
        GetSystemTime(&st_now_utc);

        FILETIME ft_now;
        SystemTimeToFileTime(&st_now_utc, &ft_now);

        ULARGE_INTEGER now, write_time;
        now.LowPart = ft_now.dwLowDateTime;
        now.HighPart = ft_now.dwHighDateTime;
        write_time.LowPart = ft_write.dwLowDateTime;
        write_time.HighPart = ft_write.dwHighDateTime;

        const ULONGLONG twenty_four_hours = 24ULL * 60 * 60 * 10000000ULL;
        const ULONGLONG six_hours = 6ULL * 60 * 60 * 10000000ULL;

        if ((now.QuadPart - write_time.QuadPart) > twenty_four_hours)
            return false;

        DWORD install_date = system_install_info::get_install_date();
        if (install_date != 0)
        {
            ULONGLONG install_filetime =
                (static_cast<ULONGLONG>(install_date) + 11644473600ULL) * 10000000ULL;

            ULONGLONG diff =
                (write_time.QuadPart > install_filetime)
                ? (write_time.QuadPart - install_filetime)
                : (install_filetime - write_time.QuadPart);

            if (diff <= six_hours)
            {
                return false;
            }
        }

        FILETIME ft_local;
        FileTimeToLocalFileTime(&ft_write, &ft_local);

        SYSTEMTIME st_write;
        FileTimeToSystemTime(&ft_local, &st_write);

        char timestamp[32];
        snprintf(
            timestamp,
            sizeof(timestamp),
            xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            static_cast<int>(st_write.wYear),
            static_cast<int>(st_write.wMonth),
            static_cast<int>(st_write.wDay),
            static_cast<int>(st_write.wHour),
            static_cast<int>(st_write.wMinute),
            static_cast<int>(st_write.wSecond)
        );

        LOG(DETECTION, timestamp) << xorstr_("Malicious Prefetch Modification Found:FileInfo.sys Kernel Driver Modified");

        return true;
    }
    catch (...) {}

    return false;
}

bool registry_checker::check_start_value(HKEY h_key)
{
    try{
    std::wstring value_name = xorstr_(L"Start");
    DWORD data;
    DWORD data_size = sizeof(data);
    DWORD type;

    if (RegQueryValueExW(h_key, value_name.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(&data), &data_size) == ERROR_SUCCESS &&
        type == REG_DWORD && data == 4)
    {
        LOG ( DETECTION , xorstr_("N/A") ) << xorstr_("Malicious Prefetch Modification Found:FileInfo.sys Kernel Driver Disabled");
        return true;
    }
    return false;

    }
    catch (...) { return false; }
}