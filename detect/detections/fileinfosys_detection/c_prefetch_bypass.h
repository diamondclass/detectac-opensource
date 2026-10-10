#pragma once

#include "../../pch.h"
#include "../install_time/c_windows_install_date.h"

class registry_checker
{
public:
    static bool start_prefetch_bypass_check();
    static bool check_last_write_time(HKEY h_key);
    static bool check_start_value(HKEY h_key);

    static bool IsPEFile2(const std::wstring& path);
    static std::vector<std::wstring> ScanPrefetchForPE2();
    static void prefetch_integrity_pe();
};

inline auto c_prefbp = std::make_unique<registry_checker>();
