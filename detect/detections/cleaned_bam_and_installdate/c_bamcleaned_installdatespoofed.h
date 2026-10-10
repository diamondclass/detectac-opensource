#pragma once

#include "../../pch.h"

class bam_detection {
public:
    static void detect_bam_cleaned();

    static DWORD get_install_date();
    static DWORD get_last_logon_time();
    static std::string filetime_to_unix_timestamp_string(FILETIME ft);
    static bool is_timestamp_within_range(DWORD reference_time, FILETIME ft, DWORD seconds_range);
};

inline auto c_bam_install = std::make_unique < bam_detection >();