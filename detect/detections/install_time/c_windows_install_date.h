#pragma once

#include "../../pch.h"

class system_install_info {
public:
    static void print_install_date_and_elapsed_time();
    static DWORD get_install_date();
    static std::string unix_timestamp_to_readable_time(DWORD timestamp);
    static std::string calculate_time_ago(DWORD timestamp);
};

inline auto c_install = std::make_unique<system_install_info>();