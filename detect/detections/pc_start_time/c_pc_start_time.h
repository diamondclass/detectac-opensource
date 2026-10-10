#pragma once

#include "../../pch.h"

class PCStartTime
{
public:
    FILETIME getUserLogonTime();
    std::string fileTimeToReadableString(const FILETIME& fileTime);
    std::string calculateTimeAgo(const FILETIME& localFileTime);
    static void start_pc_start_time_check();

};

inline auto c_pc_start = std::make_unique<PCStartTime>();