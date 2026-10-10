#pragma once

#include "../../../pch.h"

class PowerShellEventLogCheck
{
public:
    static bool IsMaxSize1028KB();
    static bool GetChannelMaxSizeBytes(const wchar_t* channelName, unsigned long long& outBytes);

    static void start_powershell_logsize_check();
};

inline auto c_powershell_logsize = std::make_unique<PowerShellEventLogCheck>();