#pragma once

#include "../../../pch.h"

class c_powershell_commands_ran_detection
{
public:
    static void Scan(const wchar_t* evtxPath);
    static std::string ExtractEventTime(const std::string& xml);
    static std::string FormatEventTime(const std::string& isoTime);
    static std::string ExtractHostApplication(const std::string& xml);
    static bool ContainsSuspiciousCommand(const std::string& hostApp);
    static std::string ToLower(std::string s);

    static void start_powershell_evtx_commands();
};

inline auto c_powershell_commands_ran = std::make_unique<c_powershell_commands_ran_detection> ( );