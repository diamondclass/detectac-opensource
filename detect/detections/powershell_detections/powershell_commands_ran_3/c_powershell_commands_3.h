#pragma once

#include "../../../pch.h"

class PowerShellEventParser
{
public:
    static void start_commands_3();

private:
    static const std::vector<std::wstring> s_keywords;

    static std::wstring ToLower(std::wstring s);
    static std::wstring Flatten(std::wstring s);
    static bool MatchesKeyword(const std::wstring& scriptBlock);
    static std::string WideToUtf8(const std::wstring& ws);
    static std::wstring FileTimeToLocalString(ULONGLONG ft);
    static void ProcessEvents(EVT_HANDLE hQuery, EVT_HANDLE hCtx);
};

inline auto c_commands3 = std::make_unique<PowerShellEventParser>();