#pragma once

#include "../../pch.h"
#include <vector>

class DiscordScanner {
public:
    struct ProcessInfo {
        DWORD pid;
        HANDLE hProcess;
        std::string processName;
    };

    struct Account {
        std::string id;
        std::string username;
    };

    static bool IsPrintableChar(char c);
    static std::vector<Account> ExtractAccounts(const std::string& jsonString);
    static std::vector<ProcessInfo> GetDiscordProcesses();
    static bool SearchForTargetStringInProcess(HANDLE hProcess);

    static bool ScanForDiscordUsernames();
};

inline auto c_discacc = std::make_unique<DiscordScanner>();