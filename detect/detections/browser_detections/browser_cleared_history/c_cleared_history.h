#pragma once
#include "../../../pch.h"

class browser_cleared_scan {
public:
    static std::string ChromeTimestampToLocal(long long chromeTime);
    static std::string GetEarliestHistory(const std::string& dbPath);
    static std::string GetFileCreationTime(const std::string& path);
    static std::vector<std::pair<std::string, std::string>> GetBrowserPaths();

    static void start_cleared_check();
};

