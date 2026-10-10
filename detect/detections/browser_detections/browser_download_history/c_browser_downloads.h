#pragma once

#include "../../../pch.h"
#include "../sqlite/sqlite3.h"

class BrowserDownloadScanner {
public:
    static void start_download_history();

    static std::string GetLocalAppData();
    static std::string GetAppData();
    static bool FileExists(const std::string& path);
    static bool MatchesFilter(const std::string& url, std::string& messageOut);
    static void ExtractDownloadsFromHistory(const std::string& dbPath, const std::string& browserName);

    struct FilterRule {
        std::string urlSubstring;
        std::string customMessage;
    };

    static const std::vector<FilterRule> filters;
};