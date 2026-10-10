#include "c_cleared_history.h"

std::string browser_cleared_scan::ChromeTimestampToLocal(long long chromeTime) {
    try {
        if (chromeTime <= 0) {
            return "";
        }

        unsigned long long filetimeTicks = static_cast<unsigned long long>(chromeTime) * 10ULL;

        FILETIME ft;
        ft.dwLowDateTime = static_cast<DWORD>(filetimeTicks & 0xFFFFFFFFULL);
        ft.dwHighDateTime = static_cast<DWORD>(filetimeTicks >> 32);

        SYSTEMTIME utc{}, local{};
        if (!FileTimeToSystemTime(&ft, &utc)) {
            return "";
        }
        if (!SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local)) {
            return "";
        }

        char buf[64];
        sprintf_s(
            buf,
            xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
            local.wYear, local.wMonth, local.wDay,
            local.wHour, local.wMinute, local.wSecond
        );
        return std::string(buf);
    }
    catch (...) {
        return "";
    }
}

std::string browser_cleared_scan::GetFileCreationTime(const std::string& path) {
    try {
        if (!std::filesystem::exists(path)) {
            return "";
        }

        HANDLE hFile = CreateFileA(
            path.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            return "";
        }

        FILETIME ftCreate;
        if (!GetFileTime(hFile, &ftCreate, nullptr, nullptr)) {
            CloseHandle(hFile);
            return "";
        }

        CloseHandle(hFile);

        SYSTEMTIME utc{}, local{};
        FileTimeToSystemTime(&ftCreate, &utc);
        SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local);

        char buf[64];
        sprintf_s(buf, xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
            local.wYear, local.wMonth, local.wDay,
            local.wHour, local.wMinute, local.wSecond);

        return std::string(buf);
    }
    catch (...) {
        return "";
    }
}

std::string browser_cleared_scan::GetEarliestHistory(const std::string& dbPath) {
    try {
        if (!std::filesystem::exists(dbPath)) {
            return "";
        }

        sqlite3* db = nullptr;
        int rc = sqlite3_open_v2(dbPath.c_str(), &db, SQLITE_OPEN_READONLY, nullptr);
        if (rc != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return "";
        }

        std::string sql = xorstr_("SELECT MIN(last_visit_time) FROM urls;");
        sqlite3_stmt* stmt = nullptr;

        rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            sqlite3_close(db);
            return "";
        }

        std::string result;
        rc = sqlite3_step(stmt);

        if (rc == SQLITE_ROW) {
            if (sqlite3_column_type(stmt, 0) != SQLITE_NULL) {
                long long t = sqlite3_column_int64(stmt, 0);
                result = ChromeTimestampToLocal(t);
            }
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);

        return result;
    }
    catch (...) {
        return "";
    }
}

std::vector<std::pair<std::string, std::string>> browser_cleared_scan::GetBrowserPaths() {
    try {
        char* appDataLocal = nullptr;
        char* appDataRoaming = nullptr;
        size_t len = 0;

        _dupenv_s(&appDataLocal, &len, xorstr_("LOCALAPPDATA"));
        _dupenv_s(&appDataRoaming, &len, xorstr_("APPDATA"));

        std::string local = appDataLocal ? appDataLocal : "";
        std::string roaming = appDataRoaming ? appDataRoaming : "";

        if (appDataLocal) free(appDataLocal);
        if (appDataRoaming) free(appDataRoaming);

        return {
            {xorstr_("Chrome"),   local + xorstr_("\\Google\\Chrome\\User Data\\Default\\History")},
            {xorstr_("Edge"),     local + xorstr_("\\Microsoft\\Edge\\User Data\\Default\\History")},
            {xorstr_("Brave"),    local + xorstr_("\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History")},
            {xorstr_("Opera"),    roaming + xorstr_("\\Opera Software\\Opera Stable\\Default\\History")},
            {xorstr_("OperaGX"),  roaming + xorstr_("\\Opera Software\\Opera GX Stable\\Default\\History")}
        };
    }
    catch (...) {
        return {};
    }
}

void browser_cleared_scan::start_cleared_check() {
    try {
        auto browsers = browser_cleared_scan::GetBrowserPaths();

        FILETIME ftNow;
        GetSystemTimeAsFileTime(&ftNow);

        ULARGE_INTEGER nowTicks{};
        nowTicks.LowPart = ftNow.dwLowDateTime;
        nowTicks.HighPart = ftNow.dwHighDateTime;

        const unsigned long long sevenDaysTicks = 7ULL * 24ULL * 60ULL * 60ULL * 10000000ULL;

        for (auto& b : browsers) {

            std::string earliestStr = browser_cleared_scan::GetEarliestHistory(b.second);

            if (earliestStr.empty()) {
                earliestStr = browser_cleared_scan::GetFileCreationTime(b.second);
            }

            if (earliestStr.empty()) {
                continue;
            }

            SYSTEMTIME st{};
            if (sscanf_s(
                earliestStr.c_str(),
                xorstr_("%hu-%hu-%hu %hu:%hu:%hu"),
                &st.wYear, &st.wMonth, &st.wDay,
                &st.wHour, &st.wMinute, &st.wSecond
            ) != 6) {
                continue;
            }

            FILETIME ftLocal{};
            if (!SystemTimeToFileTime(&st, &ftLocal)) {
                continue;
            }

            ULARGE_INTEGER earliestTicks{};
            earliestTicks.LowPart = ftLocal.dwLowDateTime;
            earliestTicks.HighPart = ftLocal.dwHighDateTime;

            unsigned long long diff = 0;
            if (nowTicks.QuadPart >= earliestTicks.QuadPart) {
                diff = nowTicks.QuadPart - earliestTicks.QuadPart;
            }
            else {
                continue;
            }

            if (diff <= sevenDaysTicks) {
                LOG(INFO, earliestStr) << b.first << xorstr_(" Browsing History Cleared Recently");
            }
        }

        return;
    }
    catch (...) {}
}
