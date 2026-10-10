#pragma once

#include "../../pch.h"

struct CrashRecord
{
    FILETIME time;
    std::string exePath;
    std::string formattedTime;
};

class CrashScanner
{
public:
    static void ScanFileDumps();
    static void ScanEventLog();
    static void CheckDumpFolder();
    static void PrintResults();
    static bool VerifyFileViaCatalog(LPCWSTR filePath);
    static std::unordered_map<std::string, CrashRecord> s_crashes;
    static bool IsAbsoluteWindowsPath(const std::wstring& path);
    static bool IsNewer(const FILETIME& a, const FILETIME& b);
    static bool GetCrashLocalTimeFromDump(const char* dumpPath, SYSTEMTIME& outLocalTime);
    static bool GetExecutablePathFromDump(const char* dumpPath, std::string& outExePath);
    static bool ShouldIgnoreExecutable(const std::wstring& path);
    static bool HasValidSignature(const wchar_t* filePath);
    static std::wstring ExtractBetween(
        const std::wstring& src,
        const std::wstring& start,
        const std::wstring& end
    );

    static std::wstring ConvertUtcToLocal(const std::wstring& utc);

    static void start_crashdump_checks();
};

inline auto c_cdump = std::make_unique<CrashScanner>();