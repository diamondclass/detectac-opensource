#pragma once

#include "../../pch.h"

class AutorunsScanner
{
public:
    enum class SignStatus : int {
        Unchecked     = 0,
        Signed        = 1,
        Unsigned      = 2,
        NotApplicable = 3,
    };

    struct UsnEntry {
        DWORD rawReason = 0;
    };

    struct AutorunEntry {
        std::wstring imagePath;
        std::wstring source;
        ULONGLONG    rawTimestamp     = 0;
        bool         scanned          = false;
        bool         exists           = false;
        bool         isImageHijack    = false;
        SignStatus   signStatus       = SignStatus::Unchecked;
        std::vector<UsnEntry> usnEntries;
    };

    struct PathInfo {
        size_t       index;
        std::wstring lowerPath;
    };

    using NameIndex = std::unordered_map<std::wstring, std::vector<PathInfo>>;

    static void Run();

private:
    static std::wstring TrimWS(const std::wstring& s);
    static std::wstring StripWrappingQuotes(const std::wstring& s);
    static std::wstring LowerCopy(const std::wstring& s);
    static std::wstring ExpandEnv(const std::wstring& s);
    static bool         StartsWithI(const std::wstring& s, const wchar_t* prefix);
    static std::wstring GetSysDir();
    static std::wstring GetWinDir();
    static std::wstring GetWow64Dir();
    static bool         IsAbsolutePath(const std::wstring& p);

    static std::wstring NormalizeImagePath(const std::wstring& raw);
    static std::wstring ExtractRundll32Target(const std::wstring& cmd);
    static std::wstring ResolveImagePath(const std::wstring& rawCommand);
    static bool         FileExistsOnDisk(const std::wstring& path);
    static bool         IsDirectoryOnDisk(const std::wstring& path);

    static bool         HasValidSignature(const wchar_t* filePath);
    static std::wstring GetOriginalFilename(const std::wstring& filePath);
    static bool         IsAlwaysShowFile(const std::wstring& filePath);

    static bool         ReadRegString(HKEY root, const wchar_t* sub, const wchar_t* name, std::wstring& out, REGSAM extra);
    static std::vector<std::wstring> ReadRegMultiSz(HKEY root, const wchar_t* sub, const wchar_t* name, REGSAM extra);
    static FILETIME     GetKeyTime(HKEY root, const wchar_t* sub, REGSAM extra);
    static ULONGLONG    FileTimeToU64(const FILETIME& ft);

    static std::wstring ResolveClsidPath(const std::wstring& clsid);

    static void EnumRunStyleKey(HKEY root, const wchar_t* sub, std::vector<AutorunEntry>& out, REGSAM extra);
    static std::wstring ResolveLnkTarget(const std::wstring& lnkPath);
    static void EnumStartupFolder(int csidl, std::vector<AutorunEntry>& out);
    static void EnumClsidSubkeys(HKEY root, const wchar_t* sub, std::vector<AutorunEntry>& out);
    static void EnumClsidValueNames(HKEY root, const wchar_t* sub, std::vector<AutorunEntry>& out);

    static void ScanLogon(std::vector<AutorunEntry>& out);
    static void ScanExplorer(std::vector<AutorunEntry>& out);
    static void ScanInternetExplorer(std::vector<AutorunEntry>& out);
    static void ScanScheduledTasks(std::vector<AutorunEntry>& out);
    static void EnumTaskFolder(void* folder, std::vector<AutorunEntry>& out);
    static void ScanServicesAndDrivers(std::vector<AutorunEntry>& out);
    static void ScanCodecs(std::vector<AutorunEntry>& out);
    static void ScanBootExecute(std::vector<AutorunEntry>& out);
    static void ScanImageHijacks(std::vector<AutorunEntry>& out);
    static void ScanAppInitDLLs(std::vector<AutorunEntry>& out);
    static void ScanKnownDLLs(std::vector<AutorunEntry>& out);
    static void ScanWinlogon(std::vector<AutorunEntry>& out);
    static void ScanWinsockProviders(std::vector<AutorunEntry>& out);
    static void ScanPrintMonitors(std::vector<AutorunEntry>& out);
    static void ScanLsaProviders(std::vector<AutorunEntry>& out);
    static void ScanNetworkProviders(std::vector<AutorunEntry>& out);
    static void ScanWmi(std::vector<AutorunEntry>& out);

    static std::vector<AutorunEntry> ScanAll();

    static void ScanEntrySignatures(AutorunEntry& e);
    static DWORD WINAPI ScanWorker(LPVOID param);
    static void RunSignatureScan(std::vector<AutorunEntry>& entries);

    static bool HasSuspiciousUsnReason(DWORD reason);
    static void UsnScanDrive(const wchar_t* volumePath, const NameIndex& nameIndex, std::vector<std::vector<UsnEntry>>& results);
    static std::wstring UsnResolveParentDir(HANDLE hVolume, ULONGLONG parentRef, std::map<ULONGLONG, std::wstring>& cache);
    static std::vector<std::vector<UsnEntry>> UsnScan(const std::vector<std::wstring>& filePaths);
    static void AttachUsnResults(std::vector<AutorunEntry>& entries);

    static ULONGLONG GetUserLogonTime();
    static void      CheckIfeoBootModification();
    static bool      SinceLogon(const AutorunEntry& e, ULONGLONG logonTime);
    static bool      IsUnsigned(const AutorunEntry& e);
    static bool      HasSuspiciousUsnHits(const AutorunEntry& e);

    static std::string FormatTimestamp(ULONGLONG rawFileTime);
};

class c_autoruns_detection
{
public:
    static void start_autoruns_detection();
};

inline auto c_autoruns = std::make_unique<c_autoruns_detection>();
