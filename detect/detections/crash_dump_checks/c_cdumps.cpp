#include "c_cdumps.h"

static std::unordered_map<std::wstring, bool> g_catalogCache;
std::unordered_map<std::string, CrashRecord> CrashScanner::s_crashes;

bool CrashScanner::IsNewer(const FILETIME& a, const FILETIME& b)
{
    try {
        ULARGE_INTEGER ua, ub;
        ua.LowPart = a.dwLowDateTime;
        ua.HighPart = a.dwHighDateTime;
        ub.LowPart = b.dwLowDateTime;
        ub.HighPart = b.dwHighDateTime;
        return ua.QuadPart > ub.QuadPart;
    }
    catch (...) {}
    return false;
}

bool CrashScanner::VerifyFileViaCatalog(LPCWSTR filePath)
{
    try {

        auto it = g_catalogCache.find(filePath);
        if (it != g_catalogCache.end())
            return it->second;

        HANDLE hCatAdmin = NULL;
        if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
            return false;

        HANDLE hFile = CreateFileW(
            filePath,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE)
        {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        DWORD hashSize = 0;
        CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0);

        std::vector<BYTE> hash(hashSize);
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0))
        {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        CloseHandle(hFile);

        bool isCatalogSigned = false;

        HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin,
            hash.data(),
            hashSize,
            0,
            NULL
        );

        while (hCatInfo)
        {
            CATALOG_INFO catInfo = {};
            catInfo.cbStruct = sizeof(catInfo);

            if (CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
            {
                WINTRUST_CATALOG_INFO wtc = {};
                wtc.cbStruct = sizeof(wtc);
                wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
                wtc.pbCalculatedFileHash = hash.data();
                wtc.cbCalculatedFileHash = hashSize;
                wtc.pcwszMemberFilePath = filePath;

                WINTRUST_DATA wtd = {};
                wtd.cbStruct = sizeof(wtd);
                wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
                wtd.pCatalog = &wtc;
                wtd.dwUIChoice = WTD_UI_NONE;
                wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                LONG res = WinVerifyTrust(NULL, &action, &wtd);

                wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &action, &wtd);

                if (res == ERROR_SUCCESS)
                {
                    isCatalogSigned = true;
                    break;
                }
            }

            hCatInfo = CryptCATAdminEnumCatalogFromHash(
                hCatAdmin,
                hash.data(),
                hashSize,
                0,
                &hCatInfo
            );
        }

        if (hCatInfo)
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

        CryptCATAdminReleaseContext(hCatAdmin, 0);

        g_catalogCache[filePath] = isCatalogSigned;
        return isCatalogSigned;
    }
    catch (...) {}
    return false;
}

bool CrashScanner::ShouldIgnoreExecutable(const std::wstring& path)
{
    try {
        if (!CrashScanner::IsAbsoluteWindowsPath(path))
            return true;

        if (VerifyFileViaCatalog(path.c_str()))
            return true;

        return false;
    }
    catch (...) {}
    return false;
}


bool CrashScanner::IsAbsoluteWindowsPath(const std::wstring& path)
{
    try {
        if (path.length() < 3)
            return false;

        wchar_t drive = path[0];
        if ((drive < L'A' || drive > L'Z') && (drive < L'a' || drive > L'z'))
            return false;

        return path[1] == L':' && path[2] == L'\\';
    }
    catch (...) {}
    return false;
}

bool CrashScanner::GetCrashLocalTimeFromDump(const char* dumpPath, SYSTEMTIME& outLocalTime)
{
    try {
        ZeroMemory(&outLocalTime, sizeof(outLocalTime));

        HANDLE hFile = CreateFileA(dumpPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping)
        {
            CloseHandle(hFile);
            return false;
        }

        void* base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!base)
        {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        MINIDUMP_DIRECTORY* dir = nullptr;
        void* stream = nullptr;
        ULONG streamSize = 0;

        if (!MiniDumpReadDumpStream(base, MiscInfoStream, &dir, &stream, &streamSize))
        {
            UnmapViewOfFile(base);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        MINIDUMP_MISC_INFO* misc = static_cast<MINIDUMP_MISC_INFO*>(stream);

        if (!(misc->Flags1 & MINIDUMP_MISC1_PROCESS_TIMES))
        {
            UnmapViewOfFile(base);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        ULONGLONG ull =
            (static_cast<ULONGLONG>(misc->ProcessCreateTime) + 11644473600ULL) * 10000000ULL;

        FILETIME ftUtc;
        ftUtc.dwLowDateTime = static_cast<DWORD>(ull);
        ftUtc.dwHighDateTime = static_cast<DWORD>(ull >> 32);

        FILETIME ftLocal;
        FileTimeToLocalFileTime(&ftUtc, &ftLocal);
        FileTimeToSystemTime(&ftLocal, &outLocalTime);

        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return true;
    }
    catch (...) {}
    return false;
}

bool CrashScanner::GetExecutablePathFromDump(const char* dumpPath, std::string& outExePath)
{
    try {
        outExePath.clear();

        HANDLE hFile = CreateFileA(
            dumpPath,
            GENERIC_READ,
            FILE_SHARE_READ,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr
        );

        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        HANDLE hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!hMapping)
        {
            CloseHandle(hFile);
            return false;
        }

        void* base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
        if (!base)
        {
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        MINIDUMP_DIRECTORY* dir = nullptr;
        void* stream = nullptr;
        ULONG streamSize = 0;

        if (!MiniDumpReadDumpStream(base, ModuleListStream, &dir, &stream, &streamSize))
        {
            UnmapViewOfFile(base);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        auto* moduleList = static_cast<MINIDUMP_MODULE_LIST*>(stream);
        if (moduleList->NumberOfModules == 0)
        {
            UnmapViewOfFile(base);
            CloseHandle(hMapping);
            CloseHandle(hFile);
            return false;
        }

        const MINIDUMP_MODULE& mainModule = moduleList->Modules[0];
        const MINIDUMP_STRING* moduleName =
            reinterpret_cast<const MINIDUMP_STRING*>(
                reinterpret_cast<const BYTE*>(base) + mainModule.ModuleNameRva
                );

        int len = WideCharToMultiByte(
            CP_ACP,
            0,
            moduleName->Buffer,
            -1,
            nullptr,
            0,
            nullptr,
            nullptr
        );

        if (len > 0)
        {
            outExePath.resize(len - 1);
            WideCharToMultiByte(
                CP_ACP,
                0,
                moduleName->Buffer,
                -1,
                &outExePath[0],
                len,
                nullptr,
                nullptr
            );
        }

        UnmapViewOfFile(base);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return !outExePath.empty();
    }
    catch (...) {}
    return false;
}

void CrashScanner::ScanFileDumps()
{
    try {
        char localAppData[MAX_PATH] = {};
        if (!GetEnvironmentVariableA(xorstr_("LOCALAPPDATA"), localAppData, MAX_PATH))
            return;

        std::string baseDir = std::string(localAppData) + xorstr_("\\CrashDumps\\");
        std::string searchPath = baseDir + xorstr_("*.dmp");

        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE)
            return;

        do
        {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                continue;

            std::string dumpPath = baseDir + fd.cFileName;
            std::string exePath;
            SYSTEMTIME st = {};

            if (!GetExecutablePathFromDump(dumpPath.c_str(), exePath))
                continue;

            std::string timeStr = xorstr_("N/A");
            FILETIME ft = {};

            if (GetCrashLocalTimeFromDump(dumpPath.c_str(), st))
            {
                std::ostringstream oss;
                oss << std::setfill('0')
                    << std::setw(4) << st.wYear << xorstr_("-")
                    << std::setw(2) << st.wMonth << xorstr_("-")
                    << std::setw(2) << st.wDay << xorstr_(" ")
                    << std::setw(2) << st.wHour << xorstr_(":")
                    << std::setw(2) << st.wMinute << xorstr_(":")
                    << std::setw(2) << st.wSecond;

                timeStr = oss.str();
                SystemTimeToFileTime(&st, &ft);
            }

            std::wstring wideExe(exePath.begin(), exePath.end());

            if (ShouldIgnoreExecutable(wideExe))
                continue;

            auto it = s_crashes.find(exePath);
            if (it == s_crashes.end() || IsNewer(ft, it->second.time))
            {
                s_crashes[exePath] = { ft, exePath, timeStr };
            }

        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);
    }
    catch (...) {}
}

std::wstring CrashScanner::ExtractBetween(
    const std::wstring& src,
    const std::wstring& start,
    const std::wstring& end)
{
    try {
        size_t s = src.find(start);
        if (s == std::wstring::npos)
            return xorstr_(L"");

        s += start.length();
        size_t e = src.find(end, s);
        if (e == std::wstring::npos)
            return xorstr_(L"");

        return src.substr(s, e - s);
    }
    catch (...) {}
    return L"";
}

std::wstring CrashScanner::ConvertUtcToLocal(const std::wstring& utc)
{
    try {
        SYSTEMTIME utcSt = {}, localSt = {};

        swscanf_s(
            utc.c_str(),
            xorstr_(L"%4hu-%2hu-%2huT%2hu:%2hu:%2hu"),
            &utcSt.wYear,
            &utcSt.wMonth,
            &utcSt.wDay,
            &utcSt.wHour,
            &utcSt.wMinute,
            &utcSt.wSecond
        );

        SystemTimeToTzSpecificLocalTime(nullptr, &utcSt, &localSt);

        wchar_t buf[64];
        swprintf_s(
            buf,
            xorstr_(L"%04hu-%02hu-%02hu %02hu:%02hu:%02hu"),
            localSt.wYear,
            localSt.wMonth,
            localSt.wDay,
            localSt.wHour,
            localSt.wMinute,
            localSt.wSecond
        );

        return buf;
    }
    catch (...) {}
    return L"";
}

void CrashScanner::ScanEventLog()
{
    try {
        EVT_HANDLE hQuery = EvtQuery(
            nullptr,
            xorstr_(L"Application"),
                xorstr_(L"*[System[(EventID=1000)]]"),
            EvtQueryChannelPath | EvtQueryForwardDirection
        );

        if (!hQuery)
            return;

        EVT_HANDLE events[8];
        DWORD returned = 0;

        while (EvtNext(hQuery, 8, events, INFINITE, 0, &returned))
        {
            for (DWORD i = 0; i < returned; i++)
            {
                DWORD used = 0, props = 0;

                EvtRender(nullptr, events[i], EvtRenderEventXml, 0, nullptr, &used, &props);
                if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used == 0)
                {
                    EvtClose(events[i]);
                    continue;
                }

                std::vector<wchar_t> buffer(used / sizeof(wchar_t));
                if (!EvtRender(nullptr, events[i], EvtRenderEventXml, used, buffer.data(), &used, &props))
                {
                    EvtClose(events[i]);
                    continue;
                }

                std::wstring xml(buffer.data());

                std::wstring appPath = ExtractBetween(
                    xml,
                    xorstr_(L"<Data Name='AppPath'>"),
                        xorstr_(L"</Data>")
                );

                std::wstring utcTime = ExtractBetween(
                    xml,
                    xorstr_(L"<TimeCreated SystemTime='"),
                        xorstr_(L"'/>")
                );

                if (appPath.empty() || utcTime.empty())
                {
                    EvtClose(events[i]);
                    continue;
                }

                if (ShouldIgnoreExecutable(appPath))
                {
                    EvtClose(events[i]);
                    continue;
                }

                std::wstring localTime = ConvertUtcToLocal(utcTime);
                if (localTime.empty())
                {
                    EvtClose(events[i]);
                    continue;
                }

                SYSTEMTIME st = {};
                int parsed = swscanf_s(
                    localTime.c_str(),
                    xorstr_(L"%4hu-%2hu-%2hu %2hu:%2hu:%2hu"),
                    &st.wYear,
                    &st.wMonth,
                    &st.wDay,
                    &st.wHour,
                    &st.wMinute,
                    &st.wSecond
                );

                if (parsed != 6)
                {
                    EvtClose(events[i]);
                    continue;
                }

                FILETIME ft = {};
                if (!SystemTimeToFileTime(&st, &ft))
                {
                    EvtClose(events[i]);
                    continue;
                }

                std::string exe = ascii_wstring_to_string(appPath);
                std::string timeStr = ascii_wstring_to_string(localTime);

                auto it = s_crashes.find(exe);
                if (it == s_crashes.end() || IsNewer(ft, it->second.time))
                {
                    s_crashes[exe] = { ft, exe, timeStr };
                }

                EvtClose(events[i]);
            }
        }

        EvtClose(hQuery);
    }
    catch (...) {}
}

void CrashScanner::CheckDumpFolder()
{
    try {
        char localAppData[MAX_PATH] = {};
        if (!GetEnvironmentVariableA(xorstr_("LOCALAPPDATA"), localAppData, MAX_PATH))
            return;

        std::string path = std::string(localAppData) + xorstr_("\\CrashDumps");
        DWORD attrs = GetFileAttributesA(path.c_str());

        if (attrs == INVALID_FILE_ATTRIBUTES || !(attrs & FILE_ATTRIBUTE_DIRECTORY))
        {
                LOG ( INFO , xorstr_("N/A")) << xorstr_("CrashDump Folder Is Not Present");
        }
    }
    catch (...) {}
}

bool CrashScanner::HasValidSignature(const wchar_t* filePath)
{
    try {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA wd{};
        wd.cbStruct = sizeof(wd);
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &fileInfo;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG result = WinVerifyTrust(NULL, &action, &wd);

        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wd);

        if (result == ERROR_SUCCESS)
            return true;

        HCATADMIN hCatAdmin = NULL;
        if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
            return false;

        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        DWORD hashSize = 0;
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0))
        {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        std::vector<BYTE> hash(hashSize);
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0))
        {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
        CloseHandle(hFile);

        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(catInfo);

        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hash.data(), hashSize, 0, NULL);

        bool valid = false;

        while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
        {
            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct = sizeof(wci);
            wci.pcwszCatalogFilePath = catInfo.wszCatalogFile;
            wci.pbCalculatedFileHash = hash.data();
            wci.cbCalculatedFileHash = hashSize;
            wci.pcwszMemberFilePath = filePath;

            WINTRUST_DATA catWd{};
            catWd.cbStruct = sizeof(catWd);
            catWd.dwUnionChoice = WTD_CHOICE_CATALOG;
            catWd.pCatalog = &wci;
            catWd.dwUIChoice = WTD_UI_NONE;
            catWd.fdwRevocationChecks = WTD_REVOKE_NONE;
            catWd.dwStateAction = WTD_STATEACTION_VERIFY;

            GUID catAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG catResult = WinVerifyTrust(NULL, &catAction, &catWd);

            catWd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &catAction, &catWd);

            if (catResult == ERROR_SUCCESS)
            {
                valid = true;
                break;
            }

            hCatInfo = CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash.data(), hashSize, 0, &hCatInfo);
        }

        if (hCatInfo)
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

        CryptCATAdminReleaseContext(hCatAdmin, 0);

        return valid;
    }
    catch (...) { return false; }
}

void CrashScanner::PrintResults()
{
    try {
        for (const auto& kv : s_crashes)
        {
            const CrashRecord& r = kv.second;
            std::wstring widePath(r.exePath.begin(), r.exePath.end());

            bool exists = GetFileAttributesW(widePath.c_str()) != INVALID_FILE_ATTRIBUTES;

            if (!exists)
            {
                LOG(INFO, r.formattedTime) << xorstr_("Crashed File Not Present:") << r.exePath;
                continue;
            }

            if (HasValidSignature(widePath.c_str()))
                continue;

            LOG(WARNING, r.formattedTime) << xorstr_("Suspicious Crashed File:") << r.exePath;
        }
    }
    catch (...) {}
}

void CrashScanner::start_crashdump_checks()
{
    CrashScanner::ScanFileDumps();
    CrashScanner::ScanEventLog();
    CrashScanner::PrintResults();
    CrashScanner::CheckDumpFolder();
    return;
}