#include "c_saved_files.h"

bool SavedFiles::IsPEExtension(const std::wstring& path)
{
    try {
        size_t dot = path.rfind(L'.');
        if (dot == std::wstring::npos) return false;
        std::wstring ext = path.substr(dot);
        for (auto& c : ext) c = static_cast<wchar_t>(towlower(c));

        return ext == xorstr_(L".exe") || ext == xorstr_(L".dll") || ext == xorstr_(L".sys") ||
               ext == xorstr_(L".drv") || ext == xorstr_(L".ocx") || ext == xorstr_(L".scr") ||
               ext == xorstr_(L".cpl") || ext == xorstr_(L".efi") || ext == xorstr_(L".mui") ||
               ext == xorstr_(L".tsp") || ext == xorstr_(L".ax")  || ext == xorstr_(L".com");
    }
    catch (...) { return false; }
}

bool SavedFiles::HasMZHeader(const wchar_t* path)
{
    try {
        HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        BYTE hdr[2]{};
        DWORD bytesRead = 0;
        ReadFile(hFile, hdr, 2, &bytesRead, nullptr);
        CloseHandle(hFile);
        return bytesRead == 2 && hdr[0] == 'M' && hdr[1] == 'Z';
    }
    catch (...) { return false; }
}

bool SavedFiles::IsSignedFile(const wchar_t* filePath)
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
        if (hFile == INVALID_HANDLE_VALUE) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        DWORD hashSize = 0;
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0)) {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        BYTE* hash = new BYTE[hashSize];
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0)) {
            delete[] hash;
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
        CloseHandle(hFile);

        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(catInfo);

        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hash, hashSize, 0, NULL);

        bool valid = false;

        while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct = sizeof(wci);
            wci.pcwszCatalogFilePath = catInfo.wszCatalogFile;
            wci.pbCalculatedFileHash = hash;
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

            if (catResult == ERROR_SUCCESS) {
                valid = true;
                break;
            }

            hCatInfo = CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash, hashSize, 0, &hCatInfo);
        }

        if (hCatInfo)
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

        CryptCATAdminReleaseContext(hCatAdmin, 0);
        delete[] hash;

        return valid;
    }
    catch (...) { return false; }
}

std::wstring SavedFiles::FileTimeToString(const FILETIME& ft)
{
    try {
        SYSTEMTIME st, local;
        FileTimeToSystemTime(&ft, &st);
        SystemTimeToTzSpecificLocalTime(nullptr, &st, &local);
        wchar_t buf[32];
        swprintf_s(buf, xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
            local.wYear, local.wMonth, local.wDay,
            local.wHour, local.wMinute, local.wSecond);
        return buf;
    }
    catch (...) { return L""; }
}

std::vector<SavedFiles::SuspectFile> SavedFiles::GetSuspectPEFiles()
{
    std::vector<SuspectFile> results;

    try {
        HKEY hBaseKey;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"), 0, KEY_READ, &hBaseKey) != ERROR_SUCCESS)
            return results;

        std::map<std::wstring, size_t> seen;
        wchar_t subKeyName[256];
        DWORD subKeyIndex = 0;

        while (true) {
            DWORD subKeyNameSize = _countof(subKeyName);
            if (RegEnumKeyExW(hBaseKey, subKeyIndex++, subKeyName, &subKeyNameSize,
                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                break;

            HKEY hSubKey;
            if (RegOpenKeyExW(hBaseKey, subKeyName, 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
                continue;

            try {
                FILETIME lastWriteTime{};
                RegQueryInfoKeyW(hSubKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                    nullptr, nullptr, nullptr, nullptr, &lastWriteTime);
                std::wstring keyTimestamp = FileTimeToString(lastWriteTime);

                DWORD mostRecentIndex = MAXDWORD;
                DWORD mruListSize = 0;
                if (RegQueryValueExW(hSubKey, xorstr_(L"MRUListEx"), nullptr, nullptr, nullptr, &mruListSize) == ERROR_SUCCESS
                    && mruListSize >= sizeof(DWORD)) {
                    std::vector<BYTE> mruData(mruListSize);
                    if (RegQueryValueExW(hSubKey, xorstr_(L"MRUListEx"), nullptr, nullptr, mruData.data(), &mruListSize) == ERROR_SUCCESS) {
                        mostRecentIndex = *reinterpret_cast<DWORD*>(mruData.data());
                    }
                }

                DWORD valueIndex = 0;
                wchar_t valueName[256];

                while (true) {
                    DWORD valueNameSize = _countof(valueName);
                    DWORD dataType = 0, dataSize = 0;

                    if (RegEnumValueW(hSubKey, valueIndex, valueName, &valueNameSize,
                        nullptr, &dataType, nullptr, &dataSize) != ERROR_SUCCESS)
                        break;
                    valueIndex++;

                    if (_wcsicmp(valueName, xorstr_(L"MRUListEx")) == 0) continue;
                    if (dataType != REG_BINARY || dataSize == 0) continue;

                    std::vector<BYTE> data(dataSize);
                    valueNameSize = _countof(valueName);
                    if (RegQueryValueExW(hSubKey, valueName, nullptr, nullptr,
                        data.data(), &dataSize) != ERROR_SUCCESS)
                        continue;

                    if (dataSize > data.size()) continue;

                    PWSTR pszPath = nullptr;
                    HRESULT hr = c_utils::safe_pidl_display_name(data.data(), dataSize, SIGDN_FILESYSPATH, &pszPath);
                    if (FAILED(hr) || !pszPath)
                        hr = c_utils::safe_pidl_display_name(data.data(), dataSize, SIGDN_DESKTOPABSOLUTEPARSING, &pszPath);

                    if (SUCCEEDED(hr) && pszPath) {
                        std::wstring path(pszPath);
                        CoTaskMemFree(pszPath);

                        wchar_t* end = nullptr;
                        unsigned long valueNum = wcstoul(valueName, &end, 10);
                        bool isMostRecent = (end && *end == L'\0' && valueNum == mostRecentIndex);
                        std::wstring ts = isMostRecent ? keyTimestamp : std::wstring(xorstr_(L"N/A"));

                        auto seenIt = seen.find(path);
                        if (seenIt != seen.end()) {
                            if (isMostRecent && seenIt->second < results.size()
                                && results[seenIt->second].timestamp == xorstr_(L"N/A")) {
                                results[seenIt->second].timestamp = ts;
                            }
                            continue;
                        }

                        DWORD attrs = GetFileAttributesW(path.c_str());
                        bool exists = (attrs != INVALID_FILE_ATTRIBUTES);

                        if (exists && (attrs & FILE_ATTRIBUTE_DIRECTORY)) {
                            seen[path] = static_cast<size_t>(-1);
                            continue;
                        }

                        bool isPE = exists ? HasMZHeader(path.c_str()) : IsPEExtension(path);
                        if (!isPE) {
                            seen[path] = static_cast<size_t>(-1);
                            continue;
                        }

                        if (exists) {
                            if (!IsSignedFile(path.c_str())) {
                                seen[path] = results.size();
                                results.push_back({ path, true, false, ts });
                            }
                            else {
                                seen[path] = static_cast<size_t>(-1);
                            }
                        }
                        else {
                            seen[path] = results.size();
                            results.push_back({ path, false, false, ts });
                        }
                    }
                }
            }
            catch (...) {}

            RegCloseKey(hSubKey);
        }
        RegCloseKey(hBaseKey);
    }
    catch (...) {}

    return results;
}

std::string SavedFiles::ToNarrow(const std::wstring& ws)
{
    try {
        if (ws.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
        std::string s(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
        return s;
    }
    catch (...) { return {}; }
}

void SavedFiles::start_saved_files()
{
    try {
        CoInitialize(nullptr);

        auto suspects = GetSuspectPEFiles();

        for (const auto& f : suspects) {
            std::string status = f.onDisk ? xorstr_("Unsigned") : xorstr_("Missing");
            std::string time = ToNarrow(f.timestamp);
            std::string path = ToNarrow(f.path);

            LOG ( INFO , time ) << xorstr_("Downloaded/Saved File ") << status << xorstr_(":") << path;
        }

        CoUninitialize();
    }
    catch (...) {}
}