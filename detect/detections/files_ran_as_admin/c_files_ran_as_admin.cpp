#include "c_files_ran_as_admin.h"

#define MIN_STRING_LENGTH 4

std::unordered_set<std::string> AppInfoScanner::found_paths;

std::regex AppInfoScanner::path_regex(
    xorstr_(R"(^[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]+\.[A-Za-z0-9]{1,10}$)"),
    std::regex_constants::icase
);

bool AppInfoScanner::enable_debug_privilege()
{
    try {
    HANDLE token;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;

    LUID luid;
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid))
    {
        CloseHandle(token);
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);

    CloseHandle(token);

    return result && GetLastError() != ERROR_NOT_ALL_ASSIGNED;
    }
    catch (...) { return false; }
}

DWORD AppInfoScanner::get_appinfo_pid()
{
    try {
    SC_HANDLE scm = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return 0;

    SC_HANDLE service = OpenServiceA(scm, xorstr_("Appinfo"), SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp{};
    DWORD bytes_needed;

    if (!QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes_needed))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(scm);
        return 0;
    }

    DWORD pid = ssp.dwProcessId;

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return pid;
    }
    catch (...) { return 0; }
}

std::string AppInfoScanner::sanitize_path(const std::string& s)
{
    try {
    std::string out;

    for (char c : s)
    {
        if (std::isalnum((unsigned char)c) ||
            c == '\\' || c == ':' || c == '.' ||
            c == '_' || c == '-' || c == '$' ||
            c == ' ' || c == '(' || c == ')')
        {
            out += c;
        }
        else
        {
            break;
        }
    }

    while (!out.empty() && out.back() == ' ')
        out.pop_back();

    return out;
    }
    catch (...) { return ""; }
}

bool AppInfoScanner::has_valid_catalogue_signature(const wchar_t* filePath)
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

    BYTE* hash = new BYTE[hashSize];
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash, 0))
    {
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

    while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0))
    {
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

        if (catResult == ERROR_SUCCESS)
        {
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

void AppInfoScanner::check_string(const std::string& s)
{
    try
    {
        if (s.size() < 3)
            return;

        if (!std::isalpha((unsigned char)s[0]) || s[1] != ':' || s[2] != '\\')
            return;

        std::string clean = sanitize_path(s);

        if (!std::regex_match(clean, path_regex))
            return;

        std::string lower_clean = clean;
        std::transform(lower_clean.begin(), lower_clean.end(), lower_clean.begin(), ::tolower);

        if (lower_clean == xorstr_("c:\\autoexec.bat"))
            return;

        if (!found_paths.insert(clean).second)
            return;

        std::wstring wide_path(clean.begin(), clean.end());

        if (GetFileAttributesW(wide_path.c_str()) == INVALID_FILE_ATTRIBUTES)
            return;

        size_t dot = lower_clean.find_last_of('.');
        if (dot == std::string::npos)
            return;

        std::string ext = lower_clean.substr(dot);

        if (ext != xorstr_(".exe") && ext != xorstr_(".dll") &&
            ext != xorstr_(".bat") && ext != xorstr_(".cmd") &&
            ext != xorstr_(".py") && ext != xorstr_(".cpl") &&
            ext != xorstr_(".msc") && ext != xorstr_(".ocx") &&
            ext != xorstr_(".com") && ext != xorstr_(".ps1"))
            return;

        if (has_valid_catalogue_signature(wide_path.c_str()))
            return;

        LOG ( WARNING , xorstr_("N/A")) << xorstr_("Suspicious File Executed As Administrator Since Logon:") << clean;
    }
    catch (...) {}
}

void AppInfoScanner::scan_process_memory(HANDLE process)
{
    try {
    MEMORY_BASIC_INFORMATION mbi{};
    unsigned char buffer[65536];
    SIZE_T bytes_read;

    for (unsigned char* address = 0;
        VirtualQueryEx(process, address, &mbi, sizeof(mbi)) == sizeof(mbi);
        address += mbi.RegionSize)
    {
        if (mbi.State != MEM_COMMIT)
            continue;

        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            continue;

        for (unsigned char* addr = (unsigned char*)mbi.BaseAddress;
            addr < (unsigned char*)mbi.BaseAddress + mbi.RegionSize;
            addr += sizeof(buffer))
        {
            if (!ReadProcessMemory(process, addr, buffer, sizeof(buffer), &bytes_read))
                continue;

            std::string ascii;

            for (SIZE_T i = 0; i < bytes_read; i++)
            {
                if (std::isprint(buffer[i]))
                    ascii += buffer[i];
                else
                {
                    if (ascii.length() >= MIN_STRING_LENGTH)
                        check_string(ascii);

                    ascii.clear();
                }
            }

            if (ascii.length() >= MIN_STRING_LENGTH)
                check_string(ascii);

            std::wstring wide;

            for (SIZE_T i = 0; i < bytes_read - 1; i += 2)
            {
                wchar_t wc = *(wchar_t*)&buffer[i];

                if (wc >= 0x20 && wc <= 0x7E)
                    wide += wc;
                else
                {
                    if (wide.length() >= MIN_STRING_LENGTH)
                    {
                        std::string converted = ascii_wstring_to_string(wide);
                        check_string(converted);
                    }

                    wide.clear();
                }
            }

            if (wide.length() >= MIN_STRING_LENGTH)
            {
                std::string converted = ascii_wstring_to_string(wide);
                check_string(converted);
            }
        }
    }
    }
    catch (...) {}
}

void AppInfoScanner::start_files_ran_with_admin()
{
    try {
    if (!enable_debug_privilege())
        return;

    DWORD pid = get_appinfo_pid();

    if (!pid)
        return;

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (!process)
        return;

    scan_process_memory(process);

    CloseHandle(process);
    }
    catch (...) {}
}