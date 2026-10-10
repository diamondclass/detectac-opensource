#include "c_enableprefetcher_delete.h"

FILETIME PrefetchCheck::GetRegistryKeyLastWriteTime()
{
    try {
        HKEY hKey = nullptr;

        LONG result = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"),
            0, KEY_READ, &hKey);
        if (result != ERROR_SUCCESS)
            return {};

        FILETIME ftLastWrite{};
        result = RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr,
                                  nullptr, nullptr, nullptr, nullptr, nullptr, &ftLastWrite);
        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS)
            return {};

        return ftLastWrite;
    }
    catch (...) { return {}; }
}

FILETIME PrefetchCheck::GetUserLogonTime()
{
    try {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
            return {};

        TOKEN_STATISTICS tokenStats{};
        DWORD cbReturned = 0;
        if (!GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &cbReturned)) {
            CloseHandle(hToken);
            return {};
        }
        CloseHandle(hToken);

        LUID logonId = tokenStats.AuthenticationId;

        PSECURITY_LOGON_SESSION_DATA pSessionData = nullptr;
        NTSTATUS status = LsaGetLogonSessionData(&logonId, &pSessionData);
        if (status != 0)
            return {};

        LARGE_INTEGER liLogonTime = pSessionData->LogonTime;
        LsaFreeReturnBuffer(pSessionData);

        FILETIME ftLogon{};
        ftLogon.dwLowDateTime  = liLogonTime.LowPart;
        ftLogon.dwHighDateTime = static_cast<DWORD>(liLogonTime.HighPart);

        return ftLogon;
    }
    catch (...) { return {}; }
}

LONGLONG PrefetchCheck::FileTimeToInt64(const FILETIME& ft)
{
    try {
        ULARGE_INTEGER ul;
        ul.LowPart  = ft.dwLowDateTime;
        ul.HighPart = ft.dwHighDateTime;
        return static_cast<LONGLONG>(ul.QuadPart);
    }
    catch (...) { return 0; }
}

bool PrefetchCheck::IsAfterOneMinute(const FILETIME& ftLastWrite, const FILETIME& ftLogon)
{
    try {
        constexpr LONGLONG oneMinuteIn100ns = 60LL * 10'000'000LL;

        LONGLONG diff = FileTimeToInt64(ftLastWrite) - FileTimeToInt64(ftLogon);

        return diff > oneMinuteIn100ns;
    }
    catch (...) { return false; }
}

std::string PrefetchCheck::FormatFileTimeAsLocal(const FILETIME& ftUtc)
{
    try {
        FILETIME ftLocal{};
        FileTimeToLocalFileTime(&ftUtc, &ftLocal);

        SYSTEMTIME st{};
        FileTimeToSystemTime(&ftLocal, &st);

        std::ostringstream oss;
        oss << std::setfill('0')
            << std::setw(4) << st.wYear << xorstr_("-")
            << std::setw(2) << st.wMonth << xorstr_("-")
            << std::setw(2) << st.wDay << xorstr_(" ")
            << std::setw(2) << st.wHour << xorstr_(":")
            << std::setw(2) << st.wMinute << xorstr_(":")
            << std::setw(2) << st.wSecond;
        return oss.str();
    }
    catch (...) { return ""; }
}

void PrefetchCheck::start_enableprefetcherdeletion()
{
    try {
        FILETIME ftLastWrite = GetRegistryKeyLastWriteTime();
        FILETIME ftLogon = GetUserLogonTime();

        if (IsAfterOneMinute(ftLastWrite, ftLogon)) {
            LOG(DETECTION, FormatFileTimeAsLocal(ftLastWrite)) << xorstr_("Prefetch Bypass:EnablePrefetcher Has Been Modified/Deleted & Re-Created ");
        }
    }
    catch (...) {
    }
}
