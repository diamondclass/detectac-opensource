#pragma once

#include "../pch.h"

namespace FreshInstall {

constexpr long long kGraceSeconds = 24LL * 60LL * 60LL;

inline long long RegistryInstallEpoch() noexcept
{
    try {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
                          0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS)
            return 0;

        DWORD value = 0;
        DWORD size = sizeof(value);
        DWORD type = 0;
        const LONG r = RegQueryValueExW(hKey, xorstr_(L"InstallDate"), nullptr, &type,
                                        reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(hKey);

        if (r != ERROR_SUCCESS || type != REG_DWORD) return 0;
        if (value < 1000000000UL) return 0;
        return static_cast<long long>(value);
    }
    catch (...) { return 0; }
}

inline long long WindowsDirectoryEpoch() noexcept
{
    try {
        wchar_t winDir[MAX_PATH] = {};
        if (GetWindowsDirectoryW(winDir, MAX_PATH) == 0) return 0;

        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(winDir, GetFileExInfoStandard, &fad)) return 0;

        ULARGE_INTEGER ull{};
        ull.LowPart  = fad.ftCreationTime.dwLowDateTime;
        ull.HighPart = fad.ftCreationTime.dwHighDateTime;
        if (ull.QuadPart < 116444736000000000ULL) return 0;

        return static_cast<long long>(ull.QuadPart / 10000000ULL - 11644473600ULL);
    }
    catch (...) { return 0; }
}

inline long long SecondsSinceInstall() noexcept
{
    try {
        const long long now = static_cast<long long>(std::time(nullptr));

        const long long sources[] = { WindowsDirectoryEpoch(), RegistryInstallEpoch() };

        long long best = -1;
        for (long long t : sources) {
            if (t <= 0) continue;

            long long age = now - t;
            if (age < 0) age = -age;

            if (best < 0 || age < best) best = age;
        }
        return best;
    }
    catch (...) { return -1; }
}

inline bool WithinGrace(long long graceSeconds = kGraceSeconds) noexcept
{
    try {
        const long long age = SecondsSinceInstall();
        if (age < 0) return false;
        return age < graceSeconds;
    }
    catch (...) { return false; }
}

}
