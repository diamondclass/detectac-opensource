#pragma once

#include "../../pch.h"

class MSIBypass
{
public:
    static void CheckMSIBypass();

private:
    static std::string WideToNarrow(const std::wstring& wide);
    static bool GetKeyLastWriteTime(HKEY hKey, FILETIME& ftOut);
    static ULONGLONG FileTimeToULL(const FILETIME& ft);
    static bool GetSystemBootFileTime(ULONGLONG& bootHnsOut);
    static bool FileTimeToLocalString(const FILETIME& ftUtc, std::string& out);
    static bool ReadDefaultValueRaw(HKEY hKey, std::wstring& out);
    static bool OpenRegistryKey(HKEY root, const wchar_t* path, HKEY& hKeyOut);
    static void CloseRegistryKey(HKEY& hKey);
    static std::wstring ExpandEnvVars(const std::wstring& input);
};

inline auto c_msi = std::make_unique<MSIBypass>();
