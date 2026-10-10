#include "c_dllhijackcheck.h"

auto dll_hijack_scan::fileExists(const std::string& filePath) -> bool {
    try{
    DWORD fileAttr = GetFileAttributesA(filePath.c_str());
    return (fileAttr != INVALID_FILE_ATTRIBUTES && !(fileAttr & FILE_ATTRIBUTE_DIRECTORY));
    }
    catch (...) {}
}

void dll_hijack_scan::start_dllh_scan() {
    try{
    std::string filePath = xorstr_("C:\\Windows\\cscapi.dll");

    if (dll_hijack_scan::fileExists(filePath)) {
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("DLL Hijacking Detected:") << filePath;
    }

    check_xbox_gamebar_hijack();
    return;
    }
    catch (...) {}
}

void dll_hijack_scan::check_xbox_gamebar_hijack() {
    try {
        HKEY hKey = nullptr;
        LONG rc = ::RegOpenKeyExW(
            HKEY_CLASSES_ROOT,
            xorstr_(L"CLSID\\{6db7cd52-e3b7-4ecc-bb1f-388aeef6bb50}\\InProcServer32"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey);
        if (rc != ERROR_SUCCESS || !hKey) return;

        DWORD type = 0;
        DWORD sizeBytes = 0;
        rc = ::RegQueryValueExW(hKey, nullptr, nullptr, &type, nullptr, &sizeBytes);
        if (rc != ERROR_SUCCESS || sizeBytes == 0 ||
            (type != REG_EXPAND_SZ && type != REG_SZ))
        {
            ::RegCloseKey(hKey);
            return;
        }

        std::wstring raw(sizeBytes / sizeof(wchar_t) + 1, L'\0');
        rc = ::RegQueryValueExW(hKey, nullptr, nullptr, &type,
            reinterpret_cast<LPBYTE>(&raw[0]), &sizeBytes);
        ::RegCloseKey(hKey);
        if (rc != ERROR_SUCCESS) return;

        while (!raw.empty() && raw.back() == L'\0') raw.pop_back();
        if (raw.empty()) return;

        wchar_t expandedBuf[MAX_PATH * 4]{};
        DWORD expandedLen = ::ExpandEnvironmentStringsW(
            raw.c_str(), expandedBuf, _countof(expandedBuf));
        std::wstring expanded = (expandedLen > 0 && expandedLen <= _countof(expandedBuf))
            ? std::wstring(expandedBuf) : raw;

        std::wstring lower = expanded;
        for (auto& ch : lower) ch = static_cast<wchar_t>(::towlower(ch));

        const bool okSystem32 =
            lower.size() >= 24 &&
            lower.rfind(xorstr_(L"\\system32\\wpnapps.dll")) == lower.size() - 21;
        const bool okSysWow64 =
            lower.size() >= 24 &&
            lower.rfind(xorstr_(L"\\syswow64\\wpnapps.dll")) == lower.size() - 21;

        if (okSystem32 || okSysWow64) return;

        int len = ::WideCharToMultiByte(CP_UTF8, 0, expanded.c_str(), -1,
            nullptr, 0, nullptr, nullptr);
        std::string narrow(len > 0 ? len - 1 : 0, '\0');
        if (len > 0)
            ::WideCharToMultiByte(CP_UTF8, 0, expanded.c_str(), -1,
                &narrow[0], len, nullptr, nullptr);

        LOG(DETECTION, xorstr_("N/A"))
            << xorstr_("XBOX Game Bar DLL Hijack Found ") << narrow;
    }
    catch (...) {}
}