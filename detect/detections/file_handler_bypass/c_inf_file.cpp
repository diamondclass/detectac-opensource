#include "c_inf_file.h"
#include "../install_time/c_windows_install_date.h"

#define KEY_PATH xorstr_(L"inffile\\shell\\open\\command")
#define EXPECTED_VALUE xorstr_(L"%SystemRoot%\\System32\\NOTEPAD.EXE %1")

std::string INFBypass::WideToNarrow(const std::wstring& wide) {
    try {
        if (wide.empty()) return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return {};
        std::string out(needed, '\0');
        if (!WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), (int)wide.size(), out.data(), needed, nullptr, nullptr))
            return {};
        return out;
    }
    catch (...) {
        return {};
    }
}

bool INFBypass::GetKeyLastWriteTime(HKEY hKey, FILETIME& ftOut) {
    try {
        ftOut = {};
        LONG res = RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &ftOut);
        return (res == ERROR_SUCCESS);
    }
    catch (...) {
        ftOut = {};
        return false;
    }
}

ULONGLONG INFBypass::FileTimeToULL(const FILETIME& ft) {
    try {
        ULARGE_INTEGER ul;
        ul.LowPart = ft.dwLowDateTime;
        ul.HighPart = ft.dwHighDateTime;
        return ul.QuadPart;
    }
    catch (...) {
        return 0;
    }
}

bool INFBypass::GetSystemBootFileTime(ULONGLONG& bootHnsOut) {
    try {
        ULONGLONG tickMs = GetTickCount64();
        FILETIME nowFt;
        GetSystemTimeAsFileTime(&nowFt);
        ULONGLONG nowHns = FileTimeToULL(nowFt);
        if (nowHns == 0) return false;
        bootHnsOut = nowHns - (tickMs * 10000ULL);
        return true;
    }
    catch (...) {
        bootHnsOut = 0;
        return false;
    }
}

bool INFBypass::FileTimeToLocalString(const FILETIME& ftUtc, std::string& out) {
    try {
        FILETIME ftLocal;
        if (!FileTimeToLocalFileTime(&ftUtc, &ftLocal)) return false;
        SYSTEMTIME st;
        if (!FileTimeToSystemTime(&ftLocal, &st)) return false;

        char buf[64];
        sprintf_s(buf, xorstr_("%02d/%02d/%04d %02d:%02d:%02d"),
            st.wDay, st.wMonth, st.wYear,
            st.wHour, st.wMinute, st.wSecond);
        out = buf;
        return true;
    }
    catch (...) {
        out.clear();
        return false;
    }
}

bool INFBypass::ReadDefaultValueRaw(HKEY hKey, std::wstring& out) {
    try {
        out.clear();
        DWORD type = 0, size = 0;
        LONG res = RegQueryValueExW(hKey, xorstr_(L""), nullptr, &type, nullptr, &size);
        if (res != ERROR_SUCCESS || size == 0) return false;
        if (type != REG_SZ && type != REG_EXPAND_SZ) return false;

        out.resize(size / sizeof(wchar_t), L'\0');
        res = RegQueryValueExW(hKey, xorstr_(L""), nullptr, nullptr, reinterpret_cast<LPBYTE>(out.data()), &size);
        if (res != ERROR_SUCCESS) { out.clear(); return false; }

        if (!out.empty() && out.back() == L'\0')
            out.pop_back();
        return true;
    }
    catch (...) {
        out.clear();
        return false;
    }
}

bool INFBypass::OpenRegistryKey(HKEY root, const wchar_t* path, HKEY& hKeyOut) {
    try {
        hKeyOut = nullptr;
        LONG res = RegOpenKeyExW(root, path, 0, KEY_READ, &hKeyOut);
        return (res == ERROR_SUCCESS && hKeyOut != nullptr);
    }
    catch (...) {
        hKeyOut = nullptr;
        return false;
    }
}

void INFBypass::CloseRegistryKey(HKEY& hKey) {
    try {
        if (hKey) { RegCloseKey(hKey); hKey = nullptr; }
    }
    catch (...) {
        hKey = nullptr;
    }
}

std::wstring INFBypass::ExpandEnvVars(const std::wstring& input) {
    try {
        DWORD needed = ExpandEnvironmentStringsW(input.c_str(), nullptr, 0);
        if (needed == 0) return input;
        std::wstring expanded(needed, L'\0');
        DWORD written = ExpandEnvironmentStringsW(input.c_str(), expanded.data(), needed);
        if (written == 0 || written > needed) return input;
        if (!expanded.empty() && expanded.back() == L'\0')
            expanded.pop_back();
        return expanded;
    }
    catch (...) {
        return input;
    }
}

void INFBypass::CheckINFBypass() {
    try {
        HKEY hKey = nullptr;
        if (!OpenRegistryKey(HKEY_CLASSES_ROOT, KEY_PATH, hKey))
            return;

        std::wstring defaultVal;
        bool gotValue = ReadDefaultValueRaw(hKey, defaultVal);

        FILETIME lastWrite{};
        bool gotTime = GetKeyLastWriteTime(hKey, lastWrite);

        CloseRegistryKey(hKey);

        if (gotTime) {
            FILETIME nowFt;
            GetSystemTimeAsFileTime(&nowFt);
            ULONGLONG nowHns = FileTimeToULL(nowFt);
            ULONGLONG writeHns = FileTimeToULL(lastWrite);

            ULONGLONG bootHns = 0;
            bool gotBoot = GetSystemBootFileTime(bootHns);

            ULONGLONG twentyFourH = 24ULL * 60 * 60 * 10000000ULL;
            ULONGLONG threshold = nowHns - twentyFourH;

            if (gotBoot && bootHns < threshold)
                threshold = bootHns;

            if (writeHns >= threshold) {
                bool near_install = false;
                DWORD install_date = system_install_info::get_install_date();
                if (install_date != 0)
                {
                    ULONGLONG install_filetime =
                        (static_cast<ULONGLONG>(install_date) + 11644473600ULL) * 10000000ULL;
                    ULONGLONG diff =
                        (writeHns > install_filetime)
                        ? (writeHns - install_filetime)
                        : (install_filetime - writeHns);
                    const ULONGLONG six_hours = 6ULL * 60 * 60 * 10000000ULL;
                    if (diff <= six_hours)
                        near_install = true;
                }

                if (!near_install) {
                    std::string timeStr;
                    FileTimeToLocalString(lastWrite, timeStr);
                    LOG ( DETECTION , timeStr) << xorstr_("INF Bypass Found:INF File Edited To Launch Bypass");
                }
            }
        }

        std::wstring expandedExpected = ExpandEnvVars(EXPECTED_VALUE);
        std::wstring expandedActual = gotValue ? ExpandEnvVars(defaultVal) : std::wstring();

        if (gotValue && _wcsicmp(expandedActual.c_str(), expandedExpected.c_str()) != 0) {
            LOG ( DETECTION , xorstr_("N/A")) << xorstr_("INF Bypass Found:INF File Changed ") << WideToNarrow(defaultVal);
        }

    }
    catch (...) {
    }
}
