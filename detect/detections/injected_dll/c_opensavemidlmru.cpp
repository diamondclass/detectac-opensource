#include "c_opensavemidlmru.h"


void c_opensavepidlmru::PrintAsciiValue(const BYTE* data, DWORD dataSize, const std::string& timestamp) {
    try {
        WCHAR path[MAX_PATH] = { 0 };

        if (c_utils::safe_pidl_path(data, dataSize, path) && path[0] != L'\0') {
            char narrowPath[MAX_PATH * 2] = { 0 };
            WideCharToMultiByte(CP_UTF8, 0, path, -1, narrowPath, sizeof(narrowPath), NULL, NULL);
            if (!timestamp.empty())
                LOG(WARNING, timestamp) << xorstr_("Previously Injected Dll:") << narrowPath;
            else
                LOG(WARNING, xorstr_("N/A")) << xorstr_("Previously Injected Dll:") << narrowPath;
            return;
        }

        std::string asciiString;
        bool containsPrintableChar = false;

        for (DWORD i = 0; i < dataSize; ++i) {
            if (std::isprint(data[i])) {
                asciiString += static_cast<char>(data[i]);
                containsPrintableChar = true;
            }
        }

        if (containsPrintableChar) {
            if (!timestamp.empty())
                LOG(WARNING, timestamp) << xorstr_("Previously Injected Dll:") << asciiString;
            else
                LOG(WARNING, xorstr_("N/A")) << xorstr_("Previously Injected Dll:") << asciiString;
        }
    }
    catch (...) {}
}

void c_opensavepidlmru::start_opensavemidlmru_scan() {
    try {
    HKEY hKey;
    LPCWSTR registryPath = xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU\\dll");

    if (RegOpenKeyExW(HKEY_CURRENT_USER, registryPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    FILETIME ftLastWrite = { 0 };
    RegQueryInfoKeyW(hKey, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ftLastWrite);

    std::string lastWriteTimestamp;
    SYSTEMTIME stUTC = { 0 }, stLocal = { 0 };
    if (FileTimeToSystemTime(&ftLastWrite, &stUTC) && SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) {
        char timeBuf[64] = { 0 };
        snprintf(timeBuf, sizeof(timeBuf), xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            stLocal.wYear, stLocal.wMonth, stLocal.wDay,
            stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
        lastWriteTimestamp = timeBuf;
    }

    BYTE mruData[1024] = { 0 };
    DWORD mruDataSize = sizeof(mruData);
    DWORD mruType = 0;
    DWORD mostRecentIndex = MAXDWORD;

    if (RegQueryValueExW(hKey, xorstr_(L"MRUListEx"), NULL, &mruType, mruData, &mruDataSize) == ERROR_SUCCESS
        && mruType == REG_BINARY && mruDataSize >= sizeof(DWORD)) {
        mostRecentIndex = *reinterpret_cast<DWORD*>(mruData);
    }

    DWORD index = 0;
    WCHAR valueName[256];
    DWORD valueNameSize;
    BYTE data[1024];
    DWORD dataSize;
    DWORD type;

    while (true) {
        valueNameSize = sizeof(valueName) / sizeof(valueName[0]);
        dataSize = sizeof(data);

        LONG result = RegEnumValueW(hKey, index, valueName, &valueNameSize, NULL, &type, data, &dataSize);

        if (result == ERROR_NO_MORE_ITEMS) {
            break;
        }

        if (result == ERROR_SUCCESS && type == REG_BINARY && valueNameSize > 0 && std::iswdigit(valueName[0])) {
            DWORD entryIndex = wcstoul(valueName, NULL, 10);
            bool isMostRecent = (entryIndex == mostRecentIndex);
            c_opensavepidlmru::PrintAsciiValue(data, dataSize, isMostRecent ? lastWriteTimestamp : "");
        }

        ++index;
    }

    RegCloseKey(hKey);
    }
    catch (...) {}
}
