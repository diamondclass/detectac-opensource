#include "c_hosts_and_prefetch.h"

void hosts_and_prefetch::prefetch_detection() {
    try{
    const char* folderPath = xorstr_("C:\\Windows\\Prefetch");

    DWORD attributes = GetFileAttributesA(folderPath);

    if (attributes == INVALID_FILE_ATTRIBUTES) {
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Prefetch Folder Is Not Present");
    }

    return;
    }
    catch (...) {}
}

void hosts_and_prefetch::hosts_check() {
    try{
    const char* hostsPath = xorstr_("C:\\Windows\\System32\\drivers\\etc\\hosts");

    ULONGLONG uptime_ms = GetTickCount64();
    FILETIME ftNow;
    GetSystemTimeAsFileTime(&ftNow);

    ULONGLONG now64 = ((ULONGLONG)ftNow.dwHighDateTime << 32) | ftNow.dwLowDateTime;

    ULONGLONG boot64 = now64 - (uptime_ms * 10000ULL);

    FILETIME ftBoot;
    ftBoot.dwLowDateTime = (DWORD)boot64;
    ftBoot.dwHighDateTime = (DWORD)(boot64 >> 32);

    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExA(hostsPath, GetFileExInfoStandard, &fileInfo)) {
        return;
    }

    ULONGLONG lastWrite64 = ((ULONGLONG)fileInfo.ftLastWriteTime.dwHighDateTime << 32)
        | fileInfo.ftLastWriteTime.dwLowDateTime;

    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&fileInfo.ftLastWriteTime, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    if (lastWrite64 > boot64) {
        LOG ( WARNING , xorstr_("N/A")) << xorstr_("The hosts file has been modified:(This could indicate manual changes or tampering to bypass.)");
    }

    prefetch_detection();

    return;
    }
    catch (...) {}
}

void hosts_and_prefetch::start_hosts_and_prefetch() {
    try{

    hosts_and_prefetch::prefetch_detection();

    hosts_and_prefetch::hosts_check();

    return;
    }
    catch (...) {}
}