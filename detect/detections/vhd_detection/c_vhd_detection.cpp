#include "c_vhd_detection.h"

std::wstring EventLogHelper::ConvertFileTimeToLocalTimeString(FILETIME ft) {
    try{
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    std::wstringstream wss;
    wss << std::setfill(L'0')
        << std::setw(2) << stLocal.wMonth << xorstr_(L"/")
        << std::setw(2) << stLocal.wDay << xorstr_(L"/")
        << std::setw(4) << stLocal.wYear << xorstr_(L" ")
        << std::setw(2) << stLocal.wHour << xorstr_(L":")
        << std::setw(2) << stLocal.wMinute << xorstr_(L":")
        << std::setw(2) << stLocal.wSecond;

    return wss.str();
    }
    catch (...) { return L""; }
}

FILETIME EventLogHelper::GetUserLogonTime() {
    try{
    ULONG sessionCount = 0;
    PLUID sessions = nullptr;

    if (LsaEnumerateLogonSessions(&sessionCount, &sessions) != 0) {
        return {};
    }

    FILETIME logonTime = {};
    for (ULONG i = 0; i < sessionCount; ++i) {
        PSECURITY_LOGON_SESSION_DATA sessionData = nullptr;
        if (LsaGetLogonSessionData(&sessions[i], &sessionData) == 0 && sessionData != nullptr) {
            if (sessionData->LogonType == Interactive || sessionData->LogonType == RemoteInteractive) {
                logonTime.dwHighDateTime = sessionData->LogonTime.HighPart;
                logonTime.dwLowDateTime = sessionData->LogonTime.LowPart;
                LsaFreeReturnBuffer(sessionData);
                break;
            }
            LsaFreeReturnBuffer(sessionData);
        }
    }

    LsaFreeReturnBuffer(sessions);

    FILETIME start_time = {};
    FileTimeToLocalFileTime(&logonTime, &start_time);

    return start_time;
    }
    catch (...) { return {}; }
}

void EventLogHelper::DisplayEvent(EVT_HANDLE hEvent, const FILETIME& userLogonTime) {
    try{
    DWORD status = ERROR_SUCCESS;
    EVT_HANDLE hContext = NULL;
    DWORD dwBufferSize = 0;
    DWORD dwBufferUsed = 0;
    DWORD dwPropertyCount = 0;
    PEVT_VARIANT pRenderedValues = NULL;

    hContext = EvtCreateRenderContext(0, NULL, EvtRenderContextSystem);
    if (!hContext) return;

    if (!EvtRender(hContext, hEvent, EvtRenderEventValues, 0, NULL, &dwBufferSize, &dwPropertyCount)) {
        status = GetLastError();
        if (ERROR_INSUFFICIENT_BUFFER != status) goto cleanup;

        pRenderedValues = (PEVT_VARIANT)malloc(dwBufferSize);
        if (!pRenderedValues) goto cleanup;

        if (!EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferSize, pRenderedValues, &dwBufferUsed, &dwPropertyCount)) {
            goto cleanup;
        }
    }

    if (pRenderedValues) {
        FILETIME ft;
        ft.dwLowDateTime = (DWORD)(pRenderedValues[EvtSystemTimeCreated].FileTimeVal & 0xFFFFFFFF);
        ft.dwHighDateTime = (DWORD)(pRenderedValues[EvtSystemTimeCreated].FileTimeVal >> 32);

        std::wstring timeStr = ConvertFileTimeToLocalTimeString(ft);
        WORD eventId = pRenderedValues[EvtSystemEventID].UInt16Val;

        std::wstring statusStr;
        int compareResult = CompareFileTime(&ft, &userLogonTime);
        if (compareResult < 0) {
            statusStr = xorstr_(L"Before Logon");
        }
        else {
            statusStr = xorstr_(L"After Logon");
        }

        LOG ( WARNING , utils->convert_wstring_to_string(timeStr)) << xorstr_("Virtual Disk Deleted ")
            << statusStr;
    }

cleanup:
    if (hContext) EvtClose(hContext);
    if (pRenderedValues) free(pRenderedValues);
    }
    catch (...) {}
}

void EventLogHelper::QueryEvents(const FILETIME& userLogonTime) {
    try{
    EVT_HANDLE hResults = NULL;
    LPWSTR pwsPath = const_cast<LPWSTR>(xorstr_(L"Microsoft-Windows-VHDMP-Operational"));
    LPWSTR pwsQuery = const_cast<LPWSTR>(xorstr_(L"Event/System[EventID=26]"));

    hResults = EvtQuery(NULL, pwsPath, pwsQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hResults) return;

    EVT_HANDLE hEvent = NULL;
    while (true) {
        DWORD dwReturned = 0;
        if (hEvent) {
            EvtClose(hEvent);
            hEvent = NULL;
        }

        if (!EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) break;
            continue;
        }

        if (dwReturned == 0) break;

        DisplayEvent(hEvent, userLogonTime);
    }

    if (hEvent) EvtClose(hEvent);
    if (hResults) EvtClose(hResults);
    }
    catch (...) {}
}

void EventLogHelper::Run() {
    try{
    FILETIME userLogonTime = GetUserLogonTime();

    if (userLogonTime.dwLowDateTime == 0 && userLogonTime.dwHighDateTime == 0) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        SystemTimeToFileTime(&st, &userLogonTime);
    }

    QueryEvents(userLogonTime);
    }
    catch (...) {}
}

void EventLogHelper::start_vhd_detection() {
    try{
    EventLogHelper::Run();
    }
    catch (...) {}
}