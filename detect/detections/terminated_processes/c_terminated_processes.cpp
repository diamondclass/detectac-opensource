#include "c_terminated_processes.h"

std::string ServiceTerminationWatcher::FormatEventTime(ULONGLONG evtFileTime) {
    try{
    ULARGE_INTEGER uli;
    uli.QuadPart = evtFileTime;

    FILETIME ft;
    ft.dwLowDateTime = uli.LowPart;
    ft.dwHighDateTime = uli.HighPart;

    SYSTEMTIME stUTC, stLocal;
    if (!FileTimeToSystemTime(&ft, &stUTC)) return xorstr_("0000-00-00 00:00:00");
    if (!SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal)) return xorstr_("0000-00-00 00:00:00");

    std::stringstream ss;
    ss << stLocal.wYear << xorstr_("-")
        << std::setfill('0') << std::setw(2) << stLocal.wMonth << xorstr_("-")
        << std::setfill('0') << std::setw(2) << stLocal.wDay << xorstr_(" ")
        << std::setfill('0') << std::setw(2) << stLocal.wHour << xorstr_(":")
        << std::setfill('0') << std::setw(2) << stLocal.wMinute << xorstr_(":")
        << std::setfill('0') << std::setw(2) << stLocal.wSecond;
    return ss.str();
    }
    catch (...) { return ""; }
}

void ServiceTerminationWatcher::ProcessEvent(PEVT_VARIANT pValues) {
    try{
    if (pValues[1].Type != EvtVarTypeBinary || pValues[1].BinaryVal == nullptr) return;

    std::wstring ws(reinterpret_cast<const wchar_t*>(pValues[1].BinaryVal), pValues[1].Count / sizeof(wchar_t));
    size_t last = ws.find_last_not_of(L'\0');
    if (last != std::wstring::npos) ws.resize(last + 1);

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &ws[0], (int)ws.size(), NULL, 0, NULL, NULL);
    std::string serviceName(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &ws[0], (int)ws.size(), &serviceName[0], size_needed, NULL, NULL);

    static const std::set<std::string> allowed = { xorstr_("EventLog"), xorstr_("DPS"), xorstr_("SysMain") };

    if (allowed.find(serviceName) != allowed.end()) {
        std::string timeStr = xorstr_("0000-00-00 00:00:00");

        if (pValues[0].Type == EvtVarTypeFileTime) {
            timeStr = FormatEventTime(pValues[0].FileTimeVal);
        }

        LOG ( DETECTION, timeStr ) << serviceName << xorstr_(" Has Been Terminated:Bypass Attempt");
    }
    }
    catch (...) {}
}

void ServiceTerminationWatcher::StartTerminationCheck() {
    try {
        EVT_HANDLE hResults = NULL, hContext = NULL;

        hResults = EvtQuery(NULL, xorstr_(L"System"), xorstr_(L"*[System[(EventID=7031)]]"), EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!hResults) return;

        const wchar_t* valuePaths[] = {
            xorstr_(L"Event/System/TimeCreated/@SystemTime"),
            xorstr_(L"Event/EventData/Binary")
        };

        hContext = EvtCreateRenderContext(2, valuePaths, EvtRenderContextValues);
        if (!hContext) {
            EvtClose(hResults);
            return;
        }

        EVT_HANDLE hEvent = NULL;
        DWORD dwReturned = 0;

        while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned)) {
            DWORD dwBufferUsed = 0, dwPropertyCount = 0;

            EvtRender(hContext, hEvent, EvtRenderEventValues, 0, NULL, &dwBufferUsed, &dwPropertyCount);

            std::vector<BYTE> buffer(dwBufferUsed);
            if (EvtRender(hContext, hEvent, EvtRenderEventValues, dwBufferUsed, buffer.data(), &dwBufferUsed, &dwPropertyCount)) {
                ProcessEvent(reinterpret_cast<PEVT_VARIANT>(buffer.data()));
            }
            EvtClose(hEvent);
        }

        if (hContext) EvtClose(hContext);
        if (hResults) EvtClose(hResults);
    }
    catch (...) {}
}