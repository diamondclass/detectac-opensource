#include "c_cleared_eventlog.h"


std::string cleared_eventlog::wstring_to_string(const std::wstring& wide_str)
{
    try{
    int size_required = WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_required == 0) return xorstr_("");

    std::string result(size_required - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide_str.c_str(), -1, &result[0], size_required, nullptr, nullptr);
    return result;
    }
    catch (...) { return ""; }
}

std::wstring cleared_eventlog::formatTimestampToLocal(const std::wstring& rawTimestamp)
{
    try{
    SYSTEMTIME systemTimeUTC = {};
    std::swscanf(
        rawTimestamp.c_str(),
        xorstr_( L"%4hd-%2hd-%2hdT%2hd:%2hd:%2hd" ),
        &systemTimeUTC.wYear,
        &systemTimeUTC.wMonth,
        &systemTimeUTC.wDay,
        &systemTimeUTC.wHour,
        &systemTimeUTC.wMinute,
        &systemTimeUTC.wSecond
    );

    SYSTEMTIME systemTimeLocal = {};
    if (!SystemTimeToTzSpecificLocalTime(nullptr, &systemTimeUTC, &systemTimeLocal))
    {
        return xorstr_(L"");
    }

    wchar_t formattedTimestamp[20];
    swprintf(
        formattedTimestamp,
        sizeof(formattedTimestamp) / sizeof(wchar_t),
        xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
        systemTimeLocal.wYear,
        systemTimeLocal.wMonth,
        systemTimeLocal.wDay,
        systemTimeLocal.wHour,
        systemTimeLocal.wMinute,
        systemTimeLocal.wSecond
    );

    return std::wstring(formattedTimestamp);
    }
    catch (...) { return L""; }
}

SYSTEMTIME cleared_eventlog::getPCStartTimeLocal()
{
    try{
    ULONG sessionCount = 0;
    PLUID sessions = nullptr;

    if (LsaEnumerateLogonSessions(&sessionCount, &sessions) != 0)
    {
        return {};
    }

    FILETIME logonTime = {};
    for (ULONG i = 0; i < sessionCount; ++i)
    {
        PSECURITY_LOGON_SESSION_DATA sessionData = nullptr;

        if (LsaGetLogonSessionData(&sessions[i], &sessionData) == 0 && sessionData != nullptr)
        {
            if (sessionData->LogonType == Interactive || sessionData->LogonType == RemoteInteractive)
            {
                logonTime.dwHighDateTime = sessionData->LogonTime.HighPart;
                logonTime.dwLowDateTime = sessionData->LogonTime.LowPart;

                LsaFreeReturnBuffer(sessionData);
                break;
            }

            LsaFreeReturnBuffer(sessionData);
        }
    }

    LsaFreeReturnBuffer(sessions);

    FILETIME localLogonTime = {};
    FileTimeToLocalFileTime(&logonTime, &localLogonTime);

    SYSTEMTIME systemLogonTime = {};
    FileTimeToSystemTime(&localLogonTime, &systemLogonTime);

    return systemLogonTime;
    }
    catch (...) { SYSTEMTIME st = {}; return st; }
}

bool cleared_eventlog::isTimestampAfterPCStart(const std::wstring& rawTimestamp, const SYSTEMTIME& pcStartTime)
{
    try{
    SYSTEMTIME eventTime = {};
    std::swscanf(
        rawTimestamp.c_str(),
        xorstr_(L"%4hd-%2hd-%2hdT%2hd:%2hd:%2hd"),
        &eventTime.wYear,
        &eventTime.wMonth,
        &eventTime.wDay,
        &eventTime.wHour,
        &eventTime.wMinute,
        &eventTime.wSecond
    );

    FILETIME eventFileTime, startFileTime;
    SystemTimeToFileTime(&eventTime, &eventFileTime);
    SystemTimeToFileTime(&pcStartTime, &startFileTime);

    ULONGLONG eventTimeULL = ((ULONGLONG)eventFileTime.dwHighDateTime << 32) | eventFileTime.dwLowDateTime;
    ULONGLONG startTimeULL = ((ULONGLONG)startFileTime.dwHighDateTime << 32) | startFileTime.dwLowDateTime;

    return eventTimeULL > startTimeULL;
    }
    catch (...) { return false; }
}

void cleared_eventlog::extractImportantData(const std::wstring& xmlData, const SYSTEMTIME& pcStartTime)
{
    try{
    std::wregex timeRegex(xorstr_(L"SystemTime='([^']+)'"));
    std::wregex channelRegex(xorstr_(L"<Channel>([^<]+)</Channel>"));

    std::wsmatch match;

    std::wsregex_iterator begin(xmlData.begin(), xmlData.end(), channelRegex);
    std::wsregex_iterator end;

    std::wstring channel;
    std::wstring formattedTimestamp;

    int channelCount = 0;
    for (std::wsregex_iterator i = begin; i != end; ++i)
    {
        ++channelCount;
        if (channelCount == 2)
        {
            channel = (*i)[1].str();
        }
    }

    bool is_critical_channel = (channel == xorstr_(L"System") || channel == xorstr_(L"Windows PowerShell"));

    if (std::regex_search(xmlData, match, timeRegex))
    {
        std::wstring rawTimestamp = match[1].str();
        formattedTimestamp = formatTimestampToLocal(rawTimestamp);

        if (isTimestampAfterPCStart(rawTimestamp, pcStartTime))
        {
            if (is_critical_channel)
            {
                LOG(DETECTION, wstring_to_string(formattedTimestamp))
                    << xorstr_("Cleared EventLog Since Logon: ") << channel;
            }
            else
            {
                LOG(WARNING, wstring_to_string(formattedTimestamp))
                    << xorstr_("Cleared EventLog Since Logon: ") << channel;
            }
        }
        else
        {
            LOG(INFO, wstring_to_string(formattedTimestamp))
                << xorstr_("Cleared EventLog Before Logon: ") << channel;
        }
    }
    }
    catch (...) {}
}


void cleared_eventlog::displayEventDetails(EVT_HANDLE eventHandle, const SYSTEMTIME& pcStartTime)
{
    try{
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;
    std::vector<wchar_t> xmlBuffer;

    EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferSize, nullptr, &bufferUsed, &propertyCount);

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        bufferSize = bufferUsed;
        xmlBuffer.resize(bufferSize);

        if (EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferSize, xmlBuffer.data(), &bufferUsed, &propertyCount))
        {
            extractImportantData(xmlBuffer.data(), pcStartTime);
        }
        else
        {
        }
    }
    else
    {
    }
    }
    catch (...) {}
}

void cleared_eventlog::querySystemEventLog()
{
    try{
    EVT_HANDLE logHandle = nullptr;
    EVT_HANDLE queryHandle = nullptr;
    EVT_HANDLE eventHandle = nullptr;
    DWORD returned = 0;

    SYSTEMTIME pcStartTime = getPCStartTimeLocal();

    logHandle = EvtOpenLog(nullptr, xorstr_(L"C:\\Windows\\System32\\winevt\\Logs\\System.evtx"), EvtOpenFilePath);
    if (!logHandle)
    {
        return;
    }

    const wchar_t* query = xorstr_(L"*[System/EventID=104]");

    queryHandle = EvtQuery(nullptr, xorstr_(L"C:\\Windows\\System32\\winevt\\Logs\\System.evtx"), query, EvtQueryFilePath);
    if (!queryHandle)
    {
        EvtClose(logHandle);
        return;
    }

    while (EvtNext(queryHandle, 1, &eventHandle, INFINITE, 0, &returned))
    {
        displayEventDetails(eventHandle, pcStartTime);
        EvtClose(eventHandle);
    }

    if (GetLastError() != ERROR_NO_MORE_ITEMS)
    {
    }

    EvtClose(queryHandle);
    EvtClose(logHandle);
    }
    catch (...) {}
}

void cleared_eventlog::start_cleared_eventlog()
{
    try{
    cleared_eventlog eventLog;
    eventLog.querySystemEventLog();
    }
    catch (...) {}
}