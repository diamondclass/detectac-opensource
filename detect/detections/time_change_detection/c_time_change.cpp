#include "c_time_change.h"

struct SystemTimeHash {
    std::size_t operator()(const SYSTEMTIME& st) const {
        return std::hash<int>()(st.wYear) ^ std::hash<int>()(st.wMonth) ^ std::hash<int>()(st.wDay) ^
            std::hash<int>()(st.wHour) ^ std::hash<int>()(st.wMinute) ^ std::hash<int>()(st.wSecond);
    }
};

struct SystemTimeEqual {
    bool operator()(const SYSTEMTIME& st1, const SYSTEMTIME& st2) const {
        return st1.wYear == st2.wYear && st1.wMonth == st2.wMonth && st1.wDay == st2.wDay &&
            st1.wHour == st2.wHour && st1.wMinute == st2.wMinute && st1.wSecond == st2.wSecond;
    }
};

std::unordered_set<SYSTEMTIME, SystemTimeHash, SystemTimeEqual> displayedEvents;

FILETIME SystemTimeToFileTimeHelper(const SYSTEMTIME& st) {
    try{
    FILETIME ft = {};
    SystemTimeToFileTime(&st, &ft);
    return ft;
    }
    catch (...) {}
}

SYSTEMTIME timechangeread::GetUserLogonTime() {
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

    FILETIME localLogonTime = {};
    FileTimeToLocalFileTime(&logonTime, &localLogonTime);

    SYSTEMTIME systemLogonTime = {};
    FileTimeToSystemTime(&localLogonTime, &systemLogonTime);

    return systemLogonTime;
    }
    catch (...) {}
}

void timechangeread::ReadAllEvents() {
    try{
    SYSTEMTIME logonTime = GetUserLogonTime();
    if (logonTime.wYear == 0) {
        return;
    }

    EVT_HANDLE logHandle = EvtQuery(nullptr, LogFilePath(), nullptr, EvtQueryFilePath | EvtQueryForwardDirection);

    if (!logHandle) {
        return;
    }

    while (true) {
        EVT_HANDLE eventHandles[10];
        DWORD returned = 0;

        if (!EvtNext(logHandle, 10, eventHandles, INFINITE, 0, &returned)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                break;
            }
            else {
                break;
            }
        }

        for (DWORD i = 0; i < returned; ++i) {
            ProcessEvent(eventHandles[i], logonTime);
            EvtClose(eventHandles[i]);
        }
    }

    EvtClose(logHandle);
    }
    catch (...) {}
}

int CompareSystemTimes(const SYSTEMTIME* st1, const SYSTEMTIME* st2) {
    try{
    FILETIME ft1 = SystemTimeToFileTimeHelper(*st1);
    FILETIME ft2 = SystemTimeToFileTimeHelper(*st2);
    return CompareFileTime(&ft1, &ft2);
    }
    catch (...) {}
}

void timechangeread::ProcessEvent(EVT_HANDLE eventHandle, const SYSTEMTIME& userLogonTime) {
    try{
    DWORD bufferSize = 0;
    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    if (!EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferSize, nullptr, &bufferUsed, &propertyCount)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            bufferSize = bufferUsed;
            std::vector<wchar_t> buffer(bufferSize);

            if (EvtRender(nullptr, eventHandle, EvtRenderEventXml, bufferSize, buffer.data(), &bufferUsed, &propertyCount)) {
                std::wstring eventXml(buffer.data());

                if (eventXml.find(xorstr_(L"<Version>4</Version>")) != std::wstring::npos ||
                    eventXml.find(xorstr_(L"<Version>2</Version>")) != std::wstring::npos) {
                    if (eventXml.find(xorstr_(L"1</EventID>")) != std::wstring::npos) {
                        std::wstring timestamp = ExtractTimestamp(eventXml);

                        if (!timestamp.empty()) {
                            SYSTEMTIME eventTime = { 0 };
                            swscanf_s(timestamp.c_str(), xorstr_(L"%4hu/%2hu/%2hu %2hu:%2hu:%2hu"),
                                &eventTime.wYear, &eventTime.wMonth, &eventTime.wDay,
                                &eventTime.wHour, &eventTime.wMinute, &eventTime.wSecond);

                            if (CompareSystemTimes(&eventTime, &userLogonTime) > 0) {
                                if (displayedEvents.find(eventTime) == displayedEvents.end()) {
                                    LOG(INFO, utils->convert_wstring_to_string(ConvertUtcToLocalTime(eventTime))) << xorstr_(" Time Change: The user has changed their system time, this could be used to spoof modification dates.");
                                    displayedEvents.insert(eventTime);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    }
    catch (...) {}
}

std::wstring timechangeread::ExtractTimestamp(const std::wstring& xml) {
    try{
    std::wstring searchStr = xorstr_(L"<TimeCreated SystemTime='");
    size_t start = xml.find(searchStr);

    if (start == std::wstring::npos) {
        return xorstr_(L"");
    }

    start += searchStr.length();
    size_t end = xml.find(xorstr_(L"'"), start);

    if (end == std::wstring::npos) {
        return xorstr_(L"");
    }

    std::wstring utcTimestamp = xml.substr(start, end - start);

    SYSTEMTIME utcTime = { 0 };
    swscanf_s(utcTimestamp.c_str(), xorstr_(L"%4hu-%2hu-%2huT%2hu:%2hu:%2hu"),
        &utcTime.wYear, &utcTime.wMonth, &utcTime.wDay,
        &utcTime.wHour, &utcTime.wMinute, &utcTime.wSecond);

    return ConvertUtcToLocalTime(utcTime);
    }
    catch (...) {}
    return {};
}

std::wstring timechangeread::ConvertUtcToLocalTime(const SYSTEMTIME& utcTime) {
    try{
    SYSTEMTIME localTime = { 0 };

    if (SystemTimeToTzSpecificLocalTime(NULL, &utcTime, &localTime)) {
        std::wostringstream formattedTime;
        formattedTime << std::setfill(L'0') << std::setw(4) << localTime.wYear << xorstr_(L"/")
            << std::setw(2) << localTime.wMonth << xorstr_(L"/")
            << std::setw(2) << localTime.wDay << xorstr_(L" ")
            << std::setw(2) << localTime.wHour << xorstr_(L":")
            << std::setw(2) << localTime.wMinute << xorstr_(L":")
            << std::setw(2) << localTime.wSecond;

        return formattedTime.str();
    }

    return xorstr_(L"");
    }
    catch (...) {}
    return {};
}

void timechangeread::start_timechange() {
    try{
    timechangeread::ReadAllEvents();
    return;
    }
    catch (...) {}
}
