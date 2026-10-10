#pragma once

#include "../../pch.h"

class EventLogReader {
public:
    static LPCWSTR LogFilePath() {
        static const std::wstring p = xorstr_(L"C:\\Windows\\System32\\winevt\\Logs\\Application.evtx");
        return p.c_str();
    }

    static void ReadAllEvents();
    static void ProcessEvent(EVT_HANDLE eventHandle, const SYSTEMTIME& userLogonTime);
    static std::wstring ExtractTimestamp(const std::wstring& xml);
    static std::wstring ConvertUtcToLocalTime(const SYSTEMTIME& utcTime);

    static SYSTEMTIME GetUserLogonTime();

    static void start_usn_modified2();
};

inline auto c_usnjrnl2 = std::make_unique<EventLogReader>();