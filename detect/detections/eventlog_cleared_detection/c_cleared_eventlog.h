#pragma once

#include "../../pch.h"

class cleared_eventlog
{
public:
    static std::string wstring_to_string(const std::wstring& wide_str);
    static void querySystemEventLog();
    static std::wstring formatTimestampToLocal(const std::wstring& rawTimestamp);
    static SYSTEMTIME getPCStartTimeLocal();
    static bool isTimestampAfterPCStart(const std::wstring& rawTimestamp, const SYSTEMTIME& pcStartTime);
    static void extractImportantData(const std::wstring& xmlData, const SYSTEMTIME& pcStartTime);
    static void displayEventDetails(EVT_HANDLE eventHandle, const SYSTEMTIME& pcStartTime);
    static void start_cleared_eventlog();
};


inline auto c_cleared_evt = std::make_unique<cleared_eventlog>();