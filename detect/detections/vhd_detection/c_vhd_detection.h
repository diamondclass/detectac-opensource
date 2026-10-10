#pragma once

#include "../../pch.h"

class EventLogHelper {
public:
    static void Run();

    static std::wstring ConvertFileTimeToLocalTimeString(FILETIME ft);
    static FILETIME GetUserLogonTime();
    static void QueryEvents(const FILETIME& userLogonTime);
    static void DisplayEvent(EVT_HANDLE hEvent, const FILETIME& userLogonTime);
    static void start_vhd_detection();
};

inline auto c_vhd = std::make_unique<EventLogHelper>();