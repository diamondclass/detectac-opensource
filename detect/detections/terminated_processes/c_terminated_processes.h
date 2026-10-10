#pragma once

#include "../../pch.h"

class ServiceTerminationWatcher final
{
public:
    static void StartTerminationCheck();

    static std::string FormatEventTime(ULONGLONG evtFileTime);
    static void ProcessEvent(PEVT_VARIANT pValues);
};

inline auto c_term_ser = std::make_unique<ServiceTerminationWatcher>();