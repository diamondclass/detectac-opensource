#pragma once

#include "../../pch.h"

class ReadOnlyEvtxScanner
{
public:
    static void start_eventlog_bypass();
    static void event_bypass(const std::string& directory);
    ReadOnlyEvtxScanner() = default;
private:
    static void FindReadOnlyEvtx(const std::string& directory,
        std::vector<std::string>& results);
};

inline auto c_evt_byp = std::make_unique<ReadOnlyEvtxScanner>();