#pragma once

#include "../../../pch.h"

class MonitorEDID {
public:
    static void GetMonitorEDID();
    static bool ValidateEDIDChecksum(const std::vector<uint8_t>& edid);
    static void PrintManufacturerID(const std::vector<uint8_t>& edid);
    static void ValidateEDID(const std::vector<uint8_t>& edid);
    static void start_hdmifuser_scan();
};

inline auto c_fusers = std::make_unique<MonitorEDID>();