#pragma once

#include "../../pch.h"

class LuaScanner {
public:
    static std::string ScanForMaliciousScripts();
    static std::string fixPath(const std::string& path);
    static bool hasSuspiciousStrings(const std::string& filePath);
    static void start_luascripts_scan();
};

inline auto c_luascripts = std::make_unique<LuaScanner>();