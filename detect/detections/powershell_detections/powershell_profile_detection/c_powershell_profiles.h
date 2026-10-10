#pragma once

#include "../../../pch.h"

class PowerShellProfileChecker {
public:
    static bool checkProfileExists(const std::string& profilePath);
    static bool containsKeywords(const std::string& content);
    static bool readProfileContents(const std::string& profilePath, std::string& contents);
    static void checkProfiles();
};

inline auto c_powershell_profiles = std::make_unique<PowerShellProfileChecker>();
