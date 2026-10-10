#pragma once

#include "../../pch.h"

class steam_alt {
public:
    static void ProcessLoginUsersFile(const std::string& filePath);
    static bool Is17DigitNumber(const std::string& str);
    static std::string RemoveKeywords(const std::string& line, const std::vector<std::string>& keywords);
    static std::string RemoveQuotes(const std::string& line);
    static void start_steam_alt_detection();
};

inline auto c_steam_alt = std::make_unique<steam_alt>();