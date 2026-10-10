#pragma once

#include "../../../pch.h"

class c_commands_ran_2
{
public:

	static std::string toLower(const std::string& input);
	static bool containsKeyword(const std::string& line, const std::vector<std::string>& keywords);
	static void scanFile(const std::string& filePath, const std::vector<std::string>& keywords);
	static void start_commands2();
};

inline auto c_commands2 = std::make_unique<c_commands_ran_2>();