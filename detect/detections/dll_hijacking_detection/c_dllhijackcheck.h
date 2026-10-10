#pragma once

#include "../../pch.h"

class dll_hijack_scan {
public:

	static bool fileExists(const std::string& filePath);

	static void start_dllh_scan();

	static void check_xbox_gamebar_hijack();

};

inline auto c_dllh = std::make_unique<dll_hijack_scan>();