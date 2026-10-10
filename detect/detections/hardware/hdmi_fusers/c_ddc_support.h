#pragma once

#include "../../../pch.h"

class c_ddc_support
{
public:

	static BOOL CALLBACK MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData);

	static void start_ddc_scan();

};

inline auto c_ddc = std::make_unique<c_ddc_support>();