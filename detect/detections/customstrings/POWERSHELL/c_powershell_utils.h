#pragma once

#include "../../../pch.h"
#include "POWERSHELL_NORMAL/c_custom_powershell.h"

class cpowershellmaster
{
public:

	static void start_powershell_scans();

	static void start_powershell();
};

inline auto c_cpowershell = std::make_unique<cpowershellmaster>();