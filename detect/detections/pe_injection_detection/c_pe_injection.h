#pragma once

#include "../../pch.h"

class peinjectionscan {

public:

	static std::wstring GetCustomMessage(const std::wstring& path);
	static std::wstring ToLower(const std::wstring& str);
	static void start_pe_scan();

};

inline auto c_peinj = std::make_unique<peinjectionscan>();