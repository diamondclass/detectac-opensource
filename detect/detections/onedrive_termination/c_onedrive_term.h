#pragma once

#include "../../pch.h"

class onedrive_term
{
public:

	static bool terminate_process_by_name(const std::wstring& process_name);

	static void term_onedrive();

};

inline auto c_tone = std::make_unique<onedrive_term>();