#pragma once

#include "../../../pch.h"

class junc_scan
{
public:

	static std::string convert_wstring_to_string(const std::wstring& wstr);
	static std::string parse_reason(DWORD reason);
	static std::string convert_file_time_to_string(const LARGE_INTEGER& file_time);
	static bool read_usn_journal(const std::string& drive_letter, std::atomic<bool>& found_flag);
	static void start_junc_scan();

};

inline auto c_junc = std::make_unique<junc_scan>();