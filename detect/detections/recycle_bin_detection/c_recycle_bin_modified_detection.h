#pragma once

#include "../../pch.h"

class c_recycle_bin_modified_detection
{
public:
	static std::wstring file_time_to_string_local ( const FILETIME& ft );
	static std::wstring get_current_user_sid ( );
	static FILETIME get_pc_start_time ( );

	static void start_recycle_bin_modified_checks ( );

};

inline auto c_recycle_bin_modified = std::make_unique<c_recycle_bin_modified_detection> ( );

