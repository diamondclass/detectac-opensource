#pragma once

#include <memory>
#include "../../pch.h"

class c_fat32_modification
{
public:
	static void print_event_details(EVT_HANDLE event_handle,
		const FILETIME& explorer_start_time, FILETIME& latest_time, bool& found_latest);

	static void start_fat32_modification_check ( );
};
inline auto c_fat32 = std::make_unique<c_fat32_modification> ( );

