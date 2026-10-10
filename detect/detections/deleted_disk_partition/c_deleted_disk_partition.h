#pragma once

#include "../../pch.h"

class c_deleted_disk_partition
{
public:
	static std::wstring format_timestamp_to_local ( const FILETIME& file_time );
	static FILETIME get_user_logon_time ( );
	static bool parse_iso_timestamp ( const std::wstring& iso_timestamp , FILETIME& file_time );
	static void display_event_if_after_logon ( EVT_HANDLE event_handle , const FILETIME& logon_time , std::set<std::wstring>& displayed_timestamps );
	static void query_device_management_log ( );
	static void start_deleted_part_checks ( );
};

inline auto c_deleted_disk_part = std::make_unique<c_deleted_disk_partition> ( );

