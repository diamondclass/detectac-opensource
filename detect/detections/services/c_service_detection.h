#pragma once

#include "../../pch.h"

class c_service_detection
{
public:
	static std::string file_time_to_string ( const FILETIME& ft );
	static bool enable_all_privileges ( );
	static bool get_process_start_time ( DWORD process_id , const std::string& process_name );
	static DWORD get_process_id_by_name ( const std::string& process_name );
	static void get_service_start_time ( const std::string& service_name );
	static void start_service_checks ( );

};

inline auto c_service = std::make_unique<c_service_detection> ( );
