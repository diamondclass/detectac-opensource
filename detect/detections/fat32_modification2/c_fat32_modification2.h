#pragma once

#include "../../pch.h"

class c_fat32_modification2
{
public:
	static bool enable_debug_privilege ( );
	static DWORD get_process_id_by_name ( const std::string& process_name );
	static bool has_valid_extension ( const std::wstring& file_path );
	static std::vector<std::wstring> get_fat32_drives ( );
	static bool is_private_memory_region ( const MEMORY_BASIC_INFORMATION& mbi );
	static void search_for_unicode_strings ( const wchar_t* buffer , SIZE_T size , const std::wstring& drive_letter );
	static void search_for_ascii_strings ( const char* buffer , SIZE_T size , const std::string& drive_letter );
	static void scan_memory_for_drive ( DWORD process_id , const std::wstring& drive_letter );

	static void start_fat32_2_modification_check ( );
};

inline auto c_fat32_2 = std::make_unique<c_fat32_modification2> ( );


