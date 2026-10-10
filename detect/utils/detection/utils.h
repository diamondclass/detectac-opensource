#pragma once

#include <memory>
#include <string>
#include <regex>
#include <set>
#include <mutex>
#include <curl/curl.h>
#include "../../pch.h"
#include "../thread_pool/thread_pool.h"
#include "../../detections/detection_root.h"
#include <fmt/core.h>
#include <fmt/format.h>

class c_utils
{
public:
	static std::string normalize_path ( const std::string& path );
	static std::string get_known_folder_path ( KNOWNFOLDERID folder_id );
	static std::wstring convert_string_to_wstring ( const std::string& str );
	static std::string convert_wstring_to_string(const std::wstring& wstr);
	static std::string path_to_utf8(const std::filesystem::path& p) noexcept;
	static std::string path_to_utf8(const std::wstring& w) noexcept;
	static std::string convert_filetime_to_local_readable_format ( FILETIME file_time );
	static bool convert_iso8601_to_filetime ( const std::wstring& iso_time , FILETIME* file_time );
	static FILETIME get_logon_time ( );
	static bool is_printable ( wchar_t ch );
	static bool is_well_formed_pidl ( const BYTE* data , size_t size );
	static HRESULT safe_pidl_display_name ( const BYTE* data , size_t size , SIGDN form , PWSTR* name );
	static bool safe_pidl_path ( const BYTE* data , size_t size , wchar_t* path );
	static size_t write_callback ( void* contents , size_t size , size_t nmemb , std::string* s );
	static bool is_vpn ( );
	static bool is_self_scan ( const std::string& pin );
	static std::string generate_api_key ( );
	static bool check_session_exists ( const std::string& pin );
	static void log_startup_time ( );
	static std::wstring convert_utc_to_local ( const std::wstring& utc_timestamp );
	static std::string convert_utc_to_localA ( const std::string& utc_timestamp );
	static std::string sanitize_string ( const std::string& input );
	static std::wstring sanitize_file_name ( const std::wstring& file_name );
	static std::string exec_command ( const std::string& cmd );
	static void exec_command_streamed ( const std::string& cmd , std::function<void ( const std::string& )> line_handler );

	static std::string convert_ole_char_to_string ( OLECHAR* ole_string );

	static void check_server_status ( );
	static bool contains_case_insensitive ( const char* str , const char* substr );
	static std::string generate_random_string(size_t length);
	static auto increment_progress ( ) noexcept -> void;

	static std::vector<std::pair<std::string, std::vector<std::string>>> process_strings;
	
	static std::set<std::string> scanned_files;  
	static std::mutex scanned_files_mutex;

	static bool is_excluded_directory(const std::filesystem::path& path);
	static std::wstring raw_string(const wchar_t* str, size_t length);
	static std::wstring parse_pe_file_with_filters(const std::wstring& file_path);
	static std::wstring sanitize_wstring(const std::wstring& input);

	struct filter {
		std::string output_message;
		std::string section_name;
		DWORD virtual_size;
		DWORD virtual_address;
		DWORD raw_address;
	};

	static const std::vector<filter> filters;
	static bool file_exists(const std::wstring& file_path);
	static bool section_matches_filter(const IMAGE_SECTION_HEADER& section_header, const filter& filter);
	static void unload_registry_hive();
	static void enumerate_registry_values(const std::wstring& sub_key);
};

extern std::unique_ptr<c_utils> utils;
//inline auto utils = std::make_unique<c_utils> ( );
