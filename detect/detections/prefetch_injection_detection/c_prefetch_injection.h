#pragma once

#include "../../pch.h"
#include "../prefetch_parser/prefetch_parser.h"

class PrefetchScanner {
public:
    static void start_prefetch_injections();

private:
    static std::string format_last_runtime(time_t t);
    static std::string wstring_to_string(const std::wstring& wstr);
    static bool contains_citizenfx_ini(const std::wstring& wpath);
    static std::wstring get_executable_name_from_data(const std::vector<char>& data);
    static std::wstring get_executable_path(const std::vector<std::wstring>& associated_files, const std::wstring& exe_name);
    static std::vector<char> get_prefetch_data(const std::string& file_path);
    static std::wstring extract_path_from_volume(const std::wstring& volume_path);
    static std::wstring resolve_volume_to_drive(const std::wstring& volume_path);
    static bool contains_blocked_name(const std::wstring& path);
};

inline auto c_prefinj = std::make_unique<PrefetchScanner>();