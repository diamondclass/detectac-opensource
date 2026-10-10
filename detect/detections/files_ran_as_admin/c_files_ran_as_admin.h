#pragma once

#include "../../pch.h"

class AppInfoScanner
{
public:
    static void start_files_ran_with_admin();

private:
    static bool enable_debug_privilege();
    static DWORD get_appinfo_pid();
    static void scan_process_memory(HANDLE process);
    static void check_string(const std::string& s);
    static std::string sanitize_path(const std::string& s);
    static bool has_valid_catalogue_signature(const wchar_t* filePath);
    static std::regex path_regex;
    static std::unordered_set<std::string> found_paths;
};

inline auto c_adminran = std::make_unique<AppInfoScanner>();
