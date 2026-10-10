#pragma once

#include "../../../pch.h"

class cdiscordcan {
public:
    static bool enable_debug_privilege();
    static std::vector<DWORD> get_pids_by_process_name(const std::string& proc_name);
    static void scan_process_memory(HANDLE hProcess);

    static std::vector<std::pair<std::string, std::string>> get_custom_filters_only();
    static bool apply_filter(const std::string& memory_string, const std::pair<std::string, std::string>& filter, bool is_custom);
    static void start_discord_scan();
};

inline auto c_discord = std::make_unique<cdiscordcan>();
