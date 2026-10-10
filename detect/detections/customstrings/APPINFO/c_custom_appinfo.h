#pragma once

#include "../../../pch.h"

class cappinfoscan {
public:
    static bool enable_debug_privilege();
    static DWORD get_process_id_by_name(const std::string& service_name);
    static void scan_process_memory(HANDLE h_process);
    static bool apply_filter(const std::string& memory_string, const std::pair<std::string, std::string>& filter, bool is_custom);
    static std::vector<std::pair<std::string, std::string>> get_custom_filters_only();
    static void start_appinfo_scan();
};

inline auto c_capp = std::make_unique<cappinfoscan>();