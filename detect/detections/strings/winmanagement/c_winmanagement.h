#pragma once

#include "../../../pch.h"

class memory_scanner {
public:
    static bool enable_debug_privilege();
    static DWORD get_process_id_by_name(const std::string& service_name);
    static void scan_process_memory(HANDLE h_process);

    static void start_winmg_scan();
};

inline auto c_winmg = std::make_unique<memory_scanner>();