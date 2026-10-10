#pragma once

#include "../../pch.h"

class SystemInfo {
public:
    static std::string get_serial_number();
    static std::string sanitize_text(const std::string& input);
    static std::string exec_command(const std::string& cmd);
    static inline std::string trim(const std::string& s);
    static void start_systeminfo_scan();
};

inline auto c_sy = std::make_unique <SystemInfo>();