#pragma once

#include "../../pch.h"


class DpsScanner {
public:
    static void start_diff_drive_detection();

    static std::string c_drive_volume;
    static std::vector<std::pair<std::string, std::string>> hardcoded_filters;

    static bool enable_debug_privilege();
    static DWORD get_process_id_by_name(const std::string& service_name);
    static void remove_c_drive_volume_from_filters();
    static std::string sanitize_for_output(const std::string& s);
    static std::string truncate_at_extension(const std::string& s);
    static void output_split_matches(const std::string& mem_str, const std::string& filter_name);
    static bool apply_filter(const std::string& mem_str, const std::pair<std::string, std::string>& filter);
    static inline bool is_ascii_utf8_byte(unsigned char c);
    static inline bool is_utf16le_printable(wchar_t wc);
    static void scan_process_memory(HANDLE h_process);
};

inline auto c_diffd = std::make_unique<DpsScanner>();