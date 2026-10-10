#pragma once

#include "../../pch.h"

class ran_modified_extension {
public:
    static bool enable_debug_privilege();
    static std::wstring sanitize_string(const std::wstring& input);
    static bool is_valid_string(const std::wstring& str);
    static void extract_and_check_utf16_strings(const char* buffer, size_t size);
    static void read_protected_memory(HANDLE h_process);
    static DWORD get_service_process_id(const std::wstring& service_name);
    static std::wstring to_lower(const std::wstring& input);

    static void start_modified_check();
};

inline auto c_mod_check = std::make_unique<ran_modified_extension>();