#pragma once

#include "../../pch.h"

class usn_scan {
public:
    static void read_usn_journal(const std::string& drive_letter);
    static std::string convert_wstring_to_string(const std::wstring& wstr);
    static std::string parse_reason(DWORD reason);
    static std::wstring resolve_parent_directory(HANDLE volume_handle, ULONGLONG file_reference);
    static std::string convert_file_time_to_string(const LARGE_INTEGER& file_time);

    struct custom_check {
        std::string description;
        std::string reason;
        std::wstring substring;
    };

    static std::vector<custom_check> custom_checks;
    static std::unordered_map<ULONGLONG, std::wstring> file_reference_cache;
    static std::mutex file_reference_cache_mtx;
    static void start_usn_scan();

    static bool ends_with_icase(const std::wstring& str, const std::wstring& suffix);
    static std::wstring get_user_temp_prefix();
};

inline auto c_usnjrnl = std::make_unique<usn_scan>();