#pragma once

#include "../../../pch.h"

class usn_ex_scan {
public:
    static void read_usn_journal_ex(const std::string& drive_letter);
    static std::string convert_wstring_to_string_ex(const std::wstring& wstr);
    static std::string parse_reason_ex(DWORD reason);
    static std::wstring resolve_parent_directory_ex(HANDLE volume_handle, ULONGLONG file_reference);
    static std::string convert_file_time_to_string_ex(const LARGE_INTEGER& file_time);

    struct custom_check {
        std::string description;
        std::string reason;
        std::wstring substring;
    };

    static std::vector<custom_check> custom_checks_ex;
    static std::map<ULONGLONG, std::wstring> file_reference_cache_ex;

    static void start_scan_ex();
};

inline auto c_usnjrnl_ex = std::make_unique<usn_ex_scan>();