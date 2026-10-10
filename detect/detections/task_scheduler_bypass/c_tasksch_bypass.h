#pragma once

#include "../../pch.h"

class c_tasksch_bypass{
    public:
        static void read_usn_journal(const std::string& drive_letter);
        static std::string convert_wstring_to_string(const std::wstring& wstr);
        static std::string parse_reason(DWORD reason);
        static std::wstring resolve_parent_directory(HANDLE volume_handle, ULONGLONG file_reference);
        static std::string convert_file_time_to_string(const LARGE_INTEGER& file_time);

        static std::unordered_map<ULONGLONG, std::wstring> file_reference_cache;

        static void start_task_scan();
        static bool starts_with_tasks_path(const std::wstring& path);

        static std::unordered_map<std::wstring, std::time_t> set1_events;

        static std::time_t filetime_to_epoch(const LARGE_INTEGER& file_time);
        static bool is_set1(DWORD reason);
        static bool is_set2(DWORD reason);

};

inline auto c_task = std::make_unique<c_tasksch_bypass>();