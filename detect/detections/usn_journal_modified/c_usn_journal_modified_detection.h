#pragma once

#include "../../pch.h"

class usn_journal_monitor {
    public:
        static void start_usn_journal_modified_check();
        static DWORD extract_event_id(const std::wstring& xml);
        static std::wstring extract_timestamp(const std::wstring& xml);
        static FILETIME get_boot_time_utc();
        static FILETIME convert_timestamp_to_filetime(const std::wstring& utc_timestamp);
        static bool is_after_boot(const FILETIME& event_time, const FILETIME& boot_time);
        static std::wstring convert_utc_to_local_time(const std::wstring& utc_timestamp);
        static void find_most_recent_event(EVT_HANDLE h_event, FILETIME boot_time, std::unordered_set<std::wstring>& seen_timestamps);
        static LPCWSTR log_file_path_get() {
            static const std::wstring p = xorstr_(L"C:\\windows\\system32\\winevt\\Logs\\Microsoft-Windows-Ntfs%4Operational.evtx");
            return p.c_str();
        }
        static std::wstring extract_process_name(const std::wstring& xml);
    };

inline auto c_usn_journal_modified = std::make_unique<usn_journal_monitor>();
