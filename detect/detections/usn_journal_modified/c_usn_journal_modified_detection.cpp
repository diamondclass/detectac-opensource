#include "c_usn_journal_modified_detection.h"

DWORD usn_journal_monitor::extract_event_id(const std::wstring& xml)
{
    try {
        std::wstring search_str = xorstr_(L"<EventID>");
        size_t start = xml.find(search_str);
        if (start == std::wstring::npos)
            return 0;

        start += search_str.length();
        size_t end = xml.find(xorstr_(L"</EventID>"), start);
        if (end == std::wstring::npos)
            return 0;

        std::wstring event_id_str = xml.substr(start, end - start);
        return std::stoul(event_id_str);
    }
    catch (...) { return 0; }
}

std::wstring usn_journal_monitor::extract_timestamp(const std::wstring& xml)
{
    try {
        std::wstring search_str = xorstr_(L"<TimeCreated SystemTime='");
        size_t start = xml.find(search_str);
        if (start == std::wstring::npos)
            return {};

        start += search_str.length();
        size_t end = xml.find(xorstr_(L"Z'/>"), start);
        if (end == std::wstring::npos)
            return {};

        return xml.substr(start, end - start);
    }
    catch (...) { return {}; }
}

std::wstring usn_journal_monitor::extract_process_name(const std::wstring& xml)
{
    try {
        std::wstring search_str = xorstr_(L"<Data Name='ProcessName'>");
        size_t start = xml.find(search_str);
        if (start == std::wstring::npos)
            return {};

        start += search_str.length();
        size_t end = xml.find(xorstr_(L"</Data>"), start);
        if (end == std::wstring::npos)
            return {};

        return xml.substr(start, end - start);
    }
    catch (...) { return {}; }
}

FILETIME usn_journal_monitor::get_boot_time_utc()
{
    try {
        FILETIME now{};
        GetSystemTimeAsFileTime(&now);
        ULARGE_INTEGER u{};
        u.LowPart = now.dwLowDateTime;
        u.HighPart = now.dwHighDateTime;
        u.QuadPart -= GetTickCount64() * 10000ULL;
        FILETIME boot{};
        boot.dwLowDateTime = u.LowPart;
        boot.dwHighDateTime = u.HighPart;
        return boot;
    }
    catch (...) { return {}; }
}

FILETIME usn_journal_monitor::convert_timestamp_to_filetime(const std::wstring& utc_timestamp)
{
    try {
        SYSTEMTIME utc_time{};
        swscanf_s(utc_timestamp.c_str(), xorstr_(L"%4hu-%2hu-%2huT%2hu:%2hu:%2hu"),
            &utc_time.wYear, &utc_time.wMonth, &utc_time.wDay,
            &utc_time.wHour, &utc_time.wMinute, &utc_time.wSecond);

        FILETIME file_time{};
        SystemTimeToFileTime(&utc_time, &file_time);
        return file_time;
    }
    catch (...) { return {}; }
}

bool usn_journal_monitor::is_after_boot(const FILETIME& event_time, const FILETIME& boot_time)
{
    try {
        return CompareFileTime(&event_time, &boot_time) > 0;
    }
    catch (...) { return false; }
}

std::wstring usn_journal_monitor::convert_utc_to_local_time(const std::wstring& utc_timestamp)
{
    try {
        SYSTEMTIME utc_time{};
        swscanf_s(utc_timestamp.c_str(), xorstr_(L"%4hu-%2hu-%2huT%2hu:%2hu:%2hu"),
            &utc_time.wYear, &utc_time.wMonth, &utc_time.wDay,
            &utc_time.wHour, &utc_time.wMinute, &utc_time.wSecond);

        SYSTEMTIME local_time{};
        if (SystemTimeToTzSpecificLocalTime(NULL, &utc_time, &local_time)) {
            wchar_t buffer[100];
            swprintf_s(buffer, xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
                local_time.wYear, local_time.wMonth, local_time.wDay,
                local_time.wHour, local_time.wMinute, local_time.wSecond);
            return std::wstring(buffer);
        }
        return {};
    }
    catch (...) { return {}; }
}

void usn_journal_monitor::find_most_recent_event(EVT_HANDLE h_event, FILETIME boot_time, std::unordered_set<std::wstring>& seen_timestamps)
{
    try {
        DWORD buffer_size = 0;
        DWORD buffer_used = 0;
        DWORD property_count = 0;

        if (EvtRender(NULL, h_event, EvtRenderEventXml, buffer_size, NULL, &buffer_used, &property_count))
            return;
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            return;

        buffer_size = buffer_used;
        std::vector<wchar_t> buffer(buffer_size);
        if (!EvtRender(NULL, h_event, EvtRenderEventXml, buffer_size, buffer.data(), &buffer_used, &property_count))
            return;

        std::wstring event_xml(buffer.data());

        DWORD event_id = extract_event_id(event_xml);
        if (event_id != 501)
            return;

        std::wstring process_name = extract_process_name(event_xml);
        if (process_name == xorstr_(L"System") ||
            process_name == xorstr_(L"SearchIndexer.") ||
            process_name == xorstr_(L"Everything.exe"))
            return;

        std::wstring timestamp = extract_timestamp(event_xml);
        if (timestamp.empty())
            return;

        FILETIME event_time = convert_timestamp_to_filetime(timestamp);
        if (!is_after_boot(event_time, boot_time))
            return;

        std::wstring local_timestamp = convert_utc_to_local_time(timestamp);
        if (seen_timestamps.find(local_timestamp) != seen_timestamps.end())
            return;

        LOG(DETECTION, utils->convert_wstring_to_string(local_timestamp))
            << xorstr_("USN Journal Modified/Cleared:");
        seen_timestamps.insert(local_timestamp);
    }
    catch (...) {}
}

void usn_journal_monitor::start_usn_journal_modified_check()
{
    try {
        EVT_HANDLE h_log = EvtQuery(
            NULL,
            log_file_path_get(),
            xorstr_(L"*[System/EventID=501]"),
            EvtQueryFilePath | EvtQueryForwardDirection);
        if (h_log == NULL)
            return;

        FILETIME boot_time = get_boot_time_utc();
        if (boot_time.dwLowDateTime == 0 && boot_time.dwHighDateTime == 0) {
            EvtClose(h_log);
            return;
        }

        std::unordered_set<std::wstring> seen_timestamps;

        while (true) {
            EVT_HANDLE h_events[10];
            DWORD returned = 0;
            if (!EvtNext(h_log, 10, h_events, INFINITE, 0, &returned))
                break;

            for (DWORD i = 0; i < returned; ++i) {
                find_most_recent_event(h_events[i], boot_time, seen_timestamps);
                EvtClose(h_events[i]);
            }
        }

        EvtClose(h_log);
    }
    catch (...) {}
}
