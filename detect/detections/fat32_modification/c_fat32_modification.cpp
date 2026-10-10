#include "c_fat32_modification.h"

void c_fat32_modification::print_event_details(EVT_HANDLE event_handle,
    const FILETIME& explorer_start_time, FILETIME& latest_time, bool& found_latest)
{
    try {
        DWORD buffer_size = 0;
        DWORD buffer_used = 0;
        DWORD property_count = 0;
        LPWSTR rendered_content = NULL;

        if (!EvtRender(NULL, event_handle, EvtRenderEventXml, 0, NULL, &buffer_used, &property_count))
        {
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                buffer_size = buffer_used;
                rendered_content = (LPWSTR)malloc(buffer_size);
                if (!rendered_content) {
                    return;
                }

                if (!EvtRender(NULL, event_handle, EvtRenderEventXml,
                    buffer_size, rendered_content, &buffer_used, &property_count))
                {
                    free(rendered_content);
                    return;
                }

                std::wstring event_xml(rendered_content);
                std::wstring time_created_tag = xorstr_(L"<TimeCreated SystemTime='");
                size_t pos = event_xml.find(time_created_tag);
                if (pos != std::wstring::npos) {
                    pos += time_created_tag.length();
                    size_t end_pos = event_xml.find(xorstr_(L"'"), pos);
                    std::wstring time_str = event_xml.substr(pos, end_pos - pos);

                    FILETIME event_time;
                    if (utils->convert_iso8601_to_filetime(time_str, &event_time)) {
                        if (CompareFileTime(&event_time, &explorer_start_time) >= 0) {
                            std::wstring event_id_tag = xorstr_(L"<EventID>507</EventID>");
                            if (event_xml.find(event_id_tag) != std::wstring::npos) {
                                if (!found_latest || CompareFileTime(&event_time, &latest_time) > 0) {
                                    latest_time = event_time;
                                    found_latest = true;
                                }
                            }
                        }
                    }
                }

                free(rendered_content);
            }
        }
    }
    catch (...) {}
}

void c_fat32_modification::start_fat32_modification_check()
{
    try {
        EVT_HANDLE query_handle = NULL;
        EVT_HANDLE event_handle = NULL;
        DWORD returned_count = 0;
        LPCWSTR evtx_path = xorstr_(L"C:\\Windows\\System32\\Winevt\\Logs\\Microsoft-Windows-Storage-ClassPnP%4Operational.evtx");

        FILETIME explorer_start_time = utils->get_logon_time();

        FILETIME latest_time = { 0 };
        bool found_latest = false;

        query_handle = EvtQuery(NULL, evtx_path, NULL, EvtQueryFilePath | EvtQueryReverseDirection);

        while (EvtNext(query_handle, 1, &event_handle, INFINITE, 0, &returned_count))
        {
            print_event_details(event_handle, explorer_start_time, latest_time, found_latest);
            EvtClose(event_handle);
        }

        if (found_latest) {
            std::wstring local_time_wstr = utils->convert_string_to_wstring
            (utils->convert_filetime_to_local_readable_format(latest_time));
            LOG(WARNING, utils->convert_filetime_to_local_readable_format(latest_time)) << xorstr_("File On FAT Drive Modified");
            detect.detection_count += 1;
        }

        if (query_handle)
        {
            EvtClose(query_handle);
        }
    }
    catch (...) {}
}