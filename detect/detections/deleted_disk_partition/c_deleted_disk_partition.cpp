#include "c_deleted_disk_partition.h"

std::wstring c_deleted_disk_partition::format_timestamp_to_local ( const FILETIME& file_time )
{
    try{
    SYSTEMTIME local_system_time;
    FILETIME local_file_time;
    wchar_t formatted_time [ 20 ];

    if ( FileTimeToLocalFileTime ( &file_time , &local_file_time ) &&
        FileTimeToSystemTime ( &local_file_time , &local_system_time ) )
    {
        swprintf_s ( formatted_time , xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d" ) ,
            local_system_time.wYear , local_system_time.wMonth , local_system_time.wDay ,
            local_system_time.wHour , local_system_time.wMinute , local_system_time.wSecond );

        return std::wstring ( formatted_time );
    }

    return xorstr_(L"N/A");
    }
    catch (...) {}
    return xorstr_(L"N/A");
}

FILETIME c_deleted_disk_partition::get_user_logon_time()
{
    try{
    ULONG sessionCount = 0;
    PLUID sessions = nullptr;

    if (LsaEnumerateLogonSessions(&sessionCount, &sessions) != 0)
    {
        return {};
    }

    FILETIME logonTime = {};
    for (ULONG i = 0; i < sessionCount; ++i)
    {
        PSECURITY_LOGON_SESSION_DATA sessionData = nullptr;

        if (LsaGetLogonSessionData(&sessions[i], &sessionData) == 0 && sessionData != nullptr)
        {
            if (sessionData->LogonType == Interactive || sessionData->LogonType == RemoteInteractive)
            {
                logonTime.dwHighDateTime = sessionData->LogonTime.HighPart;
                logonTime.dwLowDateTime = sessionData->LogonTime.LowPart;

                LsaFreeReturnBuffer(sessionData);
                break;
            }

            LsaFreeReturnBuffer(sessionData);
        }
    }

    LsaFreeReturnBuffer(sessions);

    FILETIME logon_time = {};
    FileTimeToLocalFileTime(&logonTime, &logon_time);

    return logon_time;
    }
    catch (...) {}
}

bool c_deleted_disk_partition::parse_iso_timestamp ( const std::wstring& iso_timestamp , FILETIME& file_time )
{
    try{
    SYSTEMTIME utc_system_time = {};

    if ( swscanf_s ( iso_timestamp.c_str ( ) , xorstr_(L"%4d-%2d-%2dT%2d:%2d:%2d") ,
        &utc_system_time.wYear , &utc_system_time.wMonth , &utc_system_time.wDay ,
        &utc_system_time.wHour , &utc_system_time.wMinute , &utc_system_time.wSecond ) == 6 )
    {
        return SystemTimeToFileTime ( &utc_system_time , &file_time );
    }
    return false;
    }
    catch (...) {}
}

void c_deleted_disk_partition::display_event_if_after_logon ( EVT_HANDLE event_handle , const FILETIME& logon_time , std::set<std::wstring>& displayed_timestamps )
{
    try{
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    DWORD property_count = 0;
    std::vector<wchar_t> xml_buffer;

    while ( true )
    {
        if ( !EvtRender ( nullptr , event_handle , EvtRenderEventXml , buffer_size , xml_buffer.data ( ) , &buffer_used , &property_count ) )
        {
            DWORD status = GetLastError ( );
            if ( status == ERROR_INSUFFICIENT_BUFFER )
            {
                buffer_size = buffer_used;
                xml_buffer.resize ( buffer_size );
            }
            else
            {
                return;
            }
        }
        else
        {
            std::wstring xml_content ( xml_buffer.data ( ) );

            if ( xml_content.find ( xorstr_ ( L"<EventID>117</EventID>" ) ) != std::wstring::npos )
            {
                std::wregex time_regex ( xorstr_ ( L"<TimeCreated SystemTime='([^']+)'" ) );
                std::wsmatch match;

                if ( std::regex_search ( xml_content , match , time_regex ) && match.size ( ) > 1 )
                {
                    std::wstring iso_timestamp = match [ 1 ].str ( );
                    FILETIME event_time;

                    if ( parse_iso_timestamp ( iso_timestamp , event_time ) )
                    {
                        if ( CompareFileTime ( &event_time , &logon_time ) > 0 )
                        {
                            std::wstring local_time_formatted = format_timestamp_to_local ( event_time );

                            if ( displayed_timestamps.find ( local_time_formatted ) == displayed_timestamps.end ( ) )
                            {
                                LOG ( WARNING , utils->convert_wstring_to_string ( local_time_formatted ) ) << xorstr_ ( "Disk Partition Deleted" );

                                displayed_timestamps.insert ( local_time_formatted );
                            }
                        }
                    }
                }
            }
            break;
        }
    }
    }
    catch (...) {}
}

void c_deleted_disk_partition::query_device_management_log ( )
{
    try{
    EVT_HANDLE log_handle = nullptr;
    EVT_HANDLE query_handle = nullptr;
    EVT_HANDLE event_handle = nullptr;
    DWORD returned = 0;

    FILETIME logon_time = get_user_logon_time ( );
    std::set<std::wstring> displayed_timestamps;

    log_handle = EvtOpenLog ( nullptr , xorstr_ ( L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-VolumeSnapshot-Driver%4Operational.evtx" ) , EvtOpenFilePath );
    if ( !log_handle )
    {
        return;
    }

    query_handle = EvtQuery ( nullptr , xorstr_ ( L"C:\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-VolumeSnapshot-Driver%4Operational.evtx" ) , nullptr , EvtQueryFilePath );
    if ( !query_handle )
    {
        EvtClose ( log_handle );
        return;
    }

    while ( EvtNext ( query_handle , 1 , &event_handle , INFINITE , 0 , &returned ) )
    {
        display_event_if_after_logon ( event_handle , logon_time , displayed_timestamps );
        EvtClose ( event_handle );
    }

    DWORD status = GetLastError ( );
    if ( status != ERROR_NO_MORE_ITEMS )
    {
    }

    EvtClose ( query_handle );
    EvtClose ( log_handle );
    }
    catch (...) {}
}

void c_deleted_disk_partition::start_deleted_part_checks ( )
{
    try{
    query_device_management_log ( );
    }
    catch (...) {}
}
