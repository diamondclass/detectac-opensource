#include "c_recycle_bin_modified_detection.h"

std::wstring
c_recycle_bin_modified_detection::file_time_to_string_local
( const FILETIME& ft )
{
    try{
    FILETIME local_file_time;
    SYSTEMTIME st;

    if ( !FileTimeToLocalFileTime ( &ft , &local_file_time ) )
        return xorstr_(L"");

    FileTimeToSystemTime ( &local_file_time , &st );

    std::wostringstream oss;
    oss << std::setw ( 2 ) << std::setfill ( L'0' ) << st.wDay << xorstr_(L"/")
        << std::setw ( 2 ) << std::setfill ( L'0' ) << st.wMonth << xorstr_(L"/")
        << st.wYear << xorstr_(L" ")
        << std::setw ( 2 ) << std::setfill ( L'0' ) << st.wHour << xorstr_(L":")
        << std::setw ( 2 ) << std::setfill ( L'0' ) << st.wMinute << xorstr_(L":")
        << std::setw ( 2 ) << std::setfill ( L'0' ) << st.wSecond;
    return oss.str ( );
    }
    catch (...) {}
    return {};
}

std::wstring
c_recycle_bin_modified_detection::get_current_user_sid
( )
{
    try{
    HANDLE token_handle = nullptr;
    DWORD token_size = 0;
    PTOKEN_USER token_user = nullptr;
    wchar_t* string_sid = nullptr;
    std::wstring sid_string;

    if ( !OpenProcessToken ( GetCurrentProcess ( ) , TOKEN_QUERY , &token_handle ) )
        return xorstr_(L"");

    if ( !GetTokenInformation ( token_handle , TokenUser , nullptr , 0 , &token_size ) && GetLastError ( ) != ERROR_INSUFFICIENT_BUFFER )
    {
        CloseHandle ( token_handle );
        return xorstr_(L"");
    }

    token_user = ( PTOKEN_USER ) malloc ( token_size );
    if ( token_user == nullptr )
    {
        CloseHandle ( token_handle );
        return xorstr_(L"");
    }

    if ( !GetTokenInformation ( token_handle , TokenUser , token_user , token_size , &token_size ) )
    {
        free ( token_user );
        CloseHandle ( token_handle );
        return xorstr_(L"");
    }

    if ( !ConvertSidToStringSidW ( token_user->User.Sid , &string_sid ) )
    {
        free ( token_user );
        CloseHandle ( token_handle );
        return xorstr_(L"");
    }

    sid_string = string_sid;

    LocalFree ( string_sid );
    free ( token_user );
    CloseHandle ( token_handle );

    return sid_string;
    }
    catch (...) {}
    return {};
}

FILETIME c_recycle_bin_modified_detection::get_pc_start_time()
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

    FILETIME localLogonTime = {};
    FileTimeToLocalFileTime(&logonTime, &localLogonTime);

    return localLogonTime;
    }
    catch (...) {}
}


void
c_recycle_bin_modified_detection::start_recycle_bin_modified_checks
( )
{
    try{
    std::wstring user_sid = get_current_user_sid ( );
    if ( user_sid.empty ( ) )
        return;

    std::wstring recycle_bin_path = xorstr_ ( L"C:\\$Recycle.Bin\\") + user_sid;

    WIN32_FILE_ATTRIBUTE_DATA file_info;
    if ( !GetFileAttributesExW ( recycle_bin_path.c_str ( ) , GetFileExInfoStandard , &file_info ) )
        return;

    FILETIME pc_start_time = get_pc_start_time ( );

    if ( CompareFileTime ( &file_info.ftLastWriteTime , &pc_start_time ) > 0 )
        LOG ( WARNING , utils->convert_wstring_to_string ( file_time_to_string_local ( file_info.ftLastWriteTime ) ) ) << xorstr_ ( "Recycle Bin Modified");
    }
    catch (...) {}
}
