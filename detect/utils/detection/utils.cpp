#include "utils.h"

std::unique_ptr<c_utils> utils = std::make_unique<c_utils> ( );

std::set<std::string> c_utils::scanned_files;
std::mutex c_utils::scanned_files_mutex;
const std::vector<c_utils::filter> c_utils::filters;

c_thread_pool pool ( 4 );

std::string c_utils::normalize_path ( const std::string& path )
{
    std::string normalized_path = std::regex_replace ( path , std::regex ( R"(\\+)" ) , R"(\)" ); // Convert multiple backslashes to a single one
    return normalized_path;
}

std::string c_utils::get_known_folder_path ( KNOWNFOLDERID folder_id )
{
    PWSTR path = NULL;
    if ( SUCCEEDED ( SHGetKnownFolderPath ( folder_id , 0 , NULL , &path ) ) )
    {
        std::wstring ws ( path );
        std::string folder_path = ascii_wstring_to_string ( ws );
        CoTaskMemFree ( path );
        return folder_path;
    }
    else
    {
        // LOG ( CRITICAL ) << "Failed to get known folder path for ID: " << folder_id;
        return "";
    }
}

std::wstring c_utils::convert_string_to_wstring(const std::string& str)
{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.from_bytes(str);
}

std::string c_utils::convert_wstring_to_string(const std::wstring& wstr) 
{ 
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;  
    return converter.to_bytes(wstr); 
}

std::string c_utils::path_to_utf8(const std::wstring& w) noexcept
{
    if (w.empty()) return {};
    int needed = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
        static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    int wrote = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
        static_cast<int>(w.size()), out.data(), needed, nullptr, nullptr);
    if (wrote <= 0) return {};
    return out;
}

std::string c_utils::path_to_utf8(const std::filesystem::path& p) noexcept
{
    return path_to_utf8(p.native());
}

bool c_utils::convert_iso8601_to_filetime ( const std::wstring& iso_time , FILETIME* file_time )
{
    SYSTEMTIME sys_time;
    if ( swscanf_s ( iso_time.c_str ( ) , xorstr_(L"%4hu-%2hu-%2huT%2hu:%2hu:%2hu") ,
        &sys_time.wYear , &sys_time.wMonth , &sys_time.wDay ,
        &sys_time.wHour , &sys_time.wMinute , &sys_time.wSecond ) == 6 )
    {
        sys_time.wMilliseconds = 0;
        return SystemTimeToFileTime ( &sys_time , file_time );
    }
    return false;
}

std::string c_utils::convert_filetime_to_local_readable_format ( FILETIME file_time )
{
    SYSTEMTIME utc_sys_time , local_sys_time;
    FileTimeToSystemTime ( &file_time , &utc_sys_time );
    SystemTimeToTzSpecificLocalTime ( NULL , &utc_sys_time , &local_sys_time );

    char buffer [ 100 ];
    snprintf ( buffer , sizeof ( buffer ) , xorstr_("%04d-%02d-%02d %02d:%02d:%02d") ,
        local_sys_time.wYear , local_sys_time.wMonth , local_sys_time.wDay ,
        local_sys_time.wHour , local_sys_time.wMinute , local_sys_time.wSecond );

    return std::string ( buffer );
}

FILETIME c_utils::get_logon_time ( )
{
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

    FILETIME start_time = {};
    FileTimeToLocalFileTime(&logonTime, &start_time);

    return start_time;
}

bool c_utils::is_printable ( wchar_t ch )
{
    return ( ch >= 32 && ch <= 126 ) || ( ch >= 160 && ch <= 255 );
}

bool c_utils::is_well_formed_pidl ( const BYTE* data , size_t size )
{
    if ( !data || size < sizeof ( USHORT ) )
        return false;

    size_t offset = 0;
    while ( offset + sizeof ( USHORT ) <= size ) {
        USHORT cb = 0;
        memcpy ( &cb , data + offset , sizeof ( cb ) );

        if ( cb == 0 )
            return offset > 0;

        if ( cb < sizeof ( USHORT ) || cb > size - offset )
            return false;

        offset += cb;
    }

    return false;
}

HRESULT c_utils::safe_pidl_display_name ( const BYTE* data , size_t size , SIGDN form , PWSTR* name )
{
    if ( !name )
        return E_INVALIDARG;

    *name = nullptr;

    if ( !is_well_formed_pidl ( data , size ) )
        return E_INVALIDARG;

    __try {
        return SHGetNameFromIDList ( reinterpret_cast< LPCITEMIDLIST >( data ) , form , name );
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        *name = nullptr;
        return E_FAIL;
    }
}

bool c_utils::safe_pidl_path ( const BYTE* data , size_t size , wchar_t* path )
{
    if ( !path )
        return false;

    path[ 0 ] = L'\0';

    if ( !is_well_formed_pidl ( data , size ) )
        return false;

    __try {
        return SHGetPathFromIDListW ( reinterpret_cast< LPCITEMIDLIST >( data ) , path ) != FALSE;
    }
    __except ( EXCEPTION_EXECUTE_HANDLER ) {
        path[ 0 ] = L'\0';
        return false;
    }
}

size_t c_utils::write_callback ( void* contents , size_t size , size_t nmemb , std::string* s )
{
    size_t total_size = size * nmemb;
    s->append ( static_cast< char* >( contents ) , total_size );
    return total_size;
}

bool c_utils::is_vpn ( )
{
    CURL* curl;
    CURLcode res;
    std::string read_buffer;

#ifndef TEST_CONNECTIONS
    std::string url = xorstr_("https://detect.ac/auth/security/detection/vpn");
#else
    std::string url = xorstr_("https://reversing.church/auth/security/detection/vpn");
#endif

    curl = curl_easy_init ( );
    if ( curl ) {
        curl_easy_setopt ( curl , CURLOPT_URL , url.c_str ( ) );
        curl_easy_setopt ( curl , CURLOPT_WRITEFUNCTION , write_callback );
        curl_easy_setopt ( curl , CURLOPT_WRITEDATA , &read_buffer );
        res = curl_easy_perform ( curl );
        curl_easy_cleanup ( curl );

        if ( res == CURLE_OK ) {
            return read_buffer == xorstr_("true");
        }
    }

    return false;
}

bool c_utils::is_self_scan ( const std::string& pin ) 
{
    #ifdef TEST_CONNECTIONS
        return false;
    #endif
    
    CURL* curl;
    CURLcode res;
    std::string read_buffer;

    #ifndef TEST_CONNECTIONS
        std::string url = xorstr_ ( "https://detect.ac/auth/security/detection/self");
    #else
        std::string url = xorstr_ ( "https://reversing.church/auth/security/detection/self");
    #endif

    if ( !pin.empty ( ) ) {
        std::string query = xorstr_ ( "?pin=" );
        url += query + pin;
    }

    curl = curl_easy_init ( );

    if ( curl )
    {
        curl_easy_setopt ( curl , CURLOPT_URL , url.c_str ( ) );
        curl_easy_setopt ( curl , CURLOPT_WRITEFUNCTION , write_callback );
        curl_easy_setopt ( curl , CURLOPT_WRITEDATA , &read_buffer );
        curl_easy_setopt ( curl , CURLOPT_HTTPGET , 1L ); 

        res = curl_easy_perform ( curl );

        if ( res != CURLE_OK )
        {
			//LOG ( CRITICAL , "N/A" ) << "cURL error: " << curl_easy_strerror ( res );
			//Logger::instance ( ).flush_logs ( );
			//return false;
        }

        curl_easy_cleanup ( curl );
    }
    else
    {
        LOG ( CRITICAL , xorstr_ ( "N/A" ) ) << xorstr_ ( "Networking initialization failed.");
        Logger::instance ( ).flush_logs ( );
        return false;
    }

    if ( read_buffer.find ( xorstr_ ( "true") ) != std::string::npos ) {
        LOG ( CRITICAL , xorstr_ ( "N/A" ) ) << xorstr_ ( "Self Scanning Detected.");
        Logger::instance ( ).flush_logs ( );
        return true;
    }

    return false;
}

std::string 
c_utils::generate_api_key
( )
{
    const std::string lowercase_letters = xorstr_ ("qwertyuiopasdfghjklzxcvbnm"  );
    const std::string uppercase_letters =  xorstr_ ("QWERTYUIOPASDFGHJKLZXCVBNM");
    const std::string numbers =  xorstr_ ("0123456789");
    const std::string parentheses =  xorstr_ ("(");
    
    std::mt19937 gen ( static_cast< unsigned long >( std::time ( 0 ) ) );
    std::uniform_int_distribution<> dis_lowercase ( 0 , lowercase_letters.size ( ) - 1 );
    std::uniform_int_distribution<> dis_uppercase ( 0 , uppercase_letters.size ( ) - 1 );
    std::uniform_int_distribution<> dis_number ( 0 , numbers.size ( ) - 1 );
    std::uniform_int_distribution<> dis_paren ( 0 , parentheses.size ( ) - 1 );
    std::string key = "";
    
    for ( int i = 0; i < 9; ++i ) key += lowercase_letters [ dis_lowercase ( gen ) ];
    for ( int i = 0; i < 7; ++i ) key += uppercase_letters [ dis_uppercase ( gen ) ];
    for ( int i = 0; i < 8; ++i ) key +=  xorstr_ ("?");
    for ( int i = 0; i < 3; ++i ) key +=  xorstr_ ("!");
    for ( int i = 0; i < 11; ++i ) key += numbers [ dis_number ( gen ) ];
    for ( int i = 0; i < 4; ++i ) key += parentheses [ dis_paren ( gen ) ];
    
    std::shuffle ( key.begin ( ) , key.end ( ) , gen );
    return key;
}

bool
c_utils::check_session_exists
(const std::string& pin)
{
    CURL* curl;
    CURLcode res;
    std::string read_buffer;
    std::string api_key = generate_api_key();
#ifndef TEST_CONNECTIONS
    std::string url = xorstr_("https://detect.ac/auth/api/exists/") + pin;
#else
    std::string url = xorstr_("https://reversing.church/auth/api/exists/") + pin;
#endif
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers = nullptr;
        std::string auth_header = xorstr_("Authorization: ") + api_key;
        headers = curl_slist_append(headers, auth_header.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_buffer);
        res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        if (res == CURLE_OK) {
            try {
                auto json = nlohmann::json::parse(read_buffer);
                return json[xorstr_("status")] == xorstr_("EXISTS");
            }
            catch (...) {}
        }
    }
    return false;
}


void c_utils::log_startup_time()
{
    try
    {
        ULONG sessionCount = 0;
        PLUID sessions = nullptr;

        if (LsaEnumerateLogonSessions(&sessionCount, &sessions) != 0 || sessions == nullptr)
        {
            return;
        }

        FILETIME logonFileTime = {};
        for (ULONG i = 0; i < sessionCount; ++i)
        {
            PSECURITY_LOGON_SESSION_DATA sessionData = nullptr;

            if (LsaGetLogonSessionData(&sessions[i], &sessionData) == 0 && sessionData != nullptr)
            {
                if (sessionData->LogonType == Interactive || sessionData->LogonType == RemoteInteractive)
                {
                    logonFileTime.dwHighDateTime = sessionData->LogonTime.HighPart;
                    logonFileTime.dwLowDateTime = sessionData->LogonTime.LowPart;

                    LsaFreeReturnBuffer(sessionData);
                    break;
                }

                LsaFreeReturnBuffer(sessionData);
            }
        }

        LsaFreeReturnBuffer(sessions);

        if (logonFileTime.dwHighDateTime == 0 && logonFileTime.dwLowDateTime == 0)
        {
            return;
        }

        ULARGE_INTEGER ull;
        ull.HighPart = logonFileTime.dwHighDateTime;
        ull.LowPart = logonFileTime.dwLowDateTime;

        const ULONGLONG EPOCH_DIFFERENCE = 116444736000000000ULL;
        if (ull.QuadPart < EPOCH_DIFFERENCE) {
            return;
        }

        ULONGLONG seconds = (ull.QuadPart - EPOCH_DIFFERENCE) / 10000000ULL;
        if (seconds > 32535244799ULL) {
            return;
        }

        time_t logonTimeUTC = static_cast<time_t>(seconds);
        struct tm time_info;
        if (localtime_s(&time_info, &logonTimeUTC) != 0)
        {
            return;
        }

        char timeBuffer[128];
        if (strftime(timeBuffer, sizeof(timeBuffer), xorstr_("%Y-%m-%d %H:%M:%S"), &time_info) == 0)
        {
            return;
        }

        std::string logonTimeStr(timeBuffer);
        std::stringstream ss;
        ss << xorstr_("User Logon Time: ") << logonTimeStr;

        LOG(INFO, logonTimeStr) << ss.str();
    }
    catch (const std::exception& e)
    {
    }
}


std::wstring c_utils::convert_utc_to_local(const std::wstring& utc_timestamp)
{
    SYSTEMTIME st_utc = { 0 }, st_local = { 0 };
    std::wstring date = utc_timestamp.substr(0, 10);
    std::wstring time = utc_timestamp.substr(11, 8);

    int year = std::stoi(date.substr(0, 4));
    int month = std::stoi(date.substr(5, 2));
    int day = std::stoi(date.substr(8, 2));

    int hour = std::stoi(time.substr(0, 2));
    int minute = std::stoi(time.substr(3, 2));
    int second = std::stoi(time.substr(6, 2));

    st_utc.wYear = year;
    st_utc.wMonth = month;
    st_utc.wDay = day;
    st_utc.wHour = hour;
    st_utc.wMinute = minute;
    st_utc.wSecond = second;
    st_utc.wMilliseconds = 0;

    TIME_ZONE_INFORMATION tz_info;
    GetTimeZoneInformation(&tz_info);

    SystemTimeToTzSpecificLocalTime(&tz_info, &st_utc, &st_local);

    std::wstringstream ss;
    ss << std::setw(4) << std::setfill(L'0') << st_local.wYear << xorstr_(L"-")
        << std::setw(2) << std::setfill(L'0') << st_local.wMonth << xorstr_(L"-")
        << std::setw(2) << std::setfill(L'0') << st_local.wDay << xorstr_(L" ")
        << std::setw(2) << std::setfill(L'0') << st_local.wHour << xorstr_(L":")
        << std::setw(2) << std::setfill(L'0') << st_local.wMinute << xorstr_(L":")
        << std::setw(2) << std::setfill(L'0') << st_local.wSecond;

    return ss.str();
}


std::string c_utils::convert_utc_to_localA ( const std::string& utc_timestamp )
{
    SYSTEMTIME st_utc = { 0 } , st_local = { 0 };
    std::string date = utc_timestamp.substr ( 0 , 10 );
    std::string time = utc_timestamp.substr ( 11 , 8 );

    int year = std::stoi ( date.substr ( 0 , 4 ) );
    int month = std::stoi ( date.substr ( 5 , 2 ) );
    int day = std::stoi ( date.substr ( 8 , 2 ) );

    int hour = std::stoi ( time.substr ( 0 , 2 ) );
    int minute = std::stoi ( time.substr ( 3 , 2 ) );
    int second = std::stoi ( time.substr ( 6 , 2 ) );

    st_utc.wYear = year;
    st_utc.wMonth = month;
    st_utc.wDay = day;
    st_utc.wHour = hour;
    st_utc.wMinute = minute;
    st_utc.wSecond = second;
    st_utc.wMilliseconds = 0;

    FILETIME ft_utc , ft_local;
    SystemTimeToFileTime ( &st_utc , &ft_utc );
    LocalFileTimeToFileTime ( &ft_utc , &ft_local );
    FileTimeToSystemTime ( &ft_local , &st_local );

    std::ostringstream ss;
    ss << std::setw ( 4 ) << std::setfill ( '0' ) << st_local.wYear << xorstr_("-")
        << std::setw ( 2 ) << std::setfill ( '0' ) << st_local.wMonth << xorstr_("-")
        << std::setw ( 2 ) << std::setfill ( '0' ) << st_local.wDay << xorstr_(" ")
        << std::setw ( 2 ) << std::setfill ( '0' ) << st_local.wHour << xorstr_(":")
        << std::setw ( 2 ) << std::setfill ( '0' ) << st_local.wMinute << xorstr_(":")
        << std::setw ( 2 ) << std::setfill ( '0' ) << st_local.wSecond;

    return ss.str ( );
}

std::string c_utils::sanitize_string ( const std::string& input )
{
    std::string sanitized;
    for (char c : input) {
        if (c >= 32 && c <= 126) {
            sanitized += c;
        }
        else {
            sanitized += '?';
        }
    }
    return sanitized;
}

std::wstring c_utils::sanitize_wstring(const std::wstring& input)
    {
        try
        {
            const size_t max_length = 260;
            std::wstring sanitized;
            sanitized.reserve(input.size());
            for (wchar_t ch : input)
            {
                if (sanitized.size() >= max_length)
                {
                    sanitized += xorstr_(L"...");
                    break;
                }
                sanitized += (iswprint(ch) && !iswcntrl(ch)) ? ch : L'?';
            }
            return sanitized;
        }
        catch (...)
        {
            return xorstr_(L"");
        }
    }

std::wstring c_utils::sanitize_file_name ( const std::wstring& file_name )
{
    std::wstring sanitized;
    for ( wchar_t ch : file_name )
    {
        if ( ch >= 32 && ch <= 126 )
            sanitized += ch;
        else
            sanitized += L'?';
    }
    return sanitized;
}

std::string c_utils::exec_command ( const std::string& cmd )
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead , hWrite;

    sa.nLength = sizeof ( SECURITY_ATTRIBUTES );
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if ( !CreatePipe ( &hRead , &hWrite , &sa , 0 ) )
    {
        throw std::runtime_error ( xorstr_("Failed to create pipe!") );
    }

    ZeroMemory ( &si , sizeof ( si ) );
    si.cb = sizeof ( si );
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;

    ZeroMemory ( &pi , sizeof ( pi ) );

    std::string command = xorstr_("cmd /C ") + cmd;

    if ( !CreateProcess ( NULL , const_cast< char* >( command.c_str ( ) ) , NULL , NULL , TRUE , CREATE_NO_WINDOW , NULL , NULL , &si , &pi ) )
    {
        CloseHandle ( hRead );
        CloseHandle ( hWrite );
        throw std::runtime_error ( xorstr_("CreateProcess failed!") );
    }

    CloseHandle ( hWrite );

    std::string result;
    char buffer [ 128 ];
    DWORD bytesRead;

    while ( ReadFile ( hRead , buffer , sizeof ( buffer ) - 1 , &bytesRead , NULL ) && bytesRead > 0 )
    {
        buffer [ bytesRead ] = '\0';
        result += buffer;
    }

    CloseHandle ( hRead );
    CloseHandle ( pi.hProcess );
    CloseHandle ( pi.hThread );

    return result;
}

void c_utils::exec_command_streamed ( const std::string& cmd , std::function<void ( const std::string& )> line_handler )
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    HANDLE hRead , hWrite;

    sa.nLength = sizeof ( SECURITY_ATTRIBUTES );
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    if ( !CreatePipe ( &hRead , &hWrite , &sa , 0 ) )
    {
        throw std::runtime_error ( xorstr_("Failed to create pipe!") );
    }

    ZeroMemory ( &si , sizeof ( si ) );
    si.cb = sizeof ( si );
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;

    ZeroMemory ( &pi , sizeof ( pi ) );

    std::string command = xorstr_("cmd /C ") + cmd;

    if ( !CreateProcess ( NULL , const_cast< char* >( command.c_str ( ) ) , NULL , NULL , TRUE , CREATE_NO_WINDOW , NULL , NULL , &si , &pi ) )
    {
        CloseHandle ( hRead );
        CloseHandle ( hWrite );
        throw std::runtime_error ( xorstr_("CreateProcess failed!") );
    }

    CloseHandle ( hWrite );

    char buffer [ 128 ];
    DWORD bytesRead;
    std::string line_buffer;

    while ( ReadFile ( hRead , buffer , sizeof ( buffer ) - 1 , &bytesRead , NULL ) && bytesRead > 0 )
    {
        buffer [ bytesRead ] = '\0';
        line_buffer += buffer;

        size_t pos = 0;
        while ( ( pos = line_buffer.find ( '\n' ) ) != std::string::npos )
        {
            line_handler ( line_buffer.substr ( 0 , pos ) );
            line_buffer.erase ( 0 , pos + 1 );
        }
    }

    if ( !line_buffer.empty ( ) )  
    {
        line_handler ( line_buffer );
    }

    CloseHandle ( hRead );
    CloseHandle ( pi.hProcess );
    CloseHandle ( pi.hThread );
}

std::string c_utils::convert_ole_char_to_string ( OLECHAR* ole_string )
{
    int size = WideCharToMultiByte ( CP_UTF8 , 0 , ole_string , -1 , nullptr , 0 , nullptr , nullptr );
    std::string result ( size , '\0' );
    WideCharToMultiByte ( CP_UTF8 , 0 , ole_string , -1 , &result [ 0 ] , size , nullptr , nullptr );
    return result;
}

void c_utils::check_server_status ( )
{
    CURL* curl;
    CURLcode res;
    std::string read_buffer;

    curl_global_init ( CURL_GLOBAL_DEFAULT );
    curl = curl_easy_init ( );
    if ( curl )
    {
        #ifndef TEST_CONNECTIONS
                std::string url = xorstr_ ( "https://detect.ac/auth/api/server-status");
        #else
                std::string url = xorstr_("https://reversing.church/auth/api/server-status");
        #endif

        curl_easy_setopt ( curl , CURLOPT_URL , url.c_str ( ) );
        curl_easy_setopt ( curl , CURLOPT_WRITEFUNCTION , utils->write_callback );
        curl_easy_setopt ( curl , CURLOPT_WRITEDATA , &read_buffer );

        res = curl_easy_perform ( curl );
        if ( res == CURLE_OK )
        {
            if ( read_buffer == xorstr_ ( "9rmIoOxb4BkQ33wm3PGp2A3YRm7EN4UmUGuOlHQRCfMOlm5WRIrlJBvYsOc1SeK1rOkJ75WgMzWlF1uOvpD98SQmywoTOiImNGF0y60OhwoCKna6x31Su0pDoh48lE6a") )
                detect.server_online = true;

            else
                detect.server_online = false;
        }
        else
            detect.server_online = false;

        curl_easy_cleanup ( curl );
    }
    else {
        detect.server_online = false;
    }

    curl_global_cleanup ( );
}

bool c_utils::contains_case_insensitive ( const char* str , const char* substr )
{
    std::string str_lower ( str );
    std::string substr_lower ( substr );

    std::transform ( str_lower.begin ( ) , str_lower.end ( ) , str_lower.begin ( ) ,
        [ ] ( unsigned char c ) { return std::tolower ( c ); } );
    std::transform ( substr_lower.begin ( ) , substr_lower.end ( ) , substr_lower.begin ( ) ,
        [ ] ( unsigned char c ) { return std::tolower ( c ); } );

    return str_lower.find ( substr_lower ) != std::string::npos;
}

std::string
c_utils::generate_random_string
(const size_t length)
{
    const std::string characters = xorstr_("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<size_t> distribution(0, characters.size (  ) - 1);

    std::string random_string;
    random_string.reserve(length);

    for (size_t i = 0; i < length; ++i)
    {
        random_string += characters[distribution(generator)];
    }

    return random_string;
}

auto 
c_utils::increment_progress 
( ) 
noexcept -> void
{
    try{
    constexpr uint16_t VALUE_CONSTANT = 1000U;
    detect.f_progress += static_cast < int16_t > ( VALUE_CONSTANT / detect.i_total_stages );
    if ( detect.f_progress > VALUE_CONSTANT ) detect.f_progress = VALUE_CONSTANT;
    detect.f_stage_progress = detect.f_progress / VALUE_CONSTANT;
    }
    catch (...) {}
}

bool 
c_utils::is_excluded_directory
(const std::filesystem::path& path) 
{
    try{
    static const std::vector<std::wstring> excluded_paths = 
    {
        xorstr_(L"C:\\Program Files (x86)"),
        xorstr_(L"C:\\Program Files"),
        xorstr_(L"C:\\Windows\\Microsoft.NET"),
        xorstr_(L"C:\\Windows\\assembly"),
        xorstr_(L"C:\\Windows\\Installer"),
        xorstr_(L"C:\\Windows\\Servicing"),
        xorstr_(L"C:\\Windows\\WinSxS"),
    };

    std::error_code ec;
    std::filesystem::path canonical_path = std::filesystem::weakly_canonical(path, ec);
    std::wstring lower_path = canonical_path.wstring();

    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::towlower);

    for (const auto& excluded : excluded_paths) 
    {
        std::wstring lower_excluded = excluded;
        std::transform(lower_excluded.begin(), lower_excluded.end(), lower_excluded.begin(), ::towlower);

        if (lower_path.starts_with(lower_excluded)) 
        {
            return true;
        }
    }

    return false;
    }
    catch (...) {}
    return false;
}

std::wstring c_utils::raw_string(const wchar_t* str, size_t length) {
    try{
    return std::wstring(str, length);
    }
    catch (...) {}
    return {};
}

bool c_utils::section_matches_filter(const IMAGE_SECTION_HEADER& section_header, const filter& filter) {
    try{
    try {
        std::string section_name(reinterpret_cast<const char*>(section_header.Name), sizeof(section_header.Name));
        if (!filter.section_name.empty() && section_name.find(filter.section_name) == std::string::npos)
            return false;
        if (filter.virtual_size != 0 && section_header.Misc.VirtualSize != filter.virtual_size)
            return false;
        if (filter.virtual_address != 0 && section_header.VirtualAddress != filter.virtual_address)
            return false;
        if (filter.raw_address != 0 && section_header.PointerToRawData != filter.raw_address)
            return false;
        return true;
    }
    catch (...) {
        return false;
    }
    } catch (...) {}
    return false;
}

std::wstring c_utils::parse_pe_file_with_filters(const std::wstring& file_path) {
    try{
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return xorstr_(L"");
    }

    IMAGE_DOS_HEADER dos_header;
    file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        file.close();
        return xorstr_(L"");
    }

    file.seekg(dos_header.e_lfanew, std::ios::beg);
    DWORD nt_signature = 0;
    file.read(reinterpret_cast<char*>(&nt_signature), sizeof(nt_signature));
    if (nt_signature != IMAGE_NT_SIGNATURE) {
        file.close();
        return xorstr_(L"");
    }

    IMAGE_FILE_HEADER file_header;
    file.read(reinterpret_cast<char*>(&file_header), sizeof(file_header));

    if (file_header.Machine != IMAGE_FILE_MACHINE_I386 && file_header.Machine != IMAGE_FILE_MACHINE_AMD64) {
        file.close();
        return xorstr_(L"");
    }

    IMAGE_OPTIONAL_HEADER32 opt_header32;
    IMAGE_OPTIONAL_HEADER64 opt_header64;
    bool is_32_bit = (file_header.Machine == IMAGE_FILE_MACHINE_I386);

    if (is_32_bit) {
        file.read(reinterpret_cast<char*>(&opt_header32), sizeof(opt_header32));
        if (opt_header32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
            file.close();
            return xorstr_(L"");
        }
    }
    else {
        file.read(reinterpret_cast<char*>(&opt_header64), sizeof(opt_header64));
        if (opt_header64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            file.close();
            return xorstr_(L"");
        }
    }

    size_t section_offset = dos_header.e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) +
        (is_32_bit ? file_header.SizeOfOptionalHeader : sizeof(IMAGE_OPTIONAL_HEADER64));
    file.seekg(section_offset, std::ios::beg);

    IMAGE_SECTION_HEADER section_header;
    for (WORD i = 0; i < file_header.NumberOfSections; ++i) {
        file.read(reinterpret_cast<char*>(&section_header), sizeof(section_header));

        for (const auto& filter : filters) {
            if (section_matches_filter(section_header, filter)) {
                file.close();
                return std::wstring(filter.output_message.begin(), filter.output_message.end());
            }
        }
    }

    file.close();
    return xorstr_(L"");
}
catch (...) {}
return {};
}

bool c_utils::file_exists(const std::wstring& file_path) {
    try{
    DWORD file_attr = GetFileAttributesW(file_path.c_str());
    return (file_attr != INVALID_FILE_ATTRIBUTES && !(file_attr & FILE_ATTRIBUTE_DIRECTORY));
    }
    catch (...) {}
    return false;
}

void c_utils::unload_registry_hive() {
    try{
    RegUnLoadKeyA(HKEY_LOCAL_MACHINE, xorstr_("TEMP_AMCACHE"));
    }
    catch (...) {}
}

void c_utils::enumerate_registry_values(const std::wstring& sub_key) {
    try{
    HKEY h_key;
    LONG l_res = RegOpenKeyExW(HKEY_CURRENT_USER, sub_key.c_str(), 0, KEY_READ, &h_key);

    if (l_res != ERROR_SUCCESS) {
        return;
    }

    DWORD value_count = 0;
    DWORD max_value_name_len = 0;

    l_res = RegQueryInfoKeyW(h_key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &value_count, &max_value_name_len, nullptr, nullptr, nullptr);

    if (l_res != ERROR_SUCCESS) {
        RegCloseKey(h_key);
        return;
    }

    std::vector<wchar_t> value_name_buffer(max_value_name_len + 1);

    for (DWORD i = 0; i < value_count; ++i) {
        DWORD value_name_len = max_value_name_len + 1;

        l_res = RegEnumValueW(h_key, i, value_name_buffer.data(), &value_name_len, nullptr, nullptr, nullptr, nullptr);

        if (l_res != ERROR_SUCCESS) {
            continue;
        }

        std::wstring value_name = utils->raw_string(value_name_buffer.data(), value_name_len);

        if (utils->file_exists(value_name)) {
            std::wstring result = utils->parse_pe_file_with_filters(value_name);
            if (!result.empty()) {
                LOG(WARNING, xorstr_("N/A")) << result << xorstr_(" Found On PC:") << utils->sanitize_file_name(value_name);
            }
        }
    }

    RegCloseKey(h_key);
    }
    catch (...) {}
}