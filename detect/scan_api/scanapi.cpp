#include "scanapi.hpp"
#include "telemetry_v2.hpp"

#include <iostream>
#include <sstream>
#include "../utils/crypt/xorstr.h"

c_scanapi::c_scanapi
( const std::string& base_url , const std::string& pin )
    : base_url ( base_url ) , pin ( pin ) , verbose ( false )
{

    curl = curl_easy_init ( );
    if ( !curl ) return;

    curl_easy_setopt ( curl , CURLOPT_WRITEFUNCTION , write_callback );
    curl_easy_setopt ( curl , CURLOPT_FOLLOWLOCATION , 0L );
    curl_easy_setopt ( curl , CURLOPT_MAXREDIRS , 0L );
    curl_easy_setopt ( curl , CURLOPT_TIMEOUT , 30L );
    curl_easy_setopt ( curl , CURLOPT_CONNECTTIMEOUT , 15L );
    curl_easy_setopt ( curl , CURLOPT_SSL_VERIFYPEER , 1L );
    curl_easy_setopt ( curl , CURLOPT_SSL_VERIFYHOST , 2L );
    curl_easy_setopt ( curl , CURLOPT_SSL_OPTIONS , ( long ) CURLSSLOPT_NATIVE_CA );
    curl_easy_setopt ( curl , CURLOPT_SSLVERSION , ( long ) CURL_SSLVERSION_TLSv1_2 );
    curl_easy_setopt ( curl , CURLOPT_PINNEDPUBLICKEY , telemetry_v2::spki_pin ( ).c_str ( ) );
    curl_easy_setopt ( curl , CURLOPT_PROTOCOLS_STR , xorstr_("https") );
    curl_easy_setopt ( curl , CURLOPT_REDIR_PROTOCOLS_STR , xorstr_("https") );
    curl_easy_setopt ( curl , CURLOPT_PROXY , "" );
    curl_easy_setopt ( curl , CURLOPT_NOPROXY , xorstr_("*") );
    curl_easy_setopt ( curl , CURLOPT_NOSIGNAL , 1L );
}

c_scanapi::~c_scanapi ( )
{
    if ( curl ) curl_easy_cleanup ( curl );
}

bool
c_scanapi::start_scan
( )
{
    const auto begin_rc = telemetry_v2::shared_session ( ).begin ( pin );
    v2_active = ( begin_rc == telemetry_v2::error::none );

    std::string endpoint = xorstr_ ( "/api/scanning/start-scan/" ) + pin;
    nlohmann::json requestData = nlohmann::json::object ( );

    long responseCode = make_post_request ( endpoint , requestData );

    if ( responseCode == 200 ) return true;
    if ( v2_active ) return true;
    return false;
}

bool
c_scanapi::update_stage
( int stage , const std::string& message )
{
    if ( v2_active )
    {
        const auto rc = telemetry_v2::shared_session ( ).send_stage_update ( stage , message );
        if ( rc == telemetry_v2::error::none ) return true;
    }

    nlohmann::json requestData;
    requestData [ xorstr_ ( "pin" ) ] = pin;
    requestData [ xorstr_ ( "stage" ) ] = stage;
    requestData [ xorstr_ ( "message" ) ] = message;

    std::string endpoint = xorstr_ ( "/api/scanning/update-stage" );
    long responseCode = make_post_request ( endpoint , requestData );

    return responseCode == 200;
}

bool
c_scanapi::complete_scan
( const std::vector<std::string>& results )
{

    nlohmann::json requestData;
    requestData [ xorstr_ ( "pin" ) ] = pin;
    requestData [ xorstr_ ( "results" ) ] = results;

    std::string endpoint = xorstr_ ( "/api/scanning/complete" );
    long responseCode = make_post_request ( endpoint , requestData );

    if ( responseCode == 200 ) return true;
    if ( v2_active ) return true;
    return false;
}

size_t c_scanapi::write_callback ( void* contents , size_t size , size_t nmemb , std::string* data )
{
    size_t totalSize = size * nmemb;
    data->append ( ( char* ) contents , totalSize );
    return totalSize;
}

long
c_scanapi::make_post_request
( const std::string& endpoint , const nlohmann::json& json_data )
{
    if ( !curl ) return 0;

    std::string full_url = base_url + endpoint;
    std::string jsonString = json_data.dump ( );
    std::string responseData;

    curl_easy_setopt ( curl , CURLOPT_URL , full_url.c_str ( ) );
    curl_easy_setopt ( curl , CURLOPT_POSTFIELDS , jsonString.c_str ( ) );
    curl_easy_setopt ( curl , CURLOPT_WRITEDATA , &responseData );

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append ( headers , xorstr_ ( "Content-Type: application/json" ) );
    headers = curl_slist_append ( headers , xorstr_ ( "Accept: application/json" ) );
    curl_easy_setopt ( curl , CURLOPT_HTTPHEADER , headers );

    CURLcode res = curl_easy_perform ( curl );

    long responseCode = 0;
    curl_easy_getinfo ( curl , CURLINFO_RESPONSE_CODE , &responseCode );

    curl_slist_free_all ( headers );

    if ( res != CURLE_OK ) return 0;

    try
    {
        if ( !responseData.empty ( ) ) nlohmann::json responseJson = nlohmann::json::parse ( responseData );
    }
    catch ( const std::exception& e )
    {
    }

    return responseCode;
}
