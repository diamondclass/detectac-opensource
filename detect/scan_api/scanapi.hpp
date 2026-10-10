#pragma once

#include <string>
#include <vector>
#include <curl/curl.h>
#include <nlohmann/json.hpp>

class c_scanapi
{
public:
    c_scanapi ( const std::string& base_url , const std::string& pin );

    ~c_scanapi ( );

    bool start_scan ( );
    bool update_stage ( int stage , const std::string& message );
    bool complete_scan ( const std::vector<std::string>& results );
    void set_verbose ( bool verbose ) { this->verbose = verbose; }

    bool v2_open ( ) const noexcept { return v2_active; }

private:
    std::string base_url;
    std::string pin;
    bool verbose;
    bool v2_active = false;
    CURL* curl;

    static size_t write_callback ( void* contents , size_t size , size_t nmemb , std::string* data );

    long make_post_request ( const std::string& endpoint , const nlohmann::json& json_data );
};
