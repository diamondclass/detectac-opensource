#pragma once

#ifndef VARS_H
#define VARS_H

#include "pch.h"
#include <string>
#include <random>
#include <windows.h>
#include <filesystem>
#include "utils/crypt/xorstr.h"

struct vars
{
    bool scanned , scan_started , scan_done;
    bool pin_inputted = true;
    bool self_scan_flagged;

    bool sent_data = true;
    bool server_online = true;
    bool server_offline_failure;
    bool agreed = false;
    bool legal_popup = true;
    bool shown_notification = false;

    bool deep_scan;

    std::atomic < bool > completed { false };

    std::atomic<int> current_stage_index { 0 };

    std::string pin = extract_pin_from_filename ( );

    std::string output_log = xorstr_ ( "Idle" );

    std::string report_path;

    int detection_count , finished_scan_stages;
    int total_scan_stages = 4;

    std::string window_name , window_class;

    float f_progress , f_stage_progress = 0.0f;

#ifdef DETECT_MINECRAFT
    int i_total_stages; 
#elif DETECT_FIVEM
    int i_total_stages; 
#elif DETECT_ROBLOX
    int i_total_stages; 
#elif DETECT_FORTNITE
    int i_total_stages; 
#elif DETECT_FREEFIRE
    int i_total_stages; 
#elif DETECT_DAYZ
    int i_total_stages; 
#elif DETECT_SIEGE
    int i_total_stages; 
#elif DETECT_RUST
    int i_total_stages; 
#elif DETECT_COD
    int i_total_stages;
#elif DETECT_CS
    int i_total_stages;
#endif

private:
    std::string extract_pin_from_filename ( ) {
        try {
            
            char exe_path [ MAX_PATH ];
            if ( GetModuleFileNameA ( NULL , exe_path , MAX_PATH ) == 0 ) {
                return xorstr_ ( "00000000" ); 
            }

            std::filesystem::path path ( exe_path );
            std::string filename = path.filename ( ).string ( );

            size_t exe_pos = filename.rfind ( xorstr_ ( ".exe" ) );
            if ( exe_pos == std::string::npos ) return xorstr_ ( "00000000" );

            size_t dash_pos = filename.rfind ( '-' , exe_pos );
            if ( dash_pos == std::string::npos ) return xorstr_ ( "00000000" );

            std::string pin = filename.substr ( dash_pos + 1 , exe_pos - dash_pos - 1 );

            if ( pin.length ( ) == 8 ) {
                bool all_digits = true;
                for ( char c : pin ) {
                    if ( c < '0' || c > '9' ) {
                        all_digits = false;
                        break;
                    }
                }
                if ( all_digits ) return pin;
            }

            return xorstr_ ( "00000000" ); 

        }
        catch ( ... ) {
            return xorstr_ ( "00000000" ); 
        }
    }

}inline detect;

#endif