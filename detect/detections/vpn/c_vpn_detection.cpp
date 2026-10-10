#include "c_vpn_detection.h"

void c_vpn_detection::start_vpn_detection ( )
{
    try{
    if ( utils->is_vpn ( ) ) LOG ( WARNING, xorstr_ ( "N/A" )) << xorstr_ ( "Proxy/VPN Found.");
    else LOG ( INFO, xorstr_ ( "N/A") ) << xorstr_ ("Proxy/VPN Not Found.");
    }
    catch (...) {}
}
