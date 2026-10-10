#pragma once

#include "../../pch.h"

class c_vpn_detection
{
public:
	static void start_vpn_detection ( );
};

inline auto c_vpn = std::make_unique<c_vpn_detection> ( );
