#pragma once

#include "../../pch.h"

class hosts_and_prefetch {

public:

	static void prefetch_detection();
	static void hosts_check();
	static void start_hosts_and_prefetch();

};

inline auto c_h_and_p = std::make_unique<hosts_and_prefetch>();