#pragma once

#include "../../pch.h"
#include "browser_download_history/c_browser_downloads.h"
#include "browser_search_history/c_browserhistory.h"
#include "browser_cleared_history/c_cleared_history.h"

class c_start_browsers
{

public:

	static void start_browser_checks ( );

};

inline auto c_browsers = std::make_unique < c_start_browsers > ( );