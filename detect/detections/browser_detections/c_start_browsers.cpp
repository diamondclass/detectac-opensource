#include <windows.h>
#include "c_start_browsers.h"

#ifdef DETECT_MINECRAFT

void c_start_browsers::start_browser_checks()
{
    try
    {
        BrowserHistoryScanner::start_history_checks();
        BrowserDownloadScanner::start_download_history();
    }
    catch (...) {}
}

#else

void c_start_browsers::start_browser_checks()
{
    try
    {
        BrowserHistoryScanner::TerminateChromeProcesses();
        BrowserHistoryScanner::start_history_checks();
        BrowserDownloadScanner::start_download_history();
        browser_cleared_scan::start_cleared_check();
        return;
    }
    catch (...) {}
}

#endif
