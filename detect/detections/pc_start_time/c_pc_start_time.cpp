#include "c_pc_start_time.h"

FILETIME PCStartTime::getUserLogonTime()
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

std::string PCStartTime::fileTimeToReadableString(const FILETIME& fileTime)
{
    try{
    SYSTEMTIME systemTime = {};
    if (FileTimeToSystemTime(&fileTime, &systemTime))
    {
        std::ostringstream oss;
        oss << std::setfill('0') << std::setw(2) << systemTime.wDay << xorstr_("/")
            << std::setfill('0') << std::setw(2) << systemTime.wMonth << xorstr_("/")
            << systemTime.wYear << xorstr_(" ")
            << std::setfill('0') << std::setw(2) << systemTime.wHour << xorstr_(":")
            << std::setfill('0') << std::setw(2) << systemTime.wMinute << xorstr_(":")
            << std::setfill('0') << std::setw(2) << systemTime.wSecond;
        return oss.str();
    }
    return xorstr_("");
    }
    catch (...) {}
    return {};
}

std::string PCStartTime::calculateTimeAgo(const FILETIME& localFileTime)
{
    try{
    FILETIME nowUtc = {};
    GetSystemTimeAsFileTime(&nowUtc);

    FILETIME nowLocal = {};
    if (!FileTimeToLocalFileTime(&nowUtc, &nowLocal))
        return xorstr_("");

    ULARGE_INTEGER then = {};
    then.LowPart  = localFileTime.dwLowDateTime;
    then.HighPart = localFileTime.dwHighDateTime;

    ULARGE_INTEGER now = {};
    now.LowPart  = nowLocal.dwLowDateTime;
    now.HighPart = nowLocal.dwHighDateTime;

    if (now.QuadPart < then.QuadPart)
        return xorstr_("");

    time_t elapsed_time = static_cast<time_t>((now.QuadPart - then.QuadPart) / 10000000ULL);

    int minutes = static_cast<int>(elapsed_time / 60);
    int hours = minutes / 60;
    int days = hours / 24;
    int years = days / 365;
    int months = (days % 365) / 30;
    days = (days % 365) % 30;

    std::ostringstream time_ago;
    time_ago << years << (years == 1 ? xorstr_(" year, ") : xorstr_(" years, "));
    time_ago << months << (months == 1 ? xorstr_(" month, ") : xorstr_(" months, "));
    time_ago << days << (days == 1 ? xorstr_(" day, ") : xorstr_(" days, "));
    time_ago << hours % 24 << (hours % 24 == 1 ? xorstr_(" hour, ") : xorstr_(" hours, "));
    time_ago << minutes % 60 << (minutes % 60 == 1 ? xorstr_(" minute") : xorstr_(" minutes"));

    return time_ago.str();
    }
    catch (...) { return ""; }
}

void PCStartTime::start_pc_start_time_check()
{
    try{
    PCStartTime pcStartTime;
    FILETIME logonTime = pcStartTime.getUserLogonTime();

    if (logonTime.dwHighDateTime != 0 || logonTime.dwLowDateTime != 0)
    {
        std::string readableTime = pcStartTime.fileTimeToReadableString(logonTime);
        std::string elapsedTime = pcStartTime.calculateTimeAgo(logonTime);

        if (!elapsedTime.empty())
            LOG ( INFO , readableTime ) << xorstr_("User Logon Time:") << elapsedTime << xorstr_(" ago");
        else
            LOG ( INFO , readableTime ) << xorstr_("User Logon Time:");
    }

    return;
    }
    catch (...) {}
}