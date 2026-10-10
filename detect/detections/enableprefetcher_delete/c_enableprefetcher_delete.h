#pragma once

#include "../../pch.h"

class PrefetchCheck
{
public:
    static FILETIME GetRegistryKeyLastWriteTime();
    static FILETIME GetUserLogonTime();
    static bool IsAfterOneMinute(const FILETIME& ftLastWrite, const FILETIME& ftLogon);
    static LONGLONG FileTimeToInt64(const FILETIME& ft);
    static std::string FormatFileTimeAsLocal(const FILETIME& ftUtc);
    static void start_enableprefetcherdeletion();
};

inline auto c_prefcheck = std::make_unique<PrefetchCheck>();
