#pragma once

#include "../../../pch.h"

struct AmcacheEntry {
    std::string path;
    std::string sha1;
    std::string timestamp;
    ULONGLONG   sizeBytes = 0;
    bool        pathIsKeyName = false;
};

class AmcacheFilters {
public:
    static void start_amcache_scan() noexcept;
    static bool GetAmcacheEntries(std::vector<AmcacheEntry>& out) noexcept;
};

inline auto c_amc = std::make_unique<AmcacheFilters>();