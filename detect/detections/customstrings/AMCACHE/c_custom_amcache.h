#pragma once

#include "../../../pch.h"

class AmcacheReader2 {
public:

    static void ProcessAmcache();
    static std::wstring s2ws(const std::string& str);
    static std::string fetch_json(const std::wstring& url);
    static void load_sha1_filters_from_endpoint();
};

inline auto c_camcache = std::make_unique<AmcacheReader2>();
