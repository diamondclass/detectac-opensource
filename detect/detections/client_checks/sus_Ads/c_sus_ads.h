#pragma once

#include "../../../pch.h"

class SusAds {
public:
    SusAds() = default;
    SusAds(const SusAds&) = delete;
    SusAds& operator=(const SusAds&) = delete;

    static void start_sus_ads();
};

inline auto c_ads = std::make_unique<SusAds>();