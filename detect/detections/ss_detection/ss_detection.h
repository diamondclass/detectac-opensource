#pragma once

#include "../../pch.h"

class SsDetection {
public:
    static void start_ss_detection() noexcept;
};

inline auto c_ss = std::make_unique<SsDetection>();
