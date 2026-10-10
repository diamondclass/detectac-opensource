#pragma once

#include "../../pch.h"

class cfg_check
{
public:
    static void start_cfg_check();
};

inline auto c_cfg_check = std::make_unique<cfg_check>();
