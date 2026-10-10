#pragma once

#include "../../pch.h"

class c_atlas_trace
{
public:
    static void start_atlas_trace_scan ( );
};

inline auto c_atlas = std::make_unique<c_atlas_trace> ( );
