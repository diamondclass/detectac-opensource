#pragma once

#include "../../pch.h"

class LetterlessVolumeChecker
{
public:
    static void start_letterless_volume_check();
};

inline auto c_letvol = std::make_unique<LetterlessVolumeChecker>();
