#pragma once

#include "../../pch.h"

class DefenderHistory {
public:
    static void QueryDefenderHistory();
    static std::wstring SanitizeString(const std::wstring& input);
    static std::wstring FormatTimestamp(const std::wstring& timestamp);
};

inline auto c_windef = std::make_unique<DefenderHistory>();