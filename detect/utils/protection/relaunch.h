#pragma once

#include <string>

namespace protection {
namespace relaunch {

std::wstring MakeRandomAlnum(int minLen, int maxLen) noexcept;

} // namespace relaunch
} // namespace protection
