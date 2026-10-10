#pragma once

#include <string>

namespace protection {
namespace disguise {

bool Initialize() noexcept;
const std::wstring& GetRealOwnPath() noexcept;
const std::wstring& GetDisguisedName() noexcept;

} // namespace disguise
} // namespace protection
