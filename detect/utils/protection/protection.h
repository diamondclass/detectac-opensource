#pragma once

#include <cstdint>

namespace protection {

bool Initialize() noexcept;
bool IsCompromised() noexcept;

uint64_t WatchdogLastTickSeconds() noexcept;
bool IsWatchdogAlive(uint64_t max_age_seconds = 30) noexcept;

} // namespace protection
