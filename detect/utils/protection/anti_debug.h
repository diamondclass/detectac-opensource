#pragma once

#include <Windows.h>
#include <atomic>

namespace protection {
namespace antidebug {

unsigned RunAllChecks() noexcept;
void HideCurrentThread() noexcept;
bool EverDetected() noexcept;

enum DetectionBits : unsigned {
    kBeingDebugged       = 1u << 0,
    kNtGlobalFlag        = 1u << 1,
    kHeapFlags           = 1u << 2,
    kDebugPort           = 1u << 3,
    kDebugObjectHandle   = 1u << 4,
    kDebugFlags          = 1u << 5,
    kRemoteDebugger      = 1u << 6,
    kHardwareBreakpoint  = 1u << 7,
    kOutputDebugString   = 1u << 8,
};

} // namespace antidebug
} // namespace protection
