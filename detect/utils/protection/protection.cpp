#include <Windows.h>
#include <atomic>
#include <thread>
#include <chrono>
#include <random>

#include "protection.h"
#include "direct_syscall.h"
#include "anti_debug.h"
#include "integrity_check.h"
#include "process_disguise.h"

namespace protection {

namespace {

std::atomic<bool>     g_initialized{false};
std::atomic<bool>     g_initResult{false};
std::atomic<bool>     g_compromised{false};
std::atomic<uint64_t> g_watchdogLastTickSeconds{0};

void MarkCompromised() noexcept { g_compromised = true; }

[[maybe_unused]] void WatchdogMain() noexcept {
    try {
        antidebug::HideCurrentThread();
        std::mt19937 rng{ static_cast<unsigned>(GetTickCount64()) };
        std::uniform_int_distribution<int> jitterMs{ 5000, 10000 };

        for (;;) {
            try {
                unsigned dbg = antidebug::RunAllChecks();
                bool     ok  = integrity::Verify();

                if (dbg || !ok) MarkCompromised();

                if (syscalls::IsAvailable()) (void)syscalls::Reverify();

                g_watchdogLastTickSeconds.store(GetTickCount64() / 1000ULL,
                                                std::memory_order_release);
            } catch (...) {}

            int sleepMs = jitterMs(rng);
            Sleep(static_cast<DWORD>(sleepMs));
        }
    } catch (...) {}
}

bool DoInitialize_CxxStage() noexcept {
    bool overall = true;
    try {
        if (!syscalls::Initialize())  overall = false;

        antidebug::HideCurrentThread();

        if (!integrity::Initialize()) overall = false;

        unsigned hits = 0;
        try {
            hits += antidebug::RunAllChecks();
            if (!integrity::Verify()) ++hits;
        } catch (...) {}
        if (hits) MarkCompromised();

    } catch (...) { overall = false; }
    return overall;
}

bool DoInitialize_SehWrapped() noexcept {
    __try {
        return DoInitialize_CxxStage();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

bool Initialize() noexcept {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) {
        return g_initResult.load();
    }

    bool overall = DoInitialize_SehWrapped();

    g_initResult = overall;
    return overall;
}

bool IsCompromised() noexcept { return g_compromised.load(); }

uint64_t WatchdogLastTickSeconds() noexcept {
    return g_watchdogLastTickSeconds.load(std::memory_order_acquire);
}

bool IsWatchdogAlive(uint64_t max_age_seconds) noexcept {
    const uint64_t last = g_watchdogLastTickSeconds.load(std::memory_order_acquire);
    if (last == 0) return true;
    const uint64_t now = GetTickCount64() / 1000ULL;
    if (now < last) return true;
    return (now - last) <= max_age_seconds;
}

}
