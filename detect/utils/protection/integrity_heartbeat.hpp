#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "integrity_snapshot.hpp"
#include "hook_scanner.hpp"
#include "tamper_response.hpp"
#include "../logger/log_tamper_guard.hpp"

#include <atomic>
#include <cstdint>
#include <thread>

namespace integrity_heartbeat
{

class runner
{
public:
    runner() = default;
    ~runner() { stop(); }

    runner(const runner&)                    = delete;
    runner(runner&&)                         = delete;
    auto operator=(const runner&) -> runner& = delete;
    auto operator=(runner&&)      -> runner& = delete;

    auto start(uint32_t interval_seconds = 5) noexcept -> void
    {
        bool expected = false;
        if (!running_.compare_exchange_strong(expected, true)) return;
        interval_ = interval_seconds ? interval_seconds : 5;
        worker_ = std::thread([this] { this->loop(); });
    }

    auto stop() noexcept -> void
    {
        running_.store(false);
        if (worker_.joinable()) worker_.join();
    }

    auto snapshots_committed() const noexcept -> uint32_t { return committed_.load(); }
    auto snapshots_attempted() const noexcept -> uint32_t { return attempted_.load(); }

private:
    auto loop() noexcept -> void
    {
        while (running_.load())
        {
            uint8_t jitter_byte = 0;
            Cng::RandBytes(&jitter_byte, 1);
            const uint32_t jitter_ms = static_cast<uint32_t>(jitter_byte) * 20;
            const uint32_t total_ms  = interval_ * 1000 + jitter_ms;
            for (uint32_t elapsed = 0; elapsed < total_ms && running_.load(); elapsed += 100)
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if (!running_.load()) break;

            attempted_.fetch_add(1);
            const auto snap = integrity_snapshot::capture();
            append_snapshot_to_chain(snap);

            const auto hook = hook_scanner::run_full_scan();
            if (tamper_response::should_trigger_on(hook.bits))
            {
                tamper_response::trigger(xorstr_(L"heartbeat: hook signals detected"));
            }
        }
    }

    auto append_snapshot_to_chain(const integrity_snapshot::snapshot& s) noexcept -> void
    {
        auto& g = log_tamper_guard::instance();
        char buf[768];
        int n = _snprintf_s(buf, _TRUNCATE,
            "{\"type\":\"INTEGRITY_HB\",\"bits\":%u,\"bad_mods\":%u,\"bad_drv\":%u,"
            "\"mod_count\":%u,\"drv_count\":%u,\"boot\":%llu,"
            "\"prologue_diffs\":%u,\"syscall_stub_bad\":%u,"
            "\"hw_bp_threads\":%u,\"iat_hooked\":%u}",
            s.bits, s.bad_modules, s.bad_drivers,
            s.module_count, s.driver_count,
            static_cast<unsigned long long>(s.boot_time_seconds),
            s.ntdll_prologue_diffs, s.syscall_stub_bad,
            s.hardware_bp_threads, s.modules_iat_hooked);
        if (n <= 0) return;

        uint32_t seq = 0;
        uint8_t  tag[log_tamper_guard::chain_tag_len] = {};
        if (g.append(std::string_view(buf, static_cast<size_t>(n)), seq, tag))
            committed_.fetch_add(1);
    }

    std::atomic<bool>     running_{ false };
    std::atomic<uint32_t> committed_{ 0 };
    std::atomic<uint32_t> attempted_{ 0 };
    std::thread           worker_;
    uint32_t              interval_ = 5;
};

inline auto instance() -> runner&
{
    static runner r;
    return r;
}

}
