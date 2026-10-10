#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace telemetry_v2
{

enum class error : uint8_t
{
    none = 0,
    not_initialized,
    handshake_http,
    handshake_parse,
    handshake_signature,
    handshake_server_key,
    handshake_server_nonce,
    handshake_session_id,
    rng,
    key_load,
    keygen,
    ecdh,
    hkdf,
    aead_seal,
    record_http,
    record_response,
    finalize_http,
    already_finalized,
    payload_too_large,
    tls_pin,
};

struct integrity_signals
{
    bool     debugger_present    = false;
    bool     image_hash_mismatch = false;
    bool     admin_context       = true;
    bool     syscall_stubs_ok    = true;
    uint32_t detected_bits       = 0;
    uint32_t module_count        = 0;
    uint64_t boot_time_seconds   = 0;
};

class session
{
public:
    struct impl;

    session();
    ~session();

    session(const session&) = delete;
    session(session&&)      = delete;
    auto operator=(const session&) -> session& = delete;
    auto operator=(session&&)      -> session& = delete;

    [[nodiscard]] auto begin(std::string_view pin) noexcept -> error;

    [[nodiscard]] auto send_stage_update(int stage, std::string_view message) noexcept -> error;
    [[nodiscard]] auto send_log_batch(std::string_view logs_json) noexcept -> error;
    [[nodiscard]] auto send_integrity(const integrity_signals& signals) noexcept -> error;
    [[nodiscard]] auto send_heartbeat() noexcept -> error;

    [[nodiscard]] auto finalize(std::string_view summary_json) noexcept -> error;

    [[nodiscard]] auto is_open() const noexcept -> bool;
    [[nodiscard]] auto last_error() const noexcept -> error;
    [[nodiscard]] auto session_id() const noexcept -> std::string;

private:
    friend auto derive_log_chain_key(uint8_t out[32]) noexcept -> bool;
    friend auto derive_log_entry_seal_key(uint8_t out[32]) noexcept -> bool;
    friend auto session_bind_material(uint8_t out[32]) noexcept -> bool;

    impl* impl_;
};

auto shared_session() -> session&;

auto derive_log_chain_key(uint8_t out[32]) noexcept -> bool;
auto derive_log_entry_seal_key(uint8_t out[32]) noexcept -> bool;
auto session_bind_material(uint8_t out[32]) noexcept -> bool;

}
