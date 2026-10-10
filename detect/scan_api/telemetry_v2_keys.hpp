#pragma once

#include "../utils/crypt/xorstr.h"
#include "../detections/client_checks/yara_scanner/rule_delivery_keys.h"

#include <cstdint>
#include <string>

namespace telemetry_v2
{

constexpr uint32_t protocol_version = 2;

constexpr uint32_t max_handshake_response_bytes = 4 * 1024;
constexpr uint32_t max_record_response_bytes    = 4 * 1024;
constexpr uint32_t max_record_plaintext_bytes   = 4 * 1024 * 1024;

constexpr uint32_t handshake_client_nonce_len = 16;
constexpr uint32_t handshake_server_nonce_len = 16;
constexpr uint32_t session_key_len            = 32;
constexpr uint32_t sub_key_len                = 32;
constexpr uint32_t nonce_len                  = 12;
constexpr uint32_t gcm_tag_len                = 16;
constexpr uint32_t chain_tag_len              = 32;
constexpr uint32_t attest_key_len             = 32;
constexpr uint32_t p256_pub_len               = 64;
constexpr uint32_t p256_sig_len               = 64;
constexpr uint32_t x25519_pub_len             = 32;

enum record_type : uint8_t
{
    record_type_stage_update = 0x01,
    record_type_log_batch    = 0x02,
    record_type_integrity    = 0x03,
    record_type_heartbeat    = 0x04,
    record_type_finalize     = 0xFF,
};

inline auto handshake_url() -> std::string
{
    return xorstr_("https://detect.ac/auth/api/scanning/v2/handshake");
}

inline auto record_url() -> std::string
{
    return xorstr_("https://detect.ac/auth/api/scanning/v2/record");
}

inline auto finalize_url() -> std::string
{
    return xorstr_("https://detect.ac/auth/api/scanning/v2/finalize");
}

inline auto spki_pin() -> std::string
{
    return RuleDelivery::SpkiPin();
}

inline auto hkdf_info_session_key() -> std::string
{
    return xorstr_("detect-telemetry-key-v1");
}

inline auto hkdf_info_env_key() -> std::string
{
    return xorstr_("detect-telemetry-env-v1");
}

inline auto hkdf_info_chain_key() -> std::string
{
    return xorstr_("detect-telemetry-chain-v1");
}

inline auto hkdf_info_log_chain_key() -> std::string
{
    return xorstr_("detect-log-entry-chain-v1");
}

inline auto hkdf_info_log_seal_key() -> std::string
{
    return xorstr_("detect-log-entry-seal-v1");
}

inline auto hkdf_info_nonce() -> std::string
{
    return xorstr_("detect-telemetry-nonce-v1");
}

inline auto aad_prefix() -> std::string
{
    return xorstr_("detect-telemetry-aad-v1");
}

inline auto handshake_sig_context() -> std::string
{
    return xorstr_("detect-telemetry-hs-v1");
}

inline auto build_id() -> std::string
{
#if defined(DETECT_MINECRAFT)
    return xorstr_("detect-mc");
#elif defined(DETECT_FIVEM)
    return xorstr_("detect-fm");
#elif defined(DETECT_GMOD)
    return xorstr_("detect-gm");
#elif defined(DETECT_FREEFIRE)
    return xorstr_("detect-ff");
#elif defined(DETECT_ROBLOX)
    return xorstr_("detect-rb");
#elif defined(DETECT_FORTNITE)
    return xorstr_("detect-fn");
#elif defined(DETECT_COD)
    return xorstr_("detect-cod");
#elif defined(DETECT_RUST)
    return xorstr_("detect-ru");
#elif defined(DETECT_DAYZ)
    return xorstr_("detect-dz");
#elif defined(DETECT_SIEGE)
    return xorstr_("detect-r6");
#elif defined(DETECT_CS)
    return xorstr_("detect-cs");
#else
    return xorstr_("detect-unknown");
#endif
}


inline auto load_server_p256_pubkey(uint8_t out[p256_pub_len]) noexcept -> bool
{
    return RuleDelivery::LoadServerP256PubKey(out);
}

inline auto load_client_attest_key(uint8_t out[attest_key_len]) noexcept -> bool
{
    return RuleDelivery::LoadClientAttestKey(out);
}

}
