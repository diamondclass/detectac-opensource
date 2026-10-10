#pragma once

#include "../../../utils/crypt/xorstr.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace RuleDelivery {

inline std::string SpkiPin()
{
    return xorstr_("sha256//GJS2WVxeKYptrGzcfJIV00jH6a3hR1lsvUSrLaboxHQ=");
}

inline std::string HandshakeUrl()
{
    return xorstr_("https://detect.ac/auth/api/detection/handshake");
}

inline std::string RulesUrl()
{
    return xorstr_("https://detect.ac/auth/api/detection/rules");
}

inline std::string HkdfInfoSessionKey() { return xorstr_("detect-rule-delivery-v1"); }
inline std::string HkdfInfoNonce()      { return xorstr_("detect-rule-nonce-v1"); }
inline std::string AadPrefix()          { return xorstr_("detect-rule-aad-v1"); }
inline std::string HkdfInfoAuth()       { return xorstr_("detect-rule-auth-v2"); }
inline std::string AuthMsgPrefix()      { return xorstr_("detect-rule-req-v2"); }

constexpr uint32_t MIN_RULESET_VERSION = 1;
constexpr uint32_t CLIENT_PROTOCOL     = 2;

namespace detail {

constexpr uint32_t SIGKEY_MASK_SEED = 0x9E3779B9u;
constexpr uint32_t ATTEST_MASK_SEED = 0x517CC1B7u;
constexpr uint64_t SIGKEY_FP_MASK   = 0xA5A5F00DDEADBEEFULL;
constexpr uint64_t ATTEST_FP_MASK   = 0x3C5A17E9B2D4086FULL;

constexpr uint8_t NextMaskByte(uint32_t& state) noexcept
{
    state = state * 1664525u + 1013904223u;
    return static_cast<uint8_t>((state >> 24) & 0xFFu);
}

template <size_t N>
constexpr std::array<uint8_t, N> MaskWith(uint32_t seed,
                                          const std::array<uint8_t, N>& in) noexcept
{
    std::array<uint8_t, N> out{};
    uint32_t               state = seed;
    for (size_t i = 0; i < N; ++i)
        out[i] = static_cast<uint8_t>(in[i] ^ NextMaskByte(state));
    return out;
}

template <size_t N>
constexpr uint64_t FnvBytes(const std::array<uint8_t, N>& in) noexcept
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (uint8_t b : in) {
        h ^= b;
        h *= 0x100000001b3ULL;
    }
    return h;
}

static constexpr std::array<uint8_t, 64> ServerP256Plain() noexcept
{
    return {
        0xcf, 0x0f, 0x24, 0xa9, 0x6d, 0x06, 0x7a, 0x2c,
        0xa3, 0x8d, 0xd0, 0x1f, 0x60, 0x19, 0x6c, 0xfa,
        0xa7, 0x0d, 0xf8, 0x45, 0x75, 0xae, 0x41, 0xc8,
        0xdf, 0xd8, 0xcb, 0x56, 0xa9, 0x9f, 0x3f, 0xa8,
        0xf2, 0x5a, 0x08, 0x36, 0xd2, 0x49, 0xd9, 0xe9,
        0x69, 0x5f, 0x0f, 0x93, 0x48, 0x77, 0xd4, 0x21,
        0xbd, 0xf8, 0x6e, 0xdd, 0xff, 0xc1, 0x86, 0x30,
        0xbd, 0x4a, 0xde, 0x3f, 0x98, 0x05, 0x42, 0x12,
    };
}

static constexpr std::array<uint8_t, 32> ClientAttestPlain() noexcept
{
    return { 0xbb, 0x0a, 0x7d, 0x58, 0x67, 0xdc, 0xa2, 0x1e,
             0xfc, 0x14, 0xe9, 0x16, 0x46, 0x9a, 0x16, 0xac,
             0x68, 0x6b, 0x86, 0xbf, 0x99, 0xe3, 0x51, 0x66,
             0x35, 0x0a, 0x47, 0x08, 0xd8, 0xc9, 0x3e, 0x44 };
}

static constexpr std::array<uint8_t, 64> SERVER_P256_MASKED = MaskWith(SIGKEY_MASK_SEED, ServerP256Plain());
static constexpr uint64_t                SERVER_P256_FP     = FnvBytes(ServerP256Plain()) ^ SIGKEY_FP_MASK;

static constexpr std::array<uint8_t, 32> CLIENT_ATTEST_MASKED = MaskWith(ATTEST_MASK_SEED, ClientAttestPlain());
static constexpr uint64_t                CLIENT_ATTEST_FP     = FnvBytes(ClientAttestPlain()) ^ ATTEST_FP_MASK;

static_assert(MaskWith(SIGKEY_MASK_SEED, SERVER_P256_MASKED) == ServerP256Plain(),
              "p256 pubkey mask does not round-trip");
static_assert(MaskWith(ATTEST_MASK_SEED, CLIENT_ATTEST_MASKED) == ClientAttestPlain(),
              "attest key mask does not round-trip");
static_assert(SIGKEY_MASK_SEED != ATTEST_MASK_SEED,
              "mask seeds must differ or xoring the two blobs leaks the secret one");

}

template <size_t N>
static inline bool LoadMaskedKey(uint32_t seed,
                                 const std::array<uint8_t, N>& masked,
                                 uint64_t fpMask,
                                 uint64_t expectedFp,
                                 uint8_t out[N]) noexcept
{
    uint32_t state = seed;
    for (size_t i = 0; i < N; ++i)
        out[i] = static_cast<uint8_t>(masked[i] ^ detail::NextMaskByte(state));

    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < N; ++i) {
        h ^= out[i];
        h *= 0x100000001b3ULL;
    }

    if ((h ^ fpMask) != expectedFp) {
        for (size_t i = 0; i < N; ++i) out[i] = 0;
        return false;
    }
    return true;
}

static inline bool LoadServerP256PubKey(uint8_t out[64]) noexcept
{
    return LoadMaskedKey<64>(detail::SIGKEY_MASK_SEED, detail::SERVER_P256_MASKED,
                             detail::SIGKEY_FP_MASK, detail::SERVER_P256_FP, out);
}

static inline bool LoadClientAttestKey(uint8_t out[32]) noexcept
{
    return LoadMaskedKey<32>(detail::ATTEST_MASK_SEED, detail::CLIENT_ATTEST_MASKED,
                             detail::ATTEST_FP_MASK, detail::CLIENT_ATTEST_FP, out);
}

}
