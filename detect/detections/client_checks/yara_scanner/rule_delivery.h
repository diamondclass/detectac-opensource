#pragma once

#include "../../../utils/crypt/crash_dump_shield.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace RuleDelivery {

enum class FetchError : uint16_t
{
    None = 0,
    BadPin,
    KeyGen,
    Rand,
    HandshakeHttp,
    HandshakeParse,
    BadServerKey,
    BadServerNonce,
    BadSessionId,
    Ecdh,
    Hkdf,
    RulesHttp,
    RulesParse,
    CounterMismatch,
    BadCiphertext,
    NonceDerive,
    GcmAuth,
    BlobTooShort,
    KeyLoad,
    SignatureInvalid,
    VersionMismatch,
    VersionRollback,
    Alloc,
    Auth
};

struct FetchResult
{
    CrashShield::ExcludedRegion plaintext;
    size_t                      rulesLength    = 0;
    uint32_t                    rulesetVersion = 0;
    bool                        ok             = false;
    FetchError                  error          = FetchError::None;
};

FetchResult FetchRules(const std::string& pin);

std::unordered_map<std::string, std::string> ParseNameTable(const char* data, size_t length);

bool StripWarningPrefix(std::string& detectionName);

}
