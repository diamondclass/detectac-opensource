#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <Windows.h>

#include "rule_delivery.h"
#include "rule_delivery_keys.h"
#include "rule_version_store.hpp"

#include "../../../utils/crypt/xorstr.h"
#include "../../../utils/crypt/crypto_init.h"
#include "../../../utils/crypt/crash_dump_shield.h"
#include "../../../utils/crypt/secure_buffer.h"
#include "../../../utils/crypt/cng_crypto.h"

#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <array>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace RuleDelivery {

namespace {

constexpr size_t X25519_KEY_SIZE     = 32;
constexpr size_t X25519_PUB_SIZE     = 32;
constexpr size_t P256_PUB_SIZE       = 64;
constexpr size_t P256_SIG_SIZE       = 64;
constexpr size_t NONCE_LEN           = 12;
constexpr size_t SESSION_KEY_LEN     = 32;
constexpr size_t CLIENT_NONCE_LEN    = 16;
constexpr size_t SERVER_NONCE_LEN    = 16;
constexpr size_t GCM_TAG_LEN         = 16;
constexpr size_t VERSION_HEADER_LEN  = 4;

constexpr size_t MAX_HANDSHAKE_BYTES = 8 * 1024;
constexpr size_t MAX_RULES_BYTES     = 12 * 1024 * 1024;

constexpr size_t MAX_PIN_LEN         = 64;
constexpr size_t MAX_SESSION_ID_LEN  = 128;
constexpr size_t ATTEST_KEY_LEN      = 32;
constexpr size_t AUTH_KEY_LEN        = 32;
constexpr size_t AUTH_TAG_LEN        = 32;

struct B64Tables
{
    char   enc[65];
    int8_t dec[256];

    B64Tables() noexcept
    {
        size_t n = 0;
        for (char c = 'A'; c <= 'Z'; ++c) enc[n++] = c;
        for (char c = 'a'; c <= 'z'; ++c) enc[n++] = c;
        for (char c = '0'; c <= '9'; ++c) enc[n++] = c;
        enc[n++] = '+';
        enc[n++] = '/';
        enc[n]   = '\0';

        for (int i = 0; i < 256; ++i) dec[i] = -1;
        for (int i = 0; i < 64; ++i)  dec[static_cast<uint8_t>(enc[i])] = static_cast<int8_t>(i);
    }
};

const B64Tables& Tables() noexcept
{
    static const B64Tables t;
    return t;
}

std::string B64Encode(const uint8_t* data, size_t len)
{
    const B64Tables& t = Tables();

    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < len) {
        uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | uint32_t(data[i + 2]);
        out.push_back(t.enc[(n >> 18) & 0x3F]);
        out.push_back(t.enc[(n >> 12) & 0x3F]);
        out.push_back(t.enc[(n >> 6) & 0x3F]);
        out.push_back(t.enc[n & 0x3F]);
        i += 3;
    }
    if (i < len) {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= uint32_t(data[i + 1]) << 8;
        out.push_back(t.enc[(n >> 18) & 0x3F]);
        out.push_back(t.enc[(n >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? t.enc[(n >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

bool B64Decode(const std::string& in, std::vector<uint8_t>& out)
{
    const B64Tables& t = Tables();

    out.clear();
    if (in.empty()) return true;
    if (in.size() % 4 != 0) return false;

    const size_t quads = in.size() / 4;
    out.reserve(quads * 3);

    for (size_t q = 0; q < quads; ++q) {
        const size_t i    = q * 4;
        const bool   last = (q + 1 == quads);

        const char c0 = in[i], c1 = in[i + 1], c2 = in[i + 2], c3 = in[i + 3];
        if (c0 == '=' || c1 == '=') return false;

        const bool pad2 = (c2 == '=');
        const bool pad3 = (c3 == '=');
        if ((pad2 || pad3) && !last) return false;
        if (pad2 && !pad3) return false;

        const int8_t v0 = t.dec[static_cast<uint8_t>(c0)];
        const int8_t v1 = t.dec[static_cast<uint8_t>(c1)];
        const int8_t v2 = pad2 ? 0 : t.dec[static_cast<uint8_t>(c2)];
        const int8_t v3 = pad3 ? 0 : t.dec[static_cast<uint8_t>(c3)];
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) return false;

        if (pad2 && (v1 & 0x0F) != 0) return false;
        if (!pad2 && pad3 && (v2 & 0x03) != 0) return false;

        const uint32_t n = (uint32_t(v0) << 18) | (uint32_t(v1) << 12) |
                           (uint32_t(v2) << 6)  | uint32_t(v3);
        out.push_back(uint8_t((n >> 16) & 0xFF));
        if (!pad2) out.push_back(uint8_t((n >> 8) & 0xFF));
        if (!pad3) out.push_back(uint8_t(n & 0xFF));
    }
    return true;
}

bool IsSanePin(const std::string& pin) noexcept
{
    if (pin.empty() || pin.size() > MAX_PIN_LEN) return false;
    for (char c : pin) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

bool IsSaneSessionID(const std::string& id) noexcept
{
    if (id.empty() || id.size() > MAX_SESSION_ID_LEN) return false;
    for (char c : id) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

bool JsonGetString(const nlohmann::json& j, const std::string& key, std::string& out)
{
    if (!j.is_object()) return false;
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return false;
    out = it->get<std::string>();
    return true;
}

bool JsonGetU32(const nlohmann::json& j, const std::string& key, uint32_t& out)
{
    if (!j.is_object()) return false;
    const auto it = j.find(key);
    if (it == j.end() || !it->is_number_unsigned()) return false;
    const uint64_t v = it->get<uint64_t>();
    if (v > 0xFFFFFFFFull) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

struct ResponseSink
{
    std::string* body     = nullptr;
    size_t       maxBytes = 0;
};

size_t CurlWriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata)
{
    auto* sink = static_cast<ResponseSink*>(userdata);
    if (!sink || !sink->body) return 0;

    const size_t bytes = size * nmemb;
    if (sink->body->size() + bytes > sink->maxBytes) return 0;
    sink->body->append(ptr, bytes);
    return bytes;
}

bool HttpPostJson(const std::string& url, const std::string& body,
                  size_t maxBytes, std::string& outResponse)
{
    outResponse.clear();

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    const std::string pin       = SpkiPin();
    const std::string userAgent = xorstr_("detect-ss-rule-delivery/1");
    const std::string hdrType   = xorstr_("Content-Type: application/json");
    const std::string hdrAccept = xorstr_("Accept: application/json");
    const std::string hdrExpect = xorstr_("Expect:");
    const std::string protoOnly = xorstr_("https");
    const std::string noProxy   = xorstr_("*");

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, hdrType.c_str());
    headers = curl_slist_append(headers, hdrAccept.c_str());
    headers = curl_slist_append(headers, hdrExpect.c_str());

    ResponseSink sink{ &outResponse, maxBytes };

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body.size());
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA);
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin.c_str());
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);

    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, noProxy.c_str());
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, protoOnly.c_str());
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, protoOnly.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)maxBytes);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent.c_str());
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    const CURLcode rc         = curl_easy_perform(curl);
    long           httpStatus = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpStatus);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || httpStatus != 200 || outResponse.empty()) {
        SecureMem::Wipe(outResponse.data(), outResponse.size());
        outResponse.clear();
        return false;
    }
    return true;
}

std::vector<uint8_t> BuildAuthMessage(const std::string& sessionID, uint32_t counter)
{
    const std::string prefix = AuthMsgPrefix();

    std::vector<uint8_t> msg;
    msg.reserve(prefix.size() + sessionID.size() + 4);
    msg.insert(msg.end(), prefix.begin(), prefix.end());
    msg.insert(msg.end(), sessionID.begin(), sessionID.end());
    msg.push_back(uint8_t((counter >> 24) & 0xFF));
    msg.push_back(uint8_t((counter >> 16) & 0xFF));
    msg.push_back(uint8_t((counter >> 8) & 0xFF));
    msg.push_back(uint8_t(counter & 0xFF));
    return msg;
}

std::vector<uint8_t> BuildAAD(const std::string& sessionID, uint32_t counter)
{
    const std::string prefix = AadPrefix();

    std::vector<uint8_t> aad;
    aad.reserve(prefix.size() + sessionID.size() + 4);
    aad.insert(aad.end(), prefix.begin(), prefix.end());
    aad.insert(aad.end(), sessionID.begin(), sessionID.end());
    aad.push_back(uint8_t((counter >> 24) & 0xFF));
    aad.push_back(uint8_t((counter >> 16) & 0xFF));
    aad.push_back(uint8_t((counter >> 8) & 0xFF));
    aad.push_back(uint8_t(counter & 0xFF));
    return aad;
}

std::vector<uint8_t> BuildNonceInfo(uint32_t counter)
{
    const std::string label = HkdfInfoNonce();

    std::vector<uint8_t> info;
    info.reserve(label.size() + 4);
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(uint8_t((counter >> 24) & 0xFF));
    info.push_back(uint8_t((counter >> 16) & 0xFF));
    info.push_back(uint8_t((counter >> 8) & 0xFF));
    info.push_back(uint8_t(counter & 0xFF));
    return info;
}

FetchResult Fail(FetchError e)
{
    FetchResult r;
    r.error = e;
    return r;
}

}

FetchResult FetchRules(const std::string& pin)
{
    CryptoInit::EnsureInitialized();

    if (!IsSanePin(pin)) return Fail(FetchError::BadPin);

    Cng::X25519Key clientPriv;
    uint8_t        clientPub[X25519_PUB_SIZE] = {};
    if (!Cng::X25519GenerateKey(clientPriv, clientPub))
        return Fail(FetchError::KeyGen);

    uint8_t clientNonce[CLIENT_NONCE_LEN] = {};
    if (!Cng::RandBytes(clientNonce, CLIENT_NONCE_LEN))
        return Fail(FetchError::Rand);

    std::string handshakeResp;
    {
        nlohmann::json handshakeReq = nlohmann::json::object();
        handshakeReq[std::string(xorstr_("pin"))]           = pin;
        handshakeReq[std::string(xorstr_("client_pubkey"))] = B64Encode(clientPub, X25519_PUB_SIZE);
        handshakeReq[std::string(xorstr_("client_nonce"))]  = B64Encode(clientNonce, CLIENT_NONCE_LEN);
        handshakeReq[std::string(xorstr_("protocol"))]      = uint32_t(CLIENT_PROTOCOL);

        const std::string url  = HandshakeUrl();
        const std::string body = handshakeReq.dump(-1, ' ', false,
                                                   nlohmann::json::error_handler_t::replace);
        if (!HttpPostJson(url, body, MAX_HANDSHAKE_BYTES, handshakeResp))
            return Fail(FetchError::HandshakeHttp);
    }

    std::string          sessionID;
    std::vector<uint8_t> serverPub;
    std::vector<uint8_t> serverNonce;
    {
        const nlohmann::json j = nlohmann::json::parse(handshakeResp.begin(), handshakeResp.end(),
                                                       nullptr, false);
        SecureMem::Wipe(handshakeResp.data(), handshakeResp.size());
        handshakeResp.clear();

        if (j.is_discarded()) return Fail(FetchError::HandshakeParse);

        std::string pubB64, nonceB64;
        if (!JsonGetString(j, xorstr_("session_id"), sessionID) ||
            !JsonGetString(j, xorstr_("server_pubkey"), pubB64) ||
            !JsonGetString(j, xorstr_("server_nonce"), nonceB64))
            return Fail(FetchError::HandshakeParse);

        if (!IsSaneSessionID(sessionID)) return Fail(FetchError::BadSessionId);
        if (!B64Decode(pubB64, serverPub) || serverPub.size() != X25519_PUB_SIZE)
            return Fail(FetchError::BadServerKey);
        if (!B64Decode(nonceB64, serverNonce) || serverNonce.size() != SERVER_NONCE_LEN)
            return Fail(FetchError::BadServerNonce);
    }

    SecureMem::SecureBytes shared(X25519_KEY_SIZE);
    shared.try_lock_pages();
    if (!Cng::X25519Derive(clientPriv, serverPub.data(), shared.data()))
        return Fail(FetchError::Ecdh);
    clientPriv.reset();

    std::array<uint8_t, CLIENT_NONCE_LEN + SERVER_NONCE_LEN> salt{};
    std::memcpy(salt.data(), clientNonce, CLIENT_NONCE_LEN);
    std::memcpy(salt.data() + CLIENT_NONCE_LEN, serverNonce.data(), SERVER_NONCE_LEN);

    SecureMem::SecureBytes sessionKey(SESSION_KEY_LEN);
    sessionKey.try_lock_pages();
    {
        const std::string info = HkdfInfoSessionKey();
        if (!Cng::HkdfSha256(shared.data(), shared.size(),
                             salt.data(), salt.size(),
                             reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                             sessionKey.data(), SESSION_KEY_LEN)) {
            shared.wipe();
            return Fail(FetchError::Hkdf);
        }
    }
    shared.wipe();

    constexpr uint32_t counter = 1;

    SecureMem::SecureBytes authKey(AUTH_KEY_LEN);
    authKey.try_lock_pages();
    {
        SecureMem::SecureBytes attestKey(ATTEST_KEY_LEN);
        attestKey.try_lock_pages();
        if (!LoadClientAttestKey(attestKey.data())) {
            sessionKey.wipe();
            return Fail(FetchError::KeyLoad);
        }

        const std::string info = HkdfInfoAuth();
        const bool        ok   = Cng::HkdfSha256(sessionKey.data(), sessionKey.size(),
                                                 attestKey.data(), attestKey.size(),
                                                 reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                                                 authKey.data(), AUTH_KEY_LEN);
        attestKey.wipe();
        if (!ok) {
            sessionKey.wipe();
            return Fail(FetchError::Hkdf);
        }
    }

    uint8_t authTag[AUTH_TAG_LEN] = {};
    {
        const auto msg = BuildAuthMessage(sessionID, counter);
        const bool ok  = Cng::HmacSha256(authKey.data(), authKey.size(),
                                         msg.data(), msg.size(),
                                         authTag);
        authKey.wipe();
        if (!ok) {
            sessionKey.wipe();
            return Fail(FetchError::Auth);
        }
    }

    std::string rulesResp;
    {
        nlohmann::json rulesReq = nlohmann::json::object();
        rulesReq[std::string(xorstr_("session_id"))] = sessionID;
        rulesReq[std::string(xorstr_("counter"))]    = counter;
        rulesReq[std::string(xorstr_("auth"))]       = B64Encode(authTag, AUTH_TAG_LEN);

        SecureMem::Wipe(authTag, AUTH_TAG_LEN);

        const std::string url  = RulesUrl();
        const std::string body = rulesReq.dump(-1, ' ', false,
                                               nlohmann::json::error_handler_t::replace);
        if (!HttpPostJson(url, body, MAX_RULES_BYTES, rulesResp)) {
            sessionKey.wipe();
            return Fail(FetchError::RulesHttp);
        }
    }

    std::vector<uint8_t> ciphertext;
    uint32_t             rulesetVersion = 0;
    {
        const nlohmann::json j = nlohmann::json::parse(rulesResp.begin(), rulesResp.end(),
                                                       nullptr, false);
        SecureMem::Wipe(rulesResp.data(), rulesResp.size());
        rulesResp.clear();

        if (j.is_discarded()) { sessionKey.wipe(); return Fail(FetchError::RulesParse); }

        uint32_t echoedCounter = 0;
        if (!JsonGetU32(j, xorstr_("counter"), echoedCounter)) {
            sessionKey.wipe();
            return Fail(FetchError::RulesParse);
        }
        if (echoedCounter != counter) {
            sessionKey.wipe();
            return Fail(FetchError::CounterMismatch);
        }
        if (!JsonGetU32(j, xorstr_("ruleset_version"), rulesetVersion)) {
            sessionKey.wipe();
            return Fail(FetchError::RulesParse);
        }
        if (rulesetVersion < MIN_RULESET_VERSION) {
            sessionKey.wipe();
            return Fail(FetchError::VersionRollback);
        }
        {
            const uint32_t seen_min = rule_version_store::load_min_version();
            if (seen_min != 0 && rulesetVersion < seen_min) {
                sessionKey.wipe();
                return Fail(FetchError::VersionRollback);
            }
        }

        std::string ctB64;
        if (!JsonGetString(j, xorstr_("ciphertext"), ctB64)) {
            sessionKey.wipe();
            return Fail(FetchError::RulesParse);
        }
        if (!B64Decode(ctB64, ciphertext) || ciphertext.size() <= GCM_TAG_LEN) {
            sessionKey.wipe();
            return Fail(FetchError::BadCiphertext);
        }
    }

    const auto nonceInfo         = BuildNonceInfo(counter);
    uint8_t    nonce[NONCE_LEN]  = {};
    if (!Cng::HkdfSha256(sessionKey.data(), sessionKey.size(),
                         nullptr, 0,
                         nonceInfo.data(), nonceInfo.size(),
                         nonce, NONCE_LEN)) {
        sessionKey.wipe();
        return Fail(FetchError::NonceDerive);
    }

    const auto aad = BuildAAD(sessionID, counter);

    CrashShield::ExcludedRegion signedBlob;
    if (!signedBlob.allocate(ciphertext.size())) {
        sessionKey.wipe();
        SecureMem::Wipe(nonce, NONCE_LEN);
        SecureMem::Wipe(ciphertext.data(), ciphertext.size());
        ciphertext.clear();
        return Fail(FetchError::Alloc);
    }

    size_t     signedLen = 0;
    const bool decrypted = Cng::AesGcmDecryptInto(sessionKey.data(), sessionKey.size(),
                                                  nonce, NONCE_LEN,
                                                  aad.data(), aad.size(),
                                                  ciphertext.data(), ciphertext.size(),
                                                  signedBlob.data(), signedBlob.capacity(), signedLen);
    signedBlob.shrink_to(signedLen);

    sessionKey.wipe();
    SecureMem::Wipe(nonce, NONCE_LEN);
    SecureMem::Wipe(ciphertext.data(), ciphertext.size());
    ciphertext.clear();

    if (!decrypted) return Fail(FetchError::GcmAuth);

    if (signedBlob.size() < P256_SIG_SIZE + VERSION_HEADER_LEN)
        return Fail(FetchError::BlobTooShort);

    const uint8_t* sig          = signedBlob.data();
    const uint8_t* plaintext    = signedBlob.data() + P256_SIG_SIZE;
    const size_t   plaintextLen = signedBlob.size() - P256_SIG_SIZE;

    uint8_t serverPubP256[P256_PUB_SIZE] = {};
    if (!LoadServerP256PubKey(serverPubP256))
        return Fail(FetchError::KeyLoad);

    const bool sigOk = Cng::EcdsaP256Verify(serverPubP256, sig, plaintext, plaintextLen);
    SecureMem::Wipe(serverPubP256, sizeof(serverPubP256));
    if (!sigOk) return Fail(FetchError::SignatureInvalid);

    const uint32_t payloadVer = (uint32_t(plaintext[0]) << 24) | (uint32_t(plaintext[1]) << 16) |
                                (uint32_t(plaintext[2]) << 8)  | uint32_t(plaintext[3]);
    if (payloadVer != rulesetVersion) return Fail(FetchError::VersionMismatch);
    if (payloadVer < MIN_RULESET_VERSION) return Fail(FetchError::VersionRollback);

    const uint8_t* rulesBytes = plaintext + VERSION_HEADER_LEN;
    const size_t   rulesLen   = plaintextLen - VERSION_HEADER_LEN;

    FetchResult result;
    if (!result.plaintext.allocate(rulesLen + 1))
        return Fail(FetchError::Alloc);

    if (rulesLen) std::memcpy(result.plaintext.data(), rulesBytes, rulesLen);
    result.plaintext.data()[rulesLen] = 0;
    result.plaintext.shrink_to(rulesLen + 1);
    result.rulesLength    = rulesLen;
    result.rulesetVersion = rulesetVersion;
    result.ok             = (rulesLen > 0);
    result.error          = result.ok ? FetchError::None : FetchError::BlobTooShort;

    if (result.ok)
    {
        const uint32_t prior = rule_version_store::load_min_version();
        if (rulesetVersion > prior)
            rule_version_store::persist_min_version(rulesetVersion);
    }

    return result;
}

std::unordered_map<std::string, std::string> ParseNameTable(const char* data, size_t length)
{
    std::unordered_map<std::string, std::string> names;
    try
    {
        if (!data || length == 0)
            return names;

        const std::string tag = xorstr_("// @dn ");

        size_t pos = 0;
        while (pos < length)
        {
            size_t lineEnd = pos;
            while (lineEnd < length && data[lineEnd] != '\n') ++lineEnd;

            size_t lineLen = lineEnd - pos;
            if (lineLen && data[pos + lineLen - 1] == '\r') --lineLen;

            size_t start = pos;
            while (start < pos + lineLen && (data[start] == ' ' || data[start] == '\t')) ++start;
            size_t rest = (pos + lineLen) - start;

            if (rest > tag.size() && std::memcmp(data + start, tag.data(), tag.size()) == 0)
            {
                const char* entry    = data + start + tag.size();
                size_t      entryLen = rest - tag.size();

                const void* barPtr = std::memchr(entry, '|', entryLen);
                if (barPtr)
                {
                    size_t bar = static_cast<size_t>(static_cast<const char*>(barPtr) - entry);

                    std::string identifier(entry, bar);
                    std::string display(entry + bar + 1, entryLen - bar - 1);

                    auto trim = [](std::string& s) {
                        size_t b = s.find_first_not_of(xorstr_(" \t"));
                        if (b == std::string::npos) { s.clear(); return; }
                        size_t e = s.find_last_not_of(xorstr_(" \t"));
                        s = s.substr(b, e - b + 1);
                    };
                    trim(identifier);
                    trim(display);

                    if (!identifier.empty() && !display.empty())
                        names.emplace(std::move(identifier), std::move(display));
                }
            }

            pos = (lineEnd < length) ? lineEnd + 1 : length;
        }
    }
    catch (...) {}
    return names;
}


bool StripWarningPrefix(std::string& detectionName)
{
    try
    {
        const std::string prefix = xorstr_("WARNING");
        if (detectionName.size() < prefix.size())
            return false;

        for (size_t i = 0; i < prefix.size(); ++i)
        {
            if (std::toupper(static_cast<unsigned char>(detectionName[i])) != prefix[i])
                return false;
        }

        size_t pos     = prefix.size();
        size_t skipped = 0;
        while (pos < detectionName.size())
        {
            const char c = detectionName[pos];
            if (c != ' ' && c != '\t' && c != ':' && c != '-' && c != '_')
                break;
            ++pos;
            ++skipped;
        }

        if (skipped == 0 && pos != detectionName.size())
            return false;

        std::string rest = detectionName.substr(pos);
        if (!rest.empty())
            detectionName = rest;
        return true;
    }
    catch (...) { return false; }
}

}
