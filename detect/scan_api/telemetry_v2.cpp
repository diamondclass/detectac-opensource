#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "telemetry_v2.hpp"
#include "telemetry_v2_keys.hpp"

#include "../utils/crypt/cng_crypto.h"
#include "../utils/crypt/crypto_init.h"
#include "../utils/crypt/secure_buffer.h"
#include "../utils/crypt/xorstr.h"

#include <curl/curl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstring>

namespace telemetry_v2
{

namespace
{

constexpr size_t max_session_id_len = 128;
constexpr size_t max_pin_len        = 64;

auto is_sane_pin(std::string_view p) noexcept -> bool
{
    if (p.empty() || p.size() > max_pin_len) return false;
    for (char c : p)
    {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '-' || c == '_';
        if (!ok) return false;
    }
    return true;
}

auto is_sane_session_id(std::string_view id) noexcept -> bool
{
    if (id.empty() || id.size() > max_session_id_len) return false;
    for (char c : id)
    {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
                        (c >= 'A' && c <= 'Z') || c == '-' || c == '_' || c == '.';
        if (!ok) return false;
    }
    return true;
}

struct b64_tables
{
    char   enc[65];
    int8_t dec[256];

    b64_tables() noexcept
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

auto tables() noexcept -> const b64_tables&
{
    static const b64_tables t;
    return t;
}

auto b64_encode(const uint8_t* data, size_t len) -> std::string
{
    const auto& t = tables();
    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < len)
    {
        const uint32_t n = (uint32_t(data[i]) << 16) | (uint32_t(data[i + 1]) << 8) | uint32_t(data[i + 2]);
        out.push_back(t.enc[(n >> 18) & 0x3F]);
        out.push_back(t.enc[(n >> 12) & 0x3F]);
        out.push_back(t.enc[(n >> 6) & 0x3F]);
        out.push_back(t.enc[n & 0x3F]);
        i += 3;
    }
    if (i < len)
    {
        uint32_t n = uint32_t(data[i]) << 16;
        if (i + 1 < len) n |= uint32_t(data[i + 1]) << 8;
        out.push_back(t.enc[(n >> 18) & 0x3F]);
        out.push_back(t.enc[(n >> 12) & 0x3F]);
        out.push_back((i + 1 < len) ? t.enc[(n >> 6) & 0x3F] : '=');
        out.push_back('=');
    }
    return out;
}

auto b64_decode(std::string_view in, std::vector<uint8_t>& out) -> bool
{
    const auto& t = tables();

    out.clear();
    if (in.empty()) return true;
    if (in.size() % 4 != 0) return false;

    const size_t quads = in.size() / 4;
    out.reserve(quads * 3);

    for (size_t q = 0; q < quads; ++q)
    {
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

struct response_sink
{
    std::string* body     = nullptr;
    size_t       max_bytes = 0;
};

auto curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t
{
    auto* sink = static_cast<response_sink*>(userdata);
    if (!sink || !sink->body) return 0;

    const size_t bytes = size * nmemb;
    if (sink->body->size() + bytes > sink->max_bytes) return 0;
    sink->body->append(ptr, bytes);
    return bytes;
}

auto http_post_json(std::string_view url, std::string_view body,
                    size_t max_bytes, std::string& out_response) -> bool
{
    out_response.clear();

    CURL* curl = curl_easy_init();
    if (!curl) return false;

    const auto pin       = spki_pin();
    const std::string user_agent = xorstr_("detect-ss-telemetry/2");
    const std::string hdr_type   = xorstr_("Content-Type: application/json");
    const std::string hdr_accept = xorstr_("Accept: application/json");
    const std::string hdr_expect = xorstr_("Expect:");
    const std::string proto_only = xorstr_("https");
    const std::string no_proxy   = xorstr_("*");

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, hdr_type.c_str());
    headers = curl_slist_append(headers, hdr_accept.c_str());
    headers = curl_slist_append(headers, hdr_expect.c_str());

    response_sink sink{ &out_response, max_bytes };

    const std::string url_z(url);
    const std::string body_z(body);

    curl_easy_setopt(curl, CURLOPT_URL, url_z.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_z.size());
    curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, body_z.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, (long)CURLSSLOPT_NATIVE_CA);
    curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pin.c_str());
    curl_easy_setopt(curl, CURLOPT_SSLVERSION, (long)CURL_SSLVERSION_TLSv1_2);

    curl_easy_setopt(curl, CURLOPT_PROXY, "");
    curl_easy_setopt(curl, CURLOPT_NOPROXY, no_proxy.c_str());
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, proto_only.c_str());
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, proto_only.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L);

    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)max_bytes);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    const CURLcode rc = curl_easy_perform(curl);
    long http_status  = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (rc != CURLE_OK || http_status != 200 || out_response.empty())
    {
        SecureMem::Wipe(out_response.data(), out_response.size());
        out_response.clear();
        return false;
    }
    return true;
}

auto put_u32_be(std::vector<uint8_t>& out, uint32_t v) -> void
{
    out.push_back(uint8_t((v >> 24) & 0xFF));
    out.push_back(uint8_t((v >> 16) & 0xFF));
    out.push_back(uint8_t((v >> 8)  & 0xFF));
    out.push_back(uint8_t( v        & 0xFF));
}

auto build_aad(std::string_view session_id, uint32_t seq, uint8_t type) -> std::vector<uint8_t>
{
    const auto prefix = aad_prefix();

    std::vector<uint8_t> aad;
    aad.reserve(prefix.size() + session_id.size() + 5);
    aad.insert(aad.end(), prefix.begin(), prefix.end());
    aad.insert(aad.end(), session_id.begin(), session_id.end());
    put_u32_be(aad, seq);
    aad.push_back(type);
    return aad;
}

auto build_nonce_info(uint32_t seq) -> std::vector<uint8_t>
{
    const auto label = hkdf_info_nonce();

    std::vector<uint8_t> info;
    info.reserve(label.size() + 4);
    info.insert(info.end(), label.begin(), label.end());
    put_u32_be(info, seq);
    return info;
}

auto derive_nonce(const uint8_t* session_key, uint32_t seq, uint8_t out[nonce_len]) noexcept -> bool
{
    const auto info = build_nonce_info(seq);
    return Cng::HkdfSha256(session_key, session_key_len,
                           nullptr, 0,
                           info.data(), info.size(),
                           out, nonce_len);
}

auto compute_record_digest(uint32_t seq, uint8_t type,
                           const uint8_t* ciphertext, size_t ct_len,
                           uint8_t out[32]) noexcept -> bool
{
    std::vector<uint8_t> buf;
    buf.reserve(4 + 1 + 4 + ct_len);
    put_u32_be(buf, seq);
    buf.push_back(type);
    put_u32_be(buf, static_cast<uint32_t>(ct_len));
    if (ct_len) buf.insert(buf.end(), ciphertext, ciphertext + ct_len);
    return Cng::Sha256Once(buf.data(), buf.size(), out);
}

auto advance_chain(uint8_t state[chain_tag_len],
                   const uint8_t* chain_key,
                   const uint8_t record_digest[32]) noexcept -> bool
{
    uint8_t buf[chain_tag_len + 32];
    std::memcpy(buf,               state,        chain_tag_len);
    std::memcpy(buf + chain_tag_len, record_digest, 32);
    uint8_t next[chain_tag_len] = {};
    const bool ok = Cng::HmacSha256(chain_key, sub_key_len, buf, sizeof(buf), next);
    SecureMem::Wipe(buf, sizeof(buf));
    if (!ok) return false;
    std::memcpy(state, next, chain_tag_len);
    SecureMem::Wipe(next, chain_tag_len);
    return true;
}

}

struct session::impl
{
    std::mutex                mu;
    bool                      open      = false;
    bool                      finalized = false;
    error                     last_err  = error::none;

    std::string               session_id;
    std::atomic<uint32_t>     next_seq{ 1 };

    SecureMem::SecureBytes    env_key;
    SecureMem::SecureBytes    chain_key;
    SecureMem::SecureBytes    session_key;

    uint8_t                   chain_state[chain_tag_len] = {};

    auto reset_locked() noexcept -> void
    {
        session_key.wipe();
        env_key.wipe();
        chain_key.wipe();
        SecureMem::Wipe(chain_state, sizeof(chain_state));
        session_id.clear();
        open      = false;
        finalized = false;
        next_seq.store(1);
    }

    auto set_error(error e) noexcept -> error
    {
        last_err = e;
        return e;
    }
};

session::session() : impl_(new session::impl()) {}

session::~session()
{
    if (impl_)
    {
        std::lock_guard lk(impl_->mu);
        impl_->reset_locked();
        delete impl_;
        impl_ = nullptr;
    }
}

auto session::is_open() const noexcept -> bool
{
    std::lock_guard lk(impl_->mu);
    return impl_->open && !impl_->finalized;
}

auto session::last_error() const noexcept -> error
{
    std::lock_guard lk(impl_->mu);
    return impl_->last_err;
}

auto session::session_id() const noexcept -> std::string
{
    std::lock_guard lk(impl_->mu);
    return impl_->session_id;
}

auto session::begin(std::string_view pin_view) noexcept -> error
{
    CryptoInit::EnsureInitialized();

    std::lock_guard lk(impl_->mu);
    impl_->reset_locked();

    if (!is_sane_pin(pin_view)) return impl_->set_error(error::not_initialized);

    Cng::X25519Key client_priv;
    uint8_t        client_pub[x25519_pub_len] = {};
    if (!Cng::X25519GenerateKey(client_priv, client_pub))
        return impl_->set_error(error::keygen);

    uint8_t client_nonce[handshake_client_nonce_len] = {};
    if (!Cng::RandBytes(client_nonce, handshake_client_nonce_len))
        return impl_->set_error(error::rng);

    std::string handshake_response;
    {
        nlohmann::json req = nlohmann::json::object();
        req[std::string(xorstr_("pin"))]              = std::string(pin_view);
        req[std::string(xorstr_("client_pubkey"))]    = b64_encode(client_pub, x25519_pub_len);
        req[std::string(xorstr_("client_nonce"))]     = b64_encode(client_nonce, handshake_client_nonce_len);
        req[std::string(xorstr_("protocol_version"))] = protocol_version;
        req[std::string(xorstr_("build_id"))]         = build_id();

        const auto body = req.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
        if (!http_post_json(handshake_url(), body, max_handshake_response_bytes, handshake_response))
            return impl_->set_error(error::handshake_http);
    }

    std::string          sid;
    std::vector<uint8_t> server_pub;
    std::vector<uint8_t> server_nonce_bytes;
    std::vector<uint8_t> handshake_sig;
    {
        const auto j = nlohmann::json::parse(handshake_response.begin(), handshake_response.end(),
                                              nullptr, false);
        SecureMem::Wipe(handshake_response.data(), handshake_response.size());
        handshake_response.clear();

        if (j.is_discarded() || !j.is_object()) return impl_->set_error(error::handshake_parse);

        auto get_str = [&](const char* k, std::string& out) -> bool {
            const auto it = j.find(k);
            if (it == j.end() || !it->is_string()) return false;
            out = it->get<std::string>();
            return true;
        };

        std::string pub_b64, nonce_b64, sig_b64;
        if (!get_str(xorstr_("session_id"), sid) ||
            !get_str(xorstr_("server_pubkey"), pub_b64) ||
            !get_str(xorstr_("server_nonce"), nonce_b64) ||
            !get_str(xorstr_("signature"), sig_b64))
        {
            return impl_->set_error(error::handshake_parse);
        }
        if (!is_sane_session_id(sid)) return impl_->set_error(error::handshake_session_id);
        if (!b64_decode(pub_b64, server_pub) || server_pub.size() != x25519_pub_len)
            return impl_->set_error(error::handshake_server_key);
        if (!b64_decode(nonce_b64, server_nonce_bytes) || server_nonce_bytes.size() != handshake_server_nonce_len)
            return impl_->set_error(error::handshake_server_nonce);
        if (!b64_decode(sig_b64, handshake_sig) || handshake_sig.size() != p256_sig_len)
            return impl_->set_error(error::handshake_signature);
    }

    {
        const auto sig_ctx = handshake_sig_context();
        std::vector<uint8_t> signed_msg;
        signed_msg.reserve(sig_ctx.size() + sid.size() + x25519_pub_len +
                           handshake_client_nonce_len + handshake_server_nonce_len + 4 + build_id().size());
        signed_msg.insert(signed_msg.end(), sig_ctx.begin(), sig_ctx.end());
        signed_msg.insert(signed_msg.end(), sid.begin(), sid.end());
        signed_msg.insert(signed_msg.end(), client_pub, client_pub + x25519_pub_len);
        signed_msg.insert(signed_msg.end(), client_nonce, client_nonce + handshake_client_nonce_len);
        signed_msg.insert(signed_msg.end(), server_pub.begin(), server_pub.end());
        signed_msg.insert(signed_msg.end(), server_nonce_bytes.begin(), server_nonce_bytes.end());
        put_u32_be(signed_msg, protocol_version);
        const auto bid = build_id();
        signed_msg.insert(signed_msg.end(), bid.begin(), bid.end());

        uint8_t server_p256[p256_pub_len] = {};
        if (!load_server_p256_pubkey(server_p256))
            return impl_->set_error(error::key_load);

        const bool sig_ok = Cng::EcdsaP256Verify(server_p256, handshake_sig.data(),
                                                 signed_msg.data(), signed_msg.size());
        SecureMem::Wipe(server_p256, sizeof(server_p256));
        if (!sig_ok) return impl_->set_error(error::handshake_signature);
    }

    SecureMem::SecureBytes shared(session_key_len);
    shared.try_lock_pages();
    if (!Cng::X25519Derive(client_priv, server_pub.data(), shared.data()))
        return impl_->set_error(error::ecdh);
    client_priv.reset();

    std::array<uint8_t, handshake_client_nonce_len + handshake_server_nonce_len> salt{};
    std::memcpy(salt.data(),                          client_nonce,             handshake_client_nonce_len);
    std::memcpy(salt.data() + handshake_client_nonce_len, server_nonce_bytes.data(), handshake_server_nonce_len);

    SecureMem::SecureBytes new_session_key(session_key_len);
    new_session_key.try_lock_pages();
    {
        const auto info = hkdf_info_session_key();
        if (!Cng::HkdfSha256(shared.data(), shared.size(),
                             salt.data(), salt.size(),
                             reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                             new_session_key.data(), session_key_len))
        {
            shared.wipe();
            return impl_->set_error(error::hkdf);
        }
    }
    shared.wipe();

    uint8_t attest[attest_key_len] = {};
    if (!load_client_attest_key(attest))
    {
        new_session_key.wipe();
        return impl_->set_error(error::key_load);
    }

    SecureMem::SecureBytes new_env_key(sub_key_len);
    new_env_key.try_lock_pages();
    {
        const auto info = hkdf_info_env_key();
        if (!Cng::HkdfSha256(new_session_key.data(), new_session_key.size(),
                             attest, attest_key_len,
                             reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                             new_env_key.data(), sub_key_len))
        {
            SecureMem::Wipe(attest, sizeof(attest));
            new_session_key.wipe();
            return impl_->set_error(error::hkdf);
        }
    }

    SecureMem::SecureBytes new_chain_key(sub_key_len);
    new_chain_key.try_lock_pages();
    {
        const auto info = hkdf_info_chain_key();
        if (!Cng::HkdfSha256(new_session_key.data(), new_session_key.size(),
                             attest, attest_key_len,
                             reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                             new_chain_key.data(), sub_key_len))
        {
            SecureMem::Wipe(attest, sizeof(attest));
            new_session_key.wipe();
            new_env_key.wipe();
            return impl_->set_error(error::hkdf);
        }
    }

    SecureMem::Wipe(attest, sizeof(attest));

    impl_->session_id  = std::move(sid);
    impl_->env_key     = std::move(new_env_key);
    impl_->chain_key   = std::move(new_chain_key);
    impl_->session_key = std::move(new_session_key);
    std::memset(impl_->chain_state, 0, chain_tag_len);
    impl_->next_seq.store(1);
    impl_->open      = true;
    impl_->finalized = false;
    impl_->last_err  = error::none;
    return error::none;
}

namespace
{

struct seal_snapshot
{
    uint32_t seq_before        = 0;
    uint8_t  chain_before[chain_tag_len] = {};
};

auto seal_record(session::impl& s, uint8_t type,
                 std::string_view plaintext_json,
                 uint32_t& out_seq,
                 std::vector<uint8_t>& out_ciphertext,
                 uint8_t out_chain_tag[chain_tag_len],
                 seal_snapshot& snap) noexcept -> error
{
    if (!s.open || s.finalized) return error::not_initialized;

    if (plaintext_json.size() > max_record_plaintext_bytes)
        return error::payload_too_large;

    snap.seq_before = s.next_seq.load();
    std::memcpy(snap.chain_before, s.chain_state, chain_tag_len);

    out_seq = s.next_seq.fetch_add(1);

    uint8_t nonce_buf[nonce_len] = {};
    if (!derive_nonce(s.session_key.data(), out_seq, nonce_buf)) return error::hkdf;

    const auto aad = build_aad(s.session_id, out_seq, type);

    out_ciphertext.assign(plaintext_json.size() + gcm_tag_len, 0);
    size_t written = 0;
    if (!Cng::AesGcmEncryptInto(s.env_key.data(), s.env_key.size(),
                                nonce_buf, nonce_len,
                                aad.data(), aad.size(),
                                reinterpret_cast<const uint8_t*>(plaintext_json.data()), plaintext_json.size(),
                                out_ciphertext.data(), out_ciphertext.size(), written))
    {
        SecureMem::Wipe(nonce_buf, nonce_len);
        SecureMem::Wipe(out_ciphertext.data(), out_ciphertext.size());
        out_ciphertext.clear();
        return error::aead_seal;
    }
    out_ciphertext.resize(written);
    SecureMem::Wipe(nonce_buf, nonce_len);

    uint8_t digest[32] = {};
    if (!compute_record_digest(out_seq, type, out_ciphertext.data(), out_ciphertext.size(), digest))
        return error::aead_seal;

    if (!advance_chain(s.chain_state, s.chain_key.data(), digest))
    {
        SecureMem::Wipe(digest, sizeof(digest));
        return error::aead_seal;
    }
    SecureMem::Wipe(digest, sizeof(digest));

    std::memcpy(out_chain_tag, s.chain_state, chain_tag_len);
    return error::none;
}

auto rewind_on_failure(session::impl& s, const seal_snapshot& snap) noexcept -> void
{
    s.next_seq.store(snap.seq_before);
    std::memcpy(s.chain_state, snap.chain_before, chain_tag_len);
}

auto post_record(std::string_view url, std::string_view session_id, uint32_t seq, uint8_t type,
                 const std::vector<uint8_t>& ciphertext,
                 const uint8_t chain_tag[chain_tag_len]) -> error
{
    nlohmann::json body = nlohmann::json::object();
    body[std::string(xorstr_("session_id"))] = std::string(session_id);
    body[std::string(xorstr_("seq"))]        = seq;
    body[std::string(xorstr_("type"))]       = type;
    body[std::string(xorstr_("ciphertext"))] = b64_encode(ciphertext.data(), ciphertext.size());
    body[std::string(xorstr_("chain_tag"))]  = b64_encode(chain_tag, chain_tag_len);

    const auto encoded = body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::string response;
    const bool ok = http_post_json(url, encoded, max_record_response_bytes, response);
    if (!ok) return error::record_http;

    const auto j = nlohmann::json::parse(response.begin(), response.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) return error::record_response;

    const auto it_status = j.find(xorstr_("status"));
    if (it_status == j.end() || !it_status->is_string()) return error::record_response;
    if (it_status->get<std::string>() != xorstr_("ok")) return error::record_response;
    return error::none;
}

}

namespace
{

auto do_send_typed(session::impl& s, uint8_t type, std::string_view plaintext) noexcept -> error
{
    if (!s.open || s.finalized) return error::not_initialized;

    uint32_t seq = 0;
    std::vector<uint8_t> ct;
    uint8_t tag[chain_tag_len] = {};
    seal_snapshot snap{};
    const auto rc = seal_record(s, type, plaintext, seq, ct, tag, snap);
    if (rc != error::none)
    {
        rewind_on_failure(s, snap);
        return rc;
    }

    const auto sent = post_record(record_url(), s.session_id, seq, type, ct, tag);
    SecureMem::Wipe(tag, sizeof(tag));
    SecureMem::Wipe(ct.data(), ct.size());

    if (sent != error::none) rewind_on_failure(s, snap);
    return sent;
}

}

auto session::send_stage_update(int stage, std::string_view message) noexcept -> error
{
    std::lock_guard lk(impl_->mu);

    nlohmann::json j = nlohmann::json::object();
    j[xorstr_("stage")]   = stage;
    j[xorstr_("message")] = std::string(message);
    const auto pt = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

    return impl_->set_error(do_send_typed(*impl_, record_type_stage_update, pt));
}

auto session::send_log_batch(std::string_view logs_json) noexcept -> error
{
    std::lock_guard lk(impl_->mu);
    return impl_->set_error(do_send_typed(*impl_, record_type_log_batch, logs_json));
}

auto session::send_integrity(const integrity_signals& signals) noexcept -> error
{
    std::lock_guard lk(impl_->mu);

    nlohmann::json j = nlohmann::json::object();
    j[xorstr_("debugger_present")]    = signals.debugger_present;
    j[xorstr_("image_hash_mismatch")] = signals.image_hash_mismatch;
    j[xorstr_("admin_context")]       = signals.admin_context;
    j[xorstr_("syscall_stubs_ok")]    = signals.syscall_stubs_ok;
    j[xorstr_("detected_bits")]       = signals.detected_bits;
    j[xorstr_("module_count")]        = signals.module_count;
    j[xorstr_("boot_time_seconds")]   = signals.boot_time_seconds;

    const auto pt = j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

    return impl_->set_error(do_send_typed(*impl_, record_type_integrity, pt));
}

auto session::send_heartbeat() noexcept -> error
{
    std::lock_guard lk(impl_->mu);
    return impl_->set_error(do_send_typed(*impl_, record_type_heartbeat, std::string_view(xorstr_("{}"))));
}

auto session::finalize(std::string_view summary_json) noexcept -> error
{
    std::lock_guard lk(impl_->mu);
    if (!impl_->open) return impl_->set_error(error::not_initialized);
    if (impl_->finalized) return impl_->set_error(error::already_finalized);

    uint32_t seq = 0;
    std::vector<uint8_t> ct;
    uint8_t tag[chain_tag_len] = {};
    seal_snapshot snap{};
    const auto rc = seal_record(*impl_, record_type_finalize, summary_json, seq, ct, tag, snap);
    if (rc != error::none)
    {
        rewind_on_failure(*impl_, snap);
        return impl_->set_error(rc);
    }

    nlohmann::json body = nlohmann::json::object();
    body[std::string(xorstr_("session_id"))] = impl_->session_id;
    body[std::string(xorstr_("seq"))]        = seq;
    body[std::string(xorstr_("type"))]       = static_cast<uint8_t>(record_type_finalize);
    body[std::string(xorstr_("ciphertext"))] = b64_encode(ct.data(), ct.size());
    body[std::string(xorstr_("chain_tag"))]  = b64_encode(tag, chain_tag_len);

    SecureMem::Wipe(tag, sizeof(tag));
    SecureMem::Wipe(ct.data(), ct.size());

    const auto encoded = body.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    std::string response;
    if (!http_post_json(finalize_url(), encoded, max_record_response_bytes, response))
    {
        rewind_on_failure(*impl_, snap);
        return impl_->set_error(error::finalize_http);
    }

    const auto j = nlohmann::json::parse(response.begin(), response.end(), nullptr, false);
    if (j.is_discarded() || !j.is_object())
    {
        rewind_on_failure(*impl_, snap);
        return impl_->set_error(error::record_response);
    }
    const auto it_status = j.find(xorstr_("status"));
    if (it_status == j.end() || !it_status->is_string())
    {
        rewind_on_failure(*impl_, snap);
        return impl_->set_error(error::record_response);
    }
    if (it_status->get<std::string>() != xorstr_("ok"))
    {
        rewind_on_failure(*impl_, snap);
        return impl_->set_error(error::record_response);
    }

    impl_->finalized = true;
    impl_->last_err  = error::none;
    return error::none;
}

auto shared_session() -> session&
{
    static session s;
    return s;
}

auto derive_log_chain_key(uint8_t out[32]) noexcept -> bool
{
    auto& s = shared_session();
    std::lock_guard lk(s.impl_->mu);
    if (!s.impl_->open || s.impl_->session_key.empty()) return false;

    uint8_t attest[attest_key_len] = {};
    if (!load_client_attest_key(attest)) return false;

    const auto info = hkdf_info_log_chain_key();
    const bool ok = Cng::HkdfSha256(s.impl_->session_key.data(), s.impl_->session_key.size(),
                                     attest, attest_key_len,
                                     reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                                     out, 32);
    SecureMem::Wipe(attest, sizeof(attest));
    return ok;
}

auto derive_log_entry_seal_key(uint8_t out[32]) noexcept -> bool
{
    auto& s = shared_session();
    std::lock_guard lk(s.impl_->mu);
    if (!s.impl_->open || s.impl_->session_key.empty()) return false;

    uint8_t attest[attest_key_len] = {};
    if (!load_client_attest_key(attest)) return false;

    const auto info = hkdf_info_log_seal_key();
    const bool ok = Cng::HkdfSha256(s.impl_->session_key.data(), s.impl_->session_key.size(),
                                     attest, attest_key_len,
                                     reinterpret_cast<const uint8_t*>(info.data()), info.size(),
                                     out, 32);
    SecureMem::Wipe(attest, sizeof(attest));
    return ok;
}

auto session_bind_material(uint8_t out[32]) noexcept -> bool
{
    auto& s = shared_session();
    std::lock_guard lk(s.impl_->mu);
    if (!s.impl_->open || s.impl_->session_id.empty()) return false;
    return Cng::Sha256Once(reinterpret_cast<const uint8_t*>(s.impl_->session_id.data()),
                           s.impl_->session_id.size(), out);
}

}
