#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include "../crypt/cng_crypto.h"
#include "../crypt/secure_buffer.h"

#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string_view>
#include <vector>

namespace log_tamper_guard
{

constexpr size_t chain_state_len = 32;
constexpr size_t chain_tag_len   = 32;
constexpr size_t seal_key_len    = 32;
constexpr size_t seal_nonce_len  = 12;
constexpr size_t seal_tag_len    = 16;
constexpr size_t page_mask_len   = 64;
constexpr size_t sid_bind_len    = 32;
constexpr size_t max_entries     = 16 * 1024;
constexpr size_t max_entry_bytes = 32 * 1024;

struct sealed_entry
{
    uint32_t             seq          = 0;
    uint8_t              chain_tag[chain_tag_len] = {};
    std::vector<uint8_t> ciphertext;
};

struct batch
{
    std::vector<sealed_entry> entries;
    uint8_t                   terminal_tag[chain_tag_len] = {};
    uint32_t                  log_call_count = 0;
    uint32_t                  drops_on_append = 0;
    uint32_t                  flush_epoch     = 0;
};

class guarded_chain
{
public:
    guarded_chain() noexcept = default;

    ~guarded_chain()
    {
        wipe_and_free();
    }

    guarded_chain(const guarded_chain&)                    = delete;
    guarded_chain(guarded_chain&&)                         = delete;
    auto operator=(const guarded_chain&) -> guarded_chain& = delete;
    auto operator=(guarded_chain&&)      -> guarded_chain& = delete;

    auto seed(const uint8_t chain_key[chain_state_len],
              const uint8_t seal_key[seal_key_len],
              const uint8_t session_bind[sid_bind_len],
              uint64_t process_binding_id) noexcept -> bool
    {
        std::lock_guard lk(mu_);
        if (seeded_.load()) return false;

        protected_ = static_cast<protected_block*>(VirtualAlloc(
            nullptr, sizeof(protected_block),
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!protected_) return false;

        mask_ = static_cast<uint8_t*>(VirtualAlloc(
            nullptr, page_mask_len,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!mask_) { VirtualFree(protected_, 0, MEM_RELEASE); protected_ = nullptr; return false; }

        Cng::RandBytes(mask_, page_mask_len);

        std::memset(protected_->state, 0, chain_state_len);
        std::memcpy(protected_->chain_key,    chain_key,    chain_state_len);
        std::memcpy(protected_->seal_key,     seal_key,     seal_key_len);
        std::memcpy(protected_->session_bind, session_bind, sid_bind_len);
        protected_->process_binding = process_binding_id;

        obfuscate();

        protected_locked_ = (VirtualLock(protected_, sizeof(protected_block)) != FALSE);
        mask_locked_      = (VirtualLock(mask_, page_mask_len) != FALSE);

        next_seq_.store(1);
        entries_.clear();
        log_call_count_.store(0);
        drops_on_append_.store(0);
        flush_epoch_.store(1);
        finalized_.store(false);
        seeded_.store(true);
        return true;
    }

    auto increment_call_counter() noexcept -> void
    {
        log_call_count_.fetch_add(1);
    }

    auto append(std::string_view entry_bytes, uint32_t& out_seq, uint8_t out_tag[chain_tag_len]) noexcept -> bool
    {
        std::lock_guard lk(mu_);
        if (!seeded_.load())                      { drops_on_append_.fetch_add(1); return false; }
        if (finalized_.load())                    { drops_on_append_.fetch_add(1); return false; }
        if (entry_bytes.size() > max_entry_bytes) { drops_on_append_.fetch_add(1); return false; }
        if (entries_.size() >= max_entries)       { drops_on_append_.fetch_add(1); return false; }
        if (GetCurrentProcessId() != protected_pid()) { poison_locked(); return false; }

        deobfuscate();

        uint8_t entry_digest[32] = {};
        if (!Cng::Sha256Once(reinterpret_cast<const uint8_t*>(entry_bytes.data()), entry_bytes.size(), entry_digest))
        {
            obfuscate();
            drops_on_append_.fetch_add(1);
            return false;
        }

        uint32_t seq = next_seq_.fetch_add(1);
        if (seq == 0) { obfuscate(); poison_locked(); drops_on_append_.fetch_add(1); return false; }
        uint8_t seq_be[4] = {
            uint8_t((seq >> 24) & 0xFF),
            uint8_t((seq >> 16) & 0xFF),
            uint8_t((seq >> 8)  & 0xFF),
            uint8_t( seq        & 0xFF),
        };
        uint32_t epoch = flush_epoch_.load();
        uint8_t epoch_be[4] = {
            uint8_t((epoch >> 24) & 0xFF),
            uint8_t((epoch >> 16) & 0xFF),
            uint8_t((epoch >> 8)  & 0xFF),
            uint8_t( epoch        & 0xFF),
        };

        uint8_t hmac_msg[chain_state_len + sid_bind_len + sizeof(seq_be) + sizeof(epoch_be) + 32];
        size_t off = 0;
        std::memcpy(hmac_msg + off, protected_->state,        chain_state_len); off += chain_state_len;
        std::memcpy(hmac_msg + off, protected_->session_bind, sid_bind_len);    off += sid_bind_len;
        std::memcpy(hmac_msg + off, seq_be,   sizeof(seq_be));   off += sizeof(seq_be);
        std::memcpy(hmac_msg + off, epoch_be, sizeof(epoch_be)); off += sizeof(epoch_be);
        std::memcpy(hmac_msg + off, entry_digest, 32);           off += 32;

        uint8_t new_state[chain_state_len] = {};
        if (!Cng::HmacSha256(protected_->chain_key, chain_state_len,
                             hmac_msg, off, new_state))
        {
            SecureMem::Wipe(hmac_msg, sizeof(hmac_msg));
            SecureMem::Wipe(entry_digest, sizeof(entry_digest));
            obfuscate();
            drops_on_append_.fetch_add(1);
            return false;
        }

        std::vector<uint8_t> ct(entry_bytes.size() + seal_tag_len, 0);
        uint8_t nonce[seal_nonce_len] = {};
        derive_nonce(protected_->seal_key, epoch, seq, nonce);

        uint8_t aad[chain_state_len + sid_bind_len + sizeof(seq_be) + sizeof(epoch_be)];
        size_t aoff = 0;
        std::memcpy(aad + aoff, protected_->state,        chain_state_len); aoff += chain_state_len;
        std::memcpy(aad + aoff, protected_->session_bind, sid_bind_len);    aoff += sid_bind_len;
        std::memcpy(aad + aoff, seq_be,   sizeof(seq_be));   aoff += sizeof(seq_be);
        std::memcpy(aad + aoff, epoch_be, sizeof(epoch_be)); aoff += sizeof(epoch_be);

        size_t written = 0;
        if (!Cng::AesGcmEncryptInto(protected_->seal_key, seal_key_len,
                                    nonce, seal_nonce_len,
                                    aad, sizeof(aad),
                                    reinterpret_cast<const uint8_t*>(entry_bytes.data()), entry_bytes.size(),
                                    ct.data(), ct.size(), written))
        {
            SecureMem::Wipe(nonce, sizeof(nonce));
            SecureMem::Wipe(hmac_msg, sizeof(hmac_msg));
            SecureMem::Wipe(entry_digest, sizeof(entry_digest));
            obfuscate();
            drops_on_append_.fetch_add(1);
            return false;
        }
        ct.resize(written);
        SecureMem::Wipe(nonce, sizeof(nonce));

        std::memcpy(protected_->state, new_state, chain_state_len);
        std::memcpy(out_tag,           new_state, chain_state_len);
        out_seq = seq;

        sealed_entry se;
        se.seq = seq;
        std::memcpy(se.chain_tag, new_state, chain_tag_len);
        se.ciphertext = std::move(ct);
        entries_.push_back(std::move(se));

        SecureMem::Wipe(hmac_msg, sizeof(hmac_msg));
        SecureMem::Wipe(entry_digest, sizeof(entry_digest));
        SecureMem::Wipe(new_state, sizeof(new_state));
        obfuscate();
        return true;
    }

    auto take_batch(batch& out) noexcept -> void
    {
        std::lock_guard lk(mu_);
        out.entries = std::move(entries_);
        entries_.clear();

        deobfuscate();
        std::memcpy(out.terminal_tag, protected_->state, chain_tag_len);
        obfuscate();

        out.log_call_count  = log_call_count_.load();
        out.drops_on_append = drops_on_append_.load();
        out.flush_epoch     = flush_epoch_.fetch_add(1);
    }

    auto finalize() noexcept -> void
    {
        finalized_.store(true);
    }

    auto seeded() const noexcept -> bool { return seeded_.load(); }

    auto entry_count() const noexcept -> size_t { return entries_.size(); }

    auto log_call_count() const noexcept -> uint32_t { return log_call_count_.load(); }
    auto drops() const noexcept -> uint32_t { return drops_on_append_.load(); }

private:
    struct protected_block
    {
        uint8_t  state[chain_state_len];
        uint8_t  chain_key[chain_state_len];
        uint8_t  seal_key[seal_key_len];
        uint8_t  session_bind[sid_bind_len];
        uint64_t process_binding;
    };

    auto protected_pid() noexcept -> uint32_t
    {
        deobfuscate();
        uint32_t pid = uint32_t(protected_->process_binding & 0xFFFFFFFFu);
        obfuscate();
        return pid;
    }

    auto poison_locked() noexcept -> void
    {
        finalized_.store(true);
        if (protected_) SecureMem::Wipe(protected_, sizeof(protected_block));
        if (mask_)      SecureMem::Wipe(mask_, page_mask_len);
    }

    auto wipe_and_free() noexcept -> void
    {
        if (protected_)
        {
            if (protected_locked_) VirtualUnlock(protected_, sizeof(protected_block));
            SecureMem::Wipe(protected_, sizeof(protected_block));
            VirtualFree(protected_, 0, MEM_RELEASE);
            protected_        = nullptr;
            protected_locked_ = false;
        }
        if (mask_)
        {
            if (mask_locked_) VirtualUnlock(mask_, page_mask_len);
            SecureMem::Wipe(mask_, page_mask_len);
            VirtualFree(mask_, 0, MEM_RELEASE);
            mask_        = nullptr;
            mask_locked_ = false;
        }
    }

    auto obfuscate() noexcept -> void
    {
        if (!protected_ || !mask_) return;
        auto* p = reinterpret_cast<uint8_t*>(protected_);
        for (size_t i = 0; i < sizeof(protected_block); ++i)
            p[i] ^= mask_[i % page_mask_len];
    }

    auto deobfuscate() noexcept -> void
    {
        obfuscate();
    }

    static auto derive_nonce(const uint8_t key[seal_key_len], uint32_t epoch, uint32_t seq,
                             uint8_t out[seal_nonce_len]) noexcept -> void
    {
        uint8_t info[9] = { 'l','o','g','-','n','o','n','c','e' };
        uint8_t salt[8] = {
            uint8_t((epoch >> 24) & 0xFF), uint8_t((epoch >> 16) & 0xFF),
            uint8_t((epoch >> 8)  & 0xFF), uint8_t( epoch        & 0xFF),
            uint8_t((seq   >> 24) & 0xFF), uint8_t((seq   >> 16) & 0xFF),
            uint8_t((seq   >> 8)  & 0xFF), uint8_t( seq          & 0xFF),
        };
        uint8_t derived[32] = {};
        Cng::HkdfSha256(key, seal_key_len, salt, sizeof(salt),
                        info, sizeof(info), derived, sizeof(derived));
        std::memcpy(out, derived, seal_nonce_len);
        SecureMem::Wipe(derived, sizeof(derived));
    }

    std::mutex                mu_;
    protected_block*          protected_        = nullptr;
    uint8_t*                  mask_             = nullptr;
    bool                      protected_locked_ = false;
    bool                      mask_locked_      = false;
    std::vector<sealed_entry> entries_;
    std::atomic<uint32_t>     next_seq_{ 1 };
    std::atomic<uint32_t>     log_call_count_{ 0 };
    std::atomic<uint32_t>     drops_on_append_{ 0 };
    std::atomic<uint32_t>     flush_epoch_{ 1 };
    std::atomic<bool>         finalized_{ false };
    std::atomic<bool>         seeded_{ false };
};

inline auto instance() -> guarded_chain&
{
    static guarded_chain g;
    return g;
}

}
