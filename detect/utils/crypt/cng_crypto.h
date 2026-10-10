#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

#ifndef STATUS_SUCCESS
#  define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

namespace Cng {

inline void SecureWipe(void* p, size_t n) noexcept
{
    if (p && n) SecureZeroMemory(p, n);
}

inline bool RandBytes(uint8_t* buf, size_t len) noexcept
{
    return BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == STATUS_SUCCESS;
}

struct AlgHandle
{
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }
    AlgHandle() = default;
    AlgHandle(const AlgHandle&)            = delete;
    AlgHandle& operator=(const AlgHandle&) = delete;
    AlgHandle(AlgHandle&& o) noexcept : h(o.h) { o.h = nullptr; }
    AlgHandle& operator=(AlgHandle&& o) noexcept
    {
        if (this != &o) { if (h) BCryptCloseAlgorithmProvider(h, 0); h = o.h; o.h = nullptr; }
        return *this;
    }
};

struct KeyHandle
{
    BCRYPT_KEY_HANDLE h = nullptr;
    ~KeyHandle() { if (h) BCryptDestroyKey(h); }
    KeyHandle() = default;
    KeyHandle(const KeyHandle&)            = delete;
    KeyHandle& operator=(const KeyHandle&) = delete;
    KeyHandle(KeyHandle&& o) noexcept : h(o.h) { o.h = nullptr; }
    KeyHandle& operator=(KeyHandle&& o) noexcept
    {
        if (this != &o) { if (h) BCryptDestroyKey(h); h = o.h; o.h = nullptr; }
        return *this;
    }
    void reset() noexcept { if (h) { BCryptDestroyKey(h); h = nullptr; } }
};

inline bool OpenAlg(AlgHandle& out, LPCWSTR name, LPCWSTR impl = nullptr, ULONG flags = 0) noexcept
{
    return BCryptOpenAlgorithmProvider(&out.h, name, impl, flags) == STATUS_SUCCESS;
}

inline bool HmacSha256(const uint8_t* key, size_t keyLen,
                       const uint8_t* msg, size_t msgLen,
                       uint8_t out[32]) noexcept
{
    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_SHA256_ALGORITHM, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG))
        return false;

    BCRYPT_HASH_HANDLE hash = nullptr;
    if (BCryptCreateHash(alg.h, &hash, nullptr, 0,
                         const_cast<PUCHAR>(key), static_cast<ULONG>(keyLen), 0) != STATUS_SUCCESS)
        return false;

    bool ok = false;
    do {
        if (msgLen && BCryptHashData(hash, const_cast<PUCHAR>(msg),
                                     static_cast<ULONG>(msgLen), 0) != STATUS_SUCCESS) break;
        if (BCryptFinishHash(hash, out, 32, 0) != STATUS_SUCCESS) break;
        ok = true;
    } while (false);

    BCryptDestroyHash(hash);
    if (!ok) SecureWipe(out, 32);
    return ok;
}

inline bool HkdfSha256(const uint8_t* ikm, size_t ikmLen,
                       const uint8_t* salt, size_t saltLen,
                       const uint8_t* info, size_t infoLen,
                       uint8_t* out, size_t outLen) noexcept
{
    if (outLen == 0 || outLen > 32u * 255u) return false;

    uint8_t       prk[32]  = {};
    const uint8_t zeroSalt[32] = {};
    const uint8_t* saltPtr    = (saltLen == 0) ? zeroSalt : salt;
    const size_t   saltUse    = (saltLen == 0) ? 32       : saltLen;

    if (!HmacSha256(saltPtr, saltUse, ikm, ikmLen, prk)) return false;

    uint8_t       t[32]     = {};
    uint8_t       block[32 + 512 + 1] = {};
    size_t        produced = 0;
    uint8_t       counter  = 0;
    bool          ok       = true;

    if (infoLen > sizeof(block) - 33) { SecureWipe(prk, 32); return false; }

    while (produced < outLen && ok) {
        counter++;
        size_t pos = 0;
        if (counter > 1) { std::memcpy(block + pos, t, 32); pos += 32; }
        if (infoLen)     { std::memcpy(block + pos, info, infoLen); pos += infoLen; }
        block[pos++] = counter;

        if (!HmacSha256(prk, 32, block, pos, t)) { ok = false; break; }
        const size_t take = (outLen - produced < 32) ? (outLen - produced) : 32;
        std::memcpy(out + produced, t, take);
        produced += take;
    }

    SecureWipe(prk, 32);
    SecureWipe(t, 32);
    SecureWipe(block, sizeof(block));
    if (!ok) SecureWipe(out, outLen);
    return ok;
}

inline bool Sha256Once(const uint8_t* msg, size_t msgLen, uint8_t out[32]) noexcept
{
    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_SHA256_ALGORITHM)) return false;

    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(alg.h, &hh, nullptr, 0, nullptr, 0, 0) != STATUS_SUCCESS)
        return false;

    bool ok = false;
    do {
        if (msgLen && BCryptHashData(hh, const_cast<PUCHAR>(msg),
                                     static_cast<ULONG>(msgLen), 0) != STATUS_SUCCESS) break;
        if (BCryptFinishHash(hh, out, 32, 0) != STATUS_SUCCESS) break;
        ok = true;
    } while (false);

    BCryptDestroyHash(hh);
    if (!ok) SecureWipe(out, 32);
    return ok;
}

inline bool AesGcmEncryptInto(const uint8_t* key, size_t keyLen,
                              const uint8_t* nonce, size_t nonceLen,
                              const uint8_t* aad, size_t aadLen,
                              const uint8_t* plaintext, size_t ptLen,
                              uint8_t* dst, size_t dstCap, size_t& dstLen) noexcept
{
    dstLen = 0;
    if (keyLen != 32) return false;
    if (ptLen + 16 > dstCap) return false;

    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_AES_ALGORITHM)) return false;

    if (BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS)
        return false;

    KeyHandle k;
    if (BCryptGenerateSymmetricKey(alg.h, &k.h, nullptr, 0,
                                   const_cast<PUCHAR>(key),
                                   static_cast<ULONG>(keyLen), 0) != STATUS_SUCCESS)
        return false;

    uint8_t tag[16] = {};
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce    = const_cast<PUCHAR>(nonce);
    info.cbNonce    = static_cast<ULONG>(nonceLen);
    info.pbAuthData = const_cast<PUCHAR>(aad);
    info.cbAuthData = static_cast<ULONG>(aadLen);
    info.pbTag      = tag;
    info.cbTag      = 16;

    ULONG written = 0;
    NTSTATUS s = BCryptEncrypt(k.h,
                               const_cast<PUCHAR>(plaintext), static_cast<ULONG>(ptLen),
                               &info,
                               nullptr, 0,
                               dst, static_cast<ULONG>(dstCap - 16), &written, 0);
    if (s != STATUS_SUCCESS) { SecureWipe(dst, dstCap); return false; }

    std::memcpy(dst + written, tag, 16);
    SecureWipe(tag, 16);
    dstLen = written + 16;
    return true;
}

inline bool AesGcmDecryptInto(const uint8_t* key, size_t keyLen,
                              const uint8_t* nonce, size_t nonceLen,
                              const uint8_t* aad, size_t aadLen,
                              const uint8_t* ciphertext, size_t ctLen,
                              uint8_t* dst, size_t dstCap, size_t& dstLen) noexcept
{
    dstLen = 0;
    if (keyLen != 32) return false;
    if (ctLen < 16) return false;
    const size_t   bodyLen = ctLen - 16;
    if (bodyLen > dstCap) return false;

    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_AES_ALGORITHM)) return false;

    if (BCryptSetProperty(alg.h, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0) != STATUS_SUCCESS)
        return false;

    KeyHandle k;
    if (BCryptGenerateSymmetricKey(alg.h, &k.h, nullptr, 0,
                                   const_cast<PUCHAR>(key),
                                   static_cast<ULONG>(keyLen), 0) != STATUS_SUCCESS)
        return false;

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info{};
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce      = const_cast<PUCHAR>(nonce);
    info.cbNonce      = static_cast<ULONG>(nonceLen);
    info.pbAuthData   = const_cast<PUCHAR>(aad);
    info.cbAuthData   = static_cast<ULONG>(aadLen);
    info.pbTag        = const_cast<PUCHAR>(ciphertext + bodyLen);
    info.cbTag        = 16;

    ULONG written = 0;
    NTSTATUS s = BCryptDecrypt(k.h,
                               const_cast<PUCHAR>(ciphertext), static_cast<ULONG>(bodyLen),
                               &info,
                               nullptr, 0,
                               dst, static_cast<ULONG>(dstCap), &written, 0);
    if (s != STATUS_SUCCESS) { SecureWipe(dst, dstCap); return false; }

    dstLen = written;
    return true;
}


inline bool X25519OpenAlg(AlgHandle& alg) noexcept
{
    if (!OpenAlg(alg, BCRYPT_ECDH_ALGORITHM)) return false;
    if (BCryptSetProperty(alg.h, BCRYPT_ECC_CURVE_NAME,
                          (PUCHAR)BCRYPT_ECC_CURVE_25519,
                          sizeof(BCRYPT_ECC_CURVE_25519), 0) != STATUS_SUCCESS)
        return false;
    return true;
}

struct X25519Key
{
    AlgHandle alg;
    KeyHandle key;

    void reset() noexcept { key.reset(); }
};

inline bool X25519GenerateKey(X25519Key& privOut, uint8_t pub[32]) noexcept
{
    X25519Key out;
    if (!X25519OpenAlg(out.alg)) return false;

    if (BCryptGenerateKeyPair(out.alg.h, &out.key.h, 255, 0) != STATUS_SUCCESS) return false;
    if (BCryptFinalizeKeyPair(out.key.h, 0) != STATUS_SUCCESS) return false;

    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {};
    ULONG   written = 0;
    if (BCryptExportKey(out.key.h, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                        blob, sizeof(blob), &written, 0) != STATUS_SUCCESS)
        return false;

    auto* hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob);
    if (hdr->cbKey != 32) return false;
    std::memcpy(pub, blob + sizeof(BCRYPT_ECCKEY_BLOB), 32);

    privOut.key = std::move(out.key);
    privOut.alg = std::move(out.alg);
    return true;
}

inline bool X25519Derive(const X25519Key& priv, const uint8_t peerPub[32],
                         uint8_t shared[32]) noexcept
{
    if (!priv.alg.h || !priv.key.h) return false;

    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {};
    auto*   hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob);
    hdr->dwMagic = BCRYPT_ECDH_PUBLIC_GENERIC_MAGIC;
    hdr->cbKey   = 32;
    std::memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), peerPub, 32);

    KeyHandle peer;
    if (BCryptImportKeyPair(priv.alg.h, nullptr, BCRYPT_ECCPUBLIC_BLOB, &peer.h,
                            blob, sizeof(blob), 0) != STATUS_SUCCESS)
        return false;

    BCRYPT_SECRET_HANDLE secret = nullptr;
    if (BCryptSecretAgreement(priv.key.h, peer.h, &secret, 0) != STATUS_SUCCESS) return false;

    ULONG got = 0;
    NTSTATUS s = BCryptDeriveKey(secret, BCRYPT_KDF_RAW_SECRET,
                                 nullptr, shared, 32, &got, 0);
    BCryptDestroySecret(secret);
    if (s != STATUS_SUCCESS || got != 32) { SecureWipe(shared, 32); return false; }

    for (size_t i = 0; i < 16; ++i) {
        const uint8_t t   = shared[i];
        shared[i]         = shared[31 - i];
        shared[31 - i]    = t;
    }

    uint8_t acc = 0;
    for (size_t i = 0; i < 32; ++i) acc |= shared[i];
    if (acc == 0) { SecureWipe(shared, 32); return false; }
    return true;
}

inline bool EcdsaP256Verify(const uint8_t pubXY[64], const uint8_t sigRS[64],
                            const uint8_t* msg, size_t msgLen) noexcept
{
    AlgHandle sha;
    if (!OpenAlg(sha, BCRYPT_SHA256_ALGORITHM)) return false;

    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(sha.h, &hh, nullptr, 0, nullptr, 0, 0) != STATUS_SUCCESS) return false;

    uint8_t digest[32] = {};
    bool    hashOk     = false;
    do {
        if (msgLen && BCryptHashData(hh, const_cast<PUCHAR>(msg),
                                     static_cast<ULONG>(msgLen), 0) != STATUS_SUCCESS) break;
        if (BCryptFinishHash(hh, digest, sizeof(digest), 0) != STATUS_SUCCESS) break;
        hashOk = true;
    } while (false);
    BCryptDestroyHash(hh);
    if (!hashOk) return false;

    AlgHandle alg;
    if (!OpenAlg(alg, BCRYPT_ECDSA_P256_ALGORITHM)) return false;

    uint8_t blob[sizeof(BCRYPT_ECCKEY_BLOB) + 64] = {};
    auto*   hdr = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob);
    hdr->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr->cbKey   = 32;
    std::memcpy(blob + sizeof(BCRYPT_ECCKEY_BLOB), pubXY, 64);

    KeyHandle pk;
    if (BCryptImportKeyPair(alg.h, nullptr, BCRYPT_ECCPUBLIC_BLOB, &pk.h,
                            blob, sizeof(blob), 0) != STATUS_SUCCESS)
        return false;

    NTSTATUS s = BCryptVerifySignature(pk.h, nullptr,
                                       digest, sizeof(digest),
                                       const_cast<PUCHAR>(sigRS), 64, 0);
    return s == STATUS_SUCCESS;
}

}
