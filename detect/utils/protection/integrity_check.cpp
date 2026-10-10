#include <Windows.h>
#include <openssl/evp.h>
#include <atomic>
#include <mutex>
#include <array>
#include <cstring>

#include "integrity_check.h"
#include "../crypt/xorstr.h"
#include "../logger/logger.h"

namespace protection {
namespace integrity {

namespace {

std::array<unsigned char, 32> g_baselineHash{};
std::atomic<bool>             g_initialised{false};
std::mutex                    g_mtx;

bool Sha256(const BYTE* data, size_t len, std::array<unsigned char, 32>& out) noexcept {
    try {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return false;
        if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx, data, len)              != 1) {
            EVP_MD_CTX_free(ctx); return false;
        }
        unsigned int outLen = 0;
        unsigned char tmp[EVP_MAX_MD_SIZE]{};
        if (EVP_DigestFinal_ex(ctx, tmp, &outLen) != 1 || outLen < 32) {
            EVP_MD_CTX_free(ctx); return false;
        }
        EVP_MD_CTX_free(ctx);
        for (int i = 0; i < 32; ++i) out[i] = tmp[i];
        return true;
    } catch (...) { return false; }
}

bool Sha256Seh(const BYTE* data, size_t len, std::array<unsigned char, 32>& out) noexcept {
    __try {
        return Sha256(data, len, out);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool FindTextSection(BYTE* base, DWORD& outRva, DWORD& outSize) noexcept {
    try {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        auto* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            char name[9] = {};
            std::memcpy(name, sec[i].Name, 8);
            if (std::strcmp(name, xorstr_(".text")) == 0) {
                outRva  = sec[i].VirtualAddress;
                outSize = sec[i].Misc.VirtualSize < sec[i].SizeOfRawData
                       ? sec[i].Misc.VirtualSize
                       : sec[i].SizeOfRawData;
                return outSize > 0;
            }
        }
        return false;
    } catch (...) { return false; }
}

bool FindTextSectionSeh(BYTE* base, DWORD& outRva, DWORD& outSize) noexcept {
    __try {
        return FindTextSection(base, outRva, outSize);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

bool Initialize() noexcept {
    try {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_initialised.load()) return true;

        BYTE* memBase = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
        if (!memBase) return false;

        DWORD rva = 0, size = 0;
        if (!FindTextSectionSeh(memBase, rva, size)) return false;

        if (!Sha256Seh(memBase + rva, size, g_baselineHash)) return false;

        g_initialised = true;
        return true;
    } catch (...) { return false; }
}

bool Verify() noexcept {
    try {
        if (!g_initialised.load()) return true;
        BYTE* memBase = reinterpret_cast<BYTE*>(GetModuleHandleW(nullptr));
        if (!memBase) return true;

        DWORD rva = 0, size = 0;
        if (!FindTextSectionSeh(memBase, rva, size)) return true;

        std::array<unsigned char, 32> cur{};
        if (!Sha256Seh(memBase + rva, size, cur)) return true;

        if (cur != g_baselineHash) {
            try {
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("Attempted Hooking Onto Detect.ac: Ban this user immediately, they have attempted to hook/tamper with the detect.ac process in runtime [x4f1]");
            } catch (...) {}
            return false;
        }
        return true;
    } catch (...) { return true; }
}

} // namespace integrity
} // namespace protection
