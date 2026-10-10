#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <Windows.h>
#include <werapi.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "wer.lib")

namespace CrashShield {

inline void SecureWipe(void* p, size_t n) noexcept
{
    if (p && n) SecureZeroMemory(p, n);
}

class ExcludedRegion
{
public:
    ExcludedRegion() = default;

    explicit ExcludedRegion(size_t bytes) { allocate(bytes); }

    ~ExcludedRegion() { release(); }

    ExcludedRegion(const ExcludedRegion&)            = delete;
    ExcludedRegion& operator=(const ExcludedRegion&) = delete;

    ExcludedRegion(ExcludedRegion&& other) noexcept
        : base_(other.base_), reserved_(other.reserved_), used_(other.used_), registered_(other.registered_)
    {
        other.base_       = nullptr;
        other.reserved_   = 0;
        other.used_       = 0;
        other.registered_ = false;
    }

    ExcludedRegion& operator=(ExcludedRegion&& other) noexcept
    {
        if (this != &other) {
            release();
            base_             = other.base_;
            reserved_         = other.reserved_;
            used_             = other.used_;
            registered_       = other.registered_;
            other.base_       = nullptr;
            other.reserved_   = 0;
            other.used_       = 0;
            other.registered_ = false;
        }
        return *this;
    }

    bool allocate(size_t bytes) noexcept
    {
        release();
        if (bytes == 0) return true;

        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const size_t page   = si.dwPageSize ? si.dwPageSize : 4096;
        const size_t padded = (bytes + page - 1) & ~(page - 1);

        void* addr = VirtualAlloc(nullptr, padded, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!addr) return false;

        base_     = addr;
        reserved_ = padded;
        used_     = bytes;

        VirtualLock(base_, reserved_);

        const HRESULT hr = WerRegisterExcludedMemoryBlock(base_, static_cast<DWORD>(reserved_));
        registered_ = SUCCEEDED(hr);
        return true;
    }

    void resize(size_t bytes)
    {
        if (bytes <= reserved_) {
            used_ = bytes;
            return;
        }
        (void)allocate(bytes);
    }

    void shrink_to(size_t used) noexcept
    {
        if (used <= reserved_) used_ = used;
    }

    void wipe() noexcept
    {
        if (base_) SecureWipe(base_, reserved_);
    }

    void release() noexcept
    {
        if (!base_) return;
        SecureWipe(base_, reserved_);
        if (registered_) WerUnregisterExcludedMemoryBlock(base_);
        VirtualUnlock(base_, reserved_);
        VirtualFree(base_, 0, MEM_RELEASE);
        base_       = nullptr;
        reserved_   = 0;
        used_       = 0;
        registered_ = false;
    }

    uint8_t*       data()       noexcept { return static_cast<uint8_t*>(base_); }
    const uint8_t* data() const noexcept { return static_cast<const uint8_t*>(base_); }
    size_t         size()     const noexcept { return used_; }
    size_t         capacity() const noexcept { return reserved_; }
    bool           empty()    const noexcept { return used_ == 0; }
    bool           excluded() const noexcept { return registered_; }

private:
    void*  base_       = nullptr;
    size_t reserved_   = 0;
    size_t used_       = 0;
    bool   registered_ = false;
};

}
