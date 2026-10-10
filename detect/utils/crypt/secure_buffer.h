#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <Windows.h>
#endif

namespace SecureMem {

inline void Wipe(void* data, size_t bytes) noexcept
{
    if (!data || bytes == 0) return;
#ifdef _WIN32
    SecureZeroMemory(data, bytes);
#else
    volatile unsigned char* p = static_cast<volatile unsigned char*>(data);
    while (bytes--) *p++ = 0;
#endif
}

template <typename T>
class SecureBuffer
{
    static_assert(sizeof(T) == 1, "SecureBuffer requires a byte-sized element");

public:
    SecureBuffer() = default;

    explicit SecureBuffer(size_t bytes) { resize(bytes); }

    SecureBuffer(const T* src, size_t bytes)
    {
        resize(bytes);
        if (bytes) std::memcpy(buf_.data(), src, bytes);
    }

    SecureBuffer(SecureBuffer&& other) noexcept
        : buf_(std::move(other.buf_)), locked_(other.locked_)
    {
        other.locked_ = false;
        other.wipe_and_clear();
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept
    {
        if (this != &other) {
            wipe_and_clear();
            buf_          = std::move(other.buf_);
            locked_       = other.locked_;
            other.locked_ = false;
            other.wipe_and_clear();
        }
        return *this;
    }

    SecureBuffer(const SecureBuffer&)            = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    ~SecureBuffer() { wipe_and_clear(); }

    void resize(size_t bytes)
    {
        wipe_and_clear();
        buf_.resize(bytes);
    }

    void reserve(size_t bytes)
    {
        if (bytes <= buf_.capacity()) return;
        std::vector<T> grown;
        grown.reserve(bytes);
        grown.resize(buf_.size());
        if (!buf_.empty()) std::memcpy(grown.data(), buf_.data(), buf_.size());
        wipe_and_clear();
        buf_.swap(grown);
    }

    void assign(const T* src, size_t bytes)
    {
        resize(bytes);
        if (bytes) std::memcpy(buf_.data(), src, bytes);
    }

    void append(const T* src, size_t bytes)
    {
        if (!bytes) return;

        const size_t old = buf_.size();
        if (buf_.capacity() >= old + bytes) {
            buf_.resize(old + bytes);
            std::memcpy(buf_.data() + old, src, bytes);
            return;
        }

        std::vector<T> grown;
        grown.resize(old + bytes);
        if (old) std::memcpy(grown.data(), buf_.data(), old);
        std::memcpy(grown.data() + old, src, bytes);
        wipe_and_clear();
        buf_.swap(grown);
    }

    bool try_lock_pages() noexcept
    {
#ifdef _WIN32
        if (locked_ || buf_.empty()) return locked_;
        locked_ = (VirtualLock(buf_.data(), buf_.size()) != FALSE);
        return locked_;
#else
        return false;
#endif
    }

    void wipe()
    {
        if (!buf_.empty()) Wipe(buf_.data(), buf_.size());
    }

    bool     empty() const noexcept { return buf_.empty(); }
    size_t   size()  const noexcept { return buf_.size(); }
    T*       data()        noexcept { return buf_.data(); }
    const T* data()  const noexcept { return buf_.data(); }

private:
    void wipe_and_clear()
    {
        if (!buf_.empty()) {
            Wipe(buf_.data(), buf_.size());
#ifdef _WIN32
            if (locked_) {
                VirtualUnlock(buf_.data(), buf_.size());
                locked_ = false;
            }
#endif
            buf_.clear();
            buf_.shrink_to_fit();
        }
        locked_ = false;
    }

    std::vector<T> buf_;
    bool           locked_ = false;
};

using SecureBytes = SecureBuffer<uint8_t>;

}
