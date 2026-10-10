#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <cwctype>

namespace SigCache {

inline std::mutex& Mutex() noexcept
{
    static std::mutex m;
    return m;
}

inline std::unordered_map<std::wstring, bool>& Map()
{
    static std::unordered_map<std::wstring, bool> m;
    return m;
}

inline std::wstring NormalizeKey(const wchar_t* path)
{
    std::wstring key(path);
    for (wchar_t& c : key) c = static_cast<wchar_t>(std::towlower(c));
    return key;
}

template <typename Fn>
inline bool GetOrCompute(const wchar_t* path, Fn&& compute)
{
    if (!path || !*path) return false;

    std::wstring key = NormalizeKey(path);

    {
        std::lock_guard<std::mutex> lk(Mutex());
        auto it = Map().find(key);
        if (it != Map().end()) return it->second;
    }

    const bool result = compute(path);

    {
        std::lock_guard<std::mutex> lk(Mutex());
        Map().emplace(std::move(key), result);
    }
    return result;
}

inline void Clear()
{
    std::lock_guard<std::mutex> lk(Mutex());
    Map().clear();
}

inline size_t Size()
{
    std::lock_guard<std::mutex> lk(Mutex());
    return Map().size();
}

}
