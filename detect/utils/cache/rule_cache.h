#pragma once

// Offline rule cache: persists server-fetched scan data (custom strings,
// YARA rules, UI theme) next to the exe so offline runs keep full coverage.
//
// Policy: network first (fresh data refreshes the cache on every success),
// disk fallback when the server is unreachable. All failures are swallowed
// so a missing/unwritable cache degrades to the old empty-result behaviour.

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rule_cache {

inline const char* game_suffix() {
#if defined(DETECT_MINECRAFT)
    return "minecraft";
#elif defined(DETECT_SIEGE)
    return "siege";
#elif defined(DETECT_GMOD)
    return "gmod";
#elif defined(DETECT_FIVEM)
    return "fivem";
#elif defined(DETECT_FREEFIRE)
    return "freefire";
#elif defined(DETECT_ROBLOX)
    return "roblox";
#elif defined(DETECT_FORTNITE)
    return "fortnite";
#elif defined(DETECT_COD)
    return "cod";
#elif defined(DETECT_RUST)
    return "rust";
#elif defined(DETECT_DAYZ)
    return "dayz";
#elif defined(DETECT_CS)
    return "cs";
#else
    return "all";
#endif
}

inline std::string strings_name() { return std::string("strings-") + game_suffix() + ".json"; }
inline std::string yara_name()    { return std::string("yara-") + game_suffix() + ".bin"; }
inline std::string theme_name()   { return std::string("theme-") + game_suffix() + ".json"; }

inline std::wstring cache_dir() {
    try {
        wchar_t exe[MAX_PATH] = {};
        std::wstring dir;
        if (GetModuleFileNameW(NULL, exe, MAX_PATH) != 0) {
            std::wstring full = exe;
            size_t sep = full.find_last_of(L"\\/");
            if (sep != std::wstring::npos) dir = full.substr(0, sep);
        }
        if (!dir.empty()) {
            dir += L"\\detect-cache";
            CreateDirectoryW(dir.c_str(), nullptr);
            return dir;
        }
        wchar_t tmp[MAX_PATH] = {};
        if (GetTempPathW(MAX_PATH, tmp) != 0) {
            dir = tmp;
            while (!dir.empty() && (dir.back() == L'\\' || dir.back() == L'/')) dir.pop_back();
            dir += L"\\detect-cache";
            CreateDirectoryW(dir.c_str(), nullptr);
            return dir;
        }
    } catch (...) {}
    return L"";
}

inline std::wstring widen_ascii(const char* s) {
    std::wstring out;
    if (!s) return out;
    while (*s) { out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*s))); ++s; }
    return out;
}

inline bool save(const char* name, const uint8_t* data, size_t len) {
    try {
        if (!name || !data || len == 0) return false;
        const std::wstring dir = cache_dir();
        if (dir.empty()) return false;
        const std::wstring path = dir + L"\\" + widen_ascii(name);
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        size_t off = 0;
        BOOL ok = TRUE;
        while (off < len) {
            size_t want = len - off;
            if (want > (1024 * 1024)) want = (1024 * 1024);
            DWORD w = 0;
            if (!WriteFile(h, data + off, static_cast<DWORD>(want), &w, nullptr) || w != want) {
                ok = FALSE;
                break;
            }
            off += w;
        }
        CloseHandle(h);
        return ok == TRUE;
    } catch (...) { return false; }
}

inline bool save(const char* name, const std::string& data) {
    return save(name, reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

inline bool load(const char* name, std::string& out) {
    try {
        out.clear();
        if (!name) return false;
        const std::wstring dir = cache_dir();
        if (dir.empty()) return false;
        const std::wstring path = dir + L"\\" + widen_ascii(name);
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(h, &size) || size.QuadPart <= 0 ||
            size.QuadPart > (16LL * 1024 * 1024)) {
            CloseHandle(h);
            return false;
        }
        out.resize(static_cast<size_t>(size.QuadPart));
        size_t off = 0;
        BOOL ok = TRUE;
        while (off < out.size()) {
            size_t want = out.size() - off;
            if (want > (1024 * 1024)) want = (1024 * 1024);
            DWORD r = 0;
            if (!ReadFile(h, &out[off], static_cast<DWORD>(want), &r, nullptr) || r == 0) {
                ok = FALSE;
                break;
            }
            off += r;
        }
        CloseHandle(h);
        if (ok != TRUE) { out.clear(); return false; }
        return !out.empty();
    } catch (...) { out.clear(); return false; }
}

}
