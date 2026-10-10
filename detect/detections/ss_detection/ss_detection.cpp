#include "ss_detection.h"

#include "../client_checks/client_checks_amcache/c_amcache.h"

namespace {

constexpr ULONGLONG kSusanoMinBytes = 10485760ULL;
constexpr ULONGLONG kSusanoMaxBytes = 10695475ULL;

bool IsVulnerableDriverBlocklistEnabled() noexcept {
    try {
        HKEY hKey = nullptr;
        LONG rc = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config"),
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &hKey);

        if (rc != ERROR_SUCCESS || !hKey) return false;

        DWORD value = 0;
        DWORD type  = 0;
        DWORD size  = sizeof(value);

        rc = RegQueryValueExW(
            hKey,
            xorstr_(L"VulnerableDriverBlocklistEnable"),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size);

        RegCloseKey(hKey);

        if (rc != ERROR_SUCCESS) return false;
        if (type != REG_DWORD)   return false;
        return value == 1;
    }
    catch (...) { return false; }
}

std::string AsciiUpperA(std::string s) noexcept {
    try {
        for (auto& c : s) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - ('a' - 'A'));
        }
        return s;
    }
    catch (...) { return std::string(); }
}

bool ContainsCaseInsensitiveA(const std::string& haystack,
                              const std::string& needle) noexcept {
    try {
        if (needle.empty()) return false;
        return AsciiUpperA(haystack).find(AsciiUpperA(needle))
               != std::string::npos;
    }
    catch (...) { return false; }
}

bool EndsWithExeA(const std::string& s) noexcept {
    try {
        if (s.size() < 4) return false;
        const std::string tail = AsciiUpperA(s.substr(s.size() - 4));
        return tail == xorstr_(".EXE");
    }
    catch (...) { return false; }
}

bool FileExistsOnDiskA(const std::string& path) noexcept {
    try {
        if (path.empty()) return false;
        DWORD attr = GetFileAttributesA(path.c_str());
        return attr != INVALID_FILE_ATTRIBUTES;
    }
    catch (...) { return false; }
}

void CollectFromAmcache(std::vector<std::string>& outPaths) noexcept {
    try {
        std::vector<AmcacheEntry> entries;
        if (!AmcacheFilters::GetAmcacheEntries(entries)) return;
        if (entries.empty()) return;

        const std::string downloadsTag = xorstr_("\\Downloads\\");

        for (const auto& e : entries) {
            try {
                if (e.path.empty())                                  continue;
                if (e.sizeBytes == 0)                                continue;
                if (e.sizeBytes < kSusanoMinBytes)                   continue;
                if (e.sizeBytes > kSusanoMaxBytes)                   continue;
                if (!EndsWithExeA(e.path))                           continue;
                if (!ContainsCaseInsensitiveA(e.path, downloadsTag)) continue;
                if (FileExistsOnDiskA(e.path))                       continue;
                outPaths.push_back(e.path);
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

}

void SsDetection::start_ss_detection() noexcept
{
    try {
        std::vector<std::string> hits;
        try { CollectFromAmcache(hits); } catch (...) {}
        if (hits.empty()) return;

        try {
            std::sort(hits.begin(), hits.end(),
                [](const std::string& a, const std::string& b) {
                    return _stricmp(a.c_str(), b.c_str()) < 0;
                });
            hits.erase(std::unique(hits.begin(), hits.end(),
                [](const std::string& a, const std::string& b) {
                    return _stricmp(a.c_str(), b.c_str()) == 0;
                }), hits.end());
        }
        catch (...) {}

        if (IsVulnerableDriverBlocklistEnabled()) return;

        const std::string label  = xorstr_("Susano Bypass");
        const std::string suffix = xorstr_(" Found:");

        for (const auto& p : hits) {
            try {
                LOG(DETECTION, xorstr_("N/A"))
                    << label
                    << suffix
                    << p;
            }
            catch (...) {}
        }
    }
    catch (...) {}
}
