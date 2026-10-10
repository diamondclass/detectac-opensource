#ifndef DETECT_UTILS_CUSTOM_STRINGS_H
#define DETECT_UTILS_CUSTOM_STRINGS_H

#include <curl/curl.h>
#include "../detections/client_checks/yara_scanner/rule_delivery_keys.h"
#include <array>
#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace custom_strings {

inline std::vector<std::pair<std::string, std::vector<std::string>>> process_strings;

inline size_t write_callback(void* contents, size_t size, size_t nmemb, std::string* s) {
    size_t total_size = size * nmemb;
    s->append(static_cast<char*>(contents), total_size);
    return total_size;
}

inline std::string fetch_json(const std::string& url) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    const std::string pin       = RuleDelivery::SpkiPin();
    const std::string protoOnly = xorstr_("https");
    const std::string noProxy   = xorstr_("*");

    std::string response_data;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
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

    CURLcode res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
    if (res != CURLE_OK) return "";
    return response_data;
}

inline std::vector<std::string> split_strings(const std::string& s) {
    std::vector<std::string> result;
    std::string item;
    for (char c : s) {
        if (c == ',') { result.push_back(item); item.clear(); }
        else item += c;
    }
    if (!item.empty()) result.push_back(item);
    return result;
}

// -----------------------------------------------------------------------------
// fast_matcher
// -----------------------------------------------------------------------------
// Case-insensitive multi-substring matcher tuned for scanning process memory
// against thousands of filter strings. The naive per-filter/per-string code
// path used elsewhere in this codebase re-lowercases both the memory buffer
// AND every filter value on every check, which scales as
//     O(strings * filters * (memory_len + filter_len))
// and takes ~40 minutes for a scan with 2000+ filters.
//
// This matcher fixes that in three ways:
//   1. Filter values are lowercased ONCE at prepare() time and stored in an
//      insertion-ordered vector.
//   2. The input memory string is lowercased ONCE per scan() call into a
//      reusable scratch buffer (no per-filter allocation).
//   3. A 256-bit bitmap of the bytes present in the input is built in O(N).
//      Every filter whose first byte is absent from the input is rejected in
//      ~2ns with two shifts and a mask. In practice this rejects 80-95% of
//      filters per scan, since typical filters start with a wide variety of
//      characters that most extracted strings do not all contain.
//   4. Dedup uses a 64-bit FNV-1a hash of (original_string, filter_name)
//      stored in an unordered_set<uint64_t>, replacing the previous
//      unordered_set<string> keyed on (original + name), which allocated and
//      hashed the full memory string every check.
//
// Emit order is preserved: entries are visited in the exact order they were
// added to the matcher (custom filters first, then hardcoded, both in their
// original ingest order), so log output remains deterministic.
class fast_matcher {
public:
    struct entry {
        std::string value_lower;
        std::string name;
        bool        is_custom = false;
    };

    void prepare(const std::vector<std::pair<std::string, std::string>>& custom_filters,
                 const std::vector<std::pair<std::string, std::string>>& hardcoded_filters)
    {
        entries_.clear();
        reported_.clear();
        entries_.reserve(custom_filters.size() + hardcoded_filters.size());
        auto ingest = [&](const std::vector<std::pair<std::string, std::string>>& src,
                          bool is_custom)
        {
            for (const auto& p : src) {
                if (p.first.empty() || p.second.empty()) continue;
                entry e;
                e.value_lower = p.first;
                to_lower(e.value_lower);
                e.name        = p.second;
                e.is_custom   = is_custom;
                entries_.push_back(std::move(e));
            }
        };
        ingest(custom_filters,    true);
        ingest(hardcoded_filters, false);
    }

    bool   empty() const noexcept { return entries_.empty(); }
    size_t size()  const noexcept { return entries_.size();  }

    // Reset the dedup memory (rarely needed; kept for parity with the old
    // static-set behaviour, which persisted for the process lifetime).
    void reset_reported() { reported_.clear(); }

    // Scan a single extracted string against every filter. `cb` is invoked
    // as cb(const entry&, const std::string& original) for each unique
    // (original, name) match; duplicates are suppressed.
    template <typename OnMatch>
    void scan(const std::string& original, OnMatch&& cb) {
        if (entries_.empty() || original.empty()) return;

        scratch_lower_.assign(original);
        to_lower(scratch_lower_);
        const std::string_view lower_view(scratch_lower_);

        uint64_t byte_bits[4] = { 0, 0, 0, 0 };
        for (unsigned char c : scratch_lower_) {
            byte_bits[c >> 6] |= (uint64_t)1 << (c & 63);
        }

        for (const entry& e : entries_) {
            if (e.value_lower.size() > lower_view.size()) continue;
            const uint8_t fb = static_cast<uint8_t>(e.value_lower.front());
            if (!((byte_bits[fb >> 6] >> (fb & 63)) & 1ULL)) continue;
            if (lower_view.find(e.value_lower) == std::string_view::npos) continue;

            const uint64_t key = hash_pair(original, e.name);
            if (!reported_.insert(key).second) continue;

            cb(e, original);
        }
    }

private:
    static void to_lower(std::string& s) noexcept {
        for (char& c : s) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }
    }

    static uint64_t hash_pair(std::string_view a, std::string_view b) noexcept {
        uint64_t h = 0xcbf29ce484222325ULL;
        for (char c : a) { h ^= static_cast<uint8_t>(c); h *= 0x100000001b3ULL; }
        h ^= 0x9e3779b97f4a7c15ULL;
        for (char c : b) { h ^= static_cast<uint8_t>(c); h *= 0x100000001b3ULL; }
        return h;
    }

    std::vector<entry>           entries_;
    std::unordered_set<uint64_t> reported_;
    std::string                  scratch_lower_;
};

}  

#endif  
