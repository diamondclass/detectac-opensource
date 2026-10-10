#include "common.h"
#include "ntdefs.h"
#include <cstdarg>
#include <cstdio>

namespace atlas {

Options g_opt;

void Report::Add(Finding f) { findings_.push_back(std::move(f)); }

void Report::SortBySeverity() {
    std::stable_sort(findings_.begin(), findings_.end(),
                     [](const Finding& a, const Finding& b) { return a.severity > b.severity; });
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}

std::string ToLower(std::string s) {
    for (auto& c : s) c = (char)tolower((unsigned char)c);
    return s;
}

std::wstring ToLowerW(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

bool Contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

bool IContains(const std::string& hay, const std::string& needle) {
    return ToLower(hay).find(ToLower(needle)) != std::string::npos;
}

bool IContainsW(const std::wstring& hay, const std::wstring& needle) {
    return ToLowerW(hay).find(ToLowerW(needle)) != std::wstring::npos;
}

bool IEndsWithW(const std::wstring& hay, const std::wstring& suffix) {
    if (suffix.size() > hay.size()) return false;
    return ToLowerW(hay).compare(hay.size() - suffix.size(), suffix.size(), ToLowerW(suffix)) == 0;
}

std::string Hex(uint64_t v, int width) {
    char buf[32];
    if (width > 0) sprintf_s(buf, xorstr_("0x%0*llX"), width, (unsigned long long)v);
    else           sprintf_s(buf, xorstr_("0x%llX"), (unsigned long long)v);
    return buf;
}

std::string HexBytes(const uint8_t* p, size_t n) {
    std::string s;
    s.reserve(n * 3);
    for (size_t i = 0; i < n; ++i) {
        char b[4];
        sprintf_s(b, xorstr_("%02X"), p[i]);
        if (i) s += ' ';
        s += b;
    }
    return s;
}

std::string Format(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int n = _vscprintf(fmt, ap);
    va_end(ap);
    if (n < 0) { va_end(ap2); return {}; }
    std::string s((size_t)n, '\0');
    vsnprintf(s.data(), (size_t)n + 1, fmt, ap2);
    va_end(ap2);
    return s;
}

std::wstring FileNameOfW(const std::wstring& path) {
    size_t p = path.find_last_of(xorstr_(L"\\/"));
    return p == std::wstring::npos ? path : path.substr(p + 1);
}

std::wstring DirNameOfW(const std::wstring& path) {
    size_t p = path.find_last_of(xorstr_(L"\\/"));
    return p == std::wstring::npos ? std::wstring() : path.substr(0, p);
}

std::wstring NtPathToDosPath(const std::wstring& nt) {
    if (nt.empty()) return nt;
    static std::vector<std::pair<std::wstring, std::wstring>> map;
    if (map.empty()) {
        wchar_t drives[512] = {};
        DWORD len = GetLogicalDriveStringsW(511, drives);
        for (wchar_t* d = drives; d < drives + len && *d; d += wcslen(d) + 1) {
            std::wstring letter(d);
            while (!letter.empty() && (letter.back() == L'\\' || letter.back() == L'/'))
                letter.pop_back();
            wchar_t dev[MAX_PATH] = {};
            if (QueryDosDeviceW(letter.c_str(), dev, MAX_PATH))
                map.emplace_back(dev, letter);
        }
    }
    for (const auto& kv : map) {
        if (nt.size() > kv.first.size() &&
            _wcsnicmp(nt.c_str(), kv.first.c_str(), kv.first.size()) == 0 &&
            nt[kv.first.size()] == L'\\') {
            return kv.second + nt.substr(kv.first.size());
        }
    }
    if (nt.compare(0, 4, xorstr_(L"\\??\\")) == 0) return nt.substr(4);
    return nt;
}

}
