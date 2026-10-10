#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../../utils/crypt/xorstr.h"

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <algorithm>

namespace atlas {

inline const char* kAtlasVersion() {
    static const std::string v = xorstr_("4.5.0");
    return v.c_str();
}
inline const char* kAtlasBuilt() {
    static const std::string v = xorstr_(__DATE__ " " __TIME__);
    return v.c_str();
}

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
};

struct Finding {
    Severity          severity = Severity::Info;
    std::string       id;
    std::vector<std::string> evidence;

    Finding& Ev(const std::string& e) { evidence.push_back(e); return *this; }
};

class Report {
public:
    void Add(Finding f);

    const std::vector<Finding>& findings() const { return findings_; }
    void SortBySeverity();

private:
    std::vector<Finding> findings_;
};

std::string  WideToUtf8(const std::wstring& w);
std::wstring Utf8ToWide(const std::string& s);
std::string  ToLower(std::string s);
std::wstring ToLowerW(std::wstring s);
bool         Contains(const std::string& hay, const std::string& needle);
bool         IContains(const std::string& hay, const std::string& needle);
bool         IContainsW(const std::wstring& hay, const std::wstring& needle);
bool         IEndsWithW(const std::wstring& hay, const std::wstring& suffix);
std::string  Hex(uint64_t v, int width = 0);
std::string  HexBytes(const uint8_t* p, size_t n);
std::string  Format(const char* fmt, ...);
std::wstring FileNameOfW(const std::wstring& path);
std::wstring DirNameOfW(const std::wstring& path);

std::wstring NtPathToDosPath(const std::wstring& nt);

struct Options {
    bool verbose      = false;
    bool deepStrings  = true;
    bool checkHandles = false;
};

extern Options g_opt;


}
