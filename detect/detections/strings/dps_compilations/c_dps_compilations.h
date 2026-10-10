#pragma once

#include "../../../pch.h"

class compilationscan {
public:
    static int compilation_scan() noexcept;

private:
    static bool IsPrintableAscii(unsigned char c) noexcept;
    static bool IsPrintableWide(wchar_t c) noexcept;
    static bool IsReadableProtection(unsigned long protect) noexcept;

    static std::string WideToUtf8(const std::wstring& w) noexcept;
    static std::wstring Utf8ToWide(const std::string& s) noexcept;

    static void ExtractAscii(const unsigned char* data, std::size_t n,
        std::set<std::string>& out) noexcept;
    static void ExtractWide(const unsigned char* data, std::size_t n,
        std::set<std::wstring>& out) noexcept;

    static bool ParseRecord(const std::wstring& s, std::wstring& outName,
        std::wstring& outDate) noexcept;

    static bool EnableDebugPrivilege() noexcept;
    static unsigned long FindDpsPid() noexcept;

    static void ScanRegion(void* process, unsigned char* base, std::size_t size,
        std::set<std::string>& asciiOut,
        std::set<std::wstring>& wideOut) noexcept;
    static void CollectStrings(void* process,
        std::set<std::string>& asciiOut,
        std::set<std::wstring>& wideOut) noexcept;

    static void Report(const std::set<std::string>& ascii,
        const std::set<std::wstring>& wide) noexcept;
};


inline auto c_compilation = std::make_unique<compilationscan>();