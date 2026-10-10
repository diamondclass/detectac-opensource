#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <shlobj.h>

#include "../../../utils/crypt/xorstr.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace rule_version_store
{

inline auto store_path() -> std::wstring
{
    wchar_t buf[MAX_PATH] = {};
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, buf) != S_OK)
        return L"";
    std::wstring p = buf;
    p += xorstr_(L"\\detect-ss");
    CreateDirectoryW(p.c_str(), nullptr);
    p += xorstr_(L"\\rv.bin");
    return p;
}

inline auto load_min_version() noexcept -> uint32_t
{
    const auto path = store_path();
    if (path.empty()) return 0;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;

    uint8_t buf[8] = {};
    DWORD read = 0;
    const BOOL ok = ReadFile(h, buf, sizeof(buf), &read, nullptr);
    CloseHandle(h);
    if (!ok || read != sizeof(buf)) return 0;

    const uint32_t ver =
        (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) |
        (uint32_t(buf[2]) << 8)  |  uint32_t(buf[3]);
    const uint32_t crc =
        (uint32_t(buf[4]) << 24) | (uint32_t(buf[5]) << 16) |
        (uint32_t(buf[6]) << 8)  |  uint32_t(buf[7]);

    const uint32_t expected = ver ^ 0xA5A5C3C3u;
    if (crc != expected) return 0;
    return ver;
}

inline auto persist_min_version(uint32_t version) noexcept -> void
{
    const auto path = store_path();
    if (path.empty()) return;

    const uint32_t crc = version ^ 0xA5A5C3C3u;
    uint8_t buf[8];
    buf[0] = uint8_t((version >> 24) & 0xFF);
    buf[1] = uint8_t((version >> 16) & 0xFF);
    buf[2] = uint8_t((version >> 8)  & 0xFF);
    buf[3] = uint8_t( version        & 0xFF);
    buf[4] = uint8_t((crc >> 24) & 0xFF);
    buf[5] = uint8_t((crc >> 16) & 0xFF);
    buf[6] = uint8_t((crc >> 8)  & 0xFF);
    buf[7] = uint8_t( crc        & 0xFF);

    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD written = 0;
    WriteFile(h, buf, sizeof(buf), &written, nullptr);
    CloseHandle(h);
}

}
