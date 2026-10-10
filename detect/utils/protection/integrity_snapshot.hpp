#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <shellapi.h>
#include <wintrust.h>
#include <SoftPub.h>

#include "../crypt/cng_crypto.h"
#include "../crypt/xorstr.h"
#include "direct_syscall.h"
#include "protection.h"
#include "hook_scanner.hpp"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

#ifndef STATUS_ACCESS_DENIED
#  define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "Psapi.lib")

namespace integrity_snapshot
{

constexpr uint32_t bit_debugger_present        = 1u << 0;
constexpr uint32_t bit_image_hash_mismatch     = 1u << 1;
constexpr uint32_t bit_test_signing_enabled    = 1u << 2;
constexpr uint32_t bit_dse_disabled            = 1u << 3;
constexpr uint32_t bit_unsigned_module_present = 1u << 4;
constexpr uint32_t bit_ntdll_inline_hook       = 1u << 5;
constexpr uint32_t bit_scanapi_iat_hook        = 1u << 6;
constexpr uint32_t bit_known_bad_module        = 1u << 7;
constexpr uint32_t bit_known_bad_driver        = 1u << 8;
constexpr uint32_t bit_admin_dropped           = 1u << 9;
constexpr uint32_t bit_watchdog_dead           = 1u << 10;
constexpr uint32_t bit_syscall_stubs_bad       = 1u << 11;
constexpr uint32_t bit_kd_debugger_enabled     = 1u << 12;
constexpr uint32_t bit_ntdll_missing           = 1u << 13;
constexpr uint32_t bit_unsigned_module_loaded  = 1u << 14;
constexpr uint32_t bit_iat_hook_detected       = 1u << 15;
constexpr uint32_t bit_ntdll_prologue_diff     = 1u << 16;
constexpr uint32_t bit_syscall_stub_bad        = 1u << 17;
constexpr uint32_t bit_hardware_breakpoint     = 1u << 18;
constexpr uint32_t bit_module_iat_hooked       = 1u << 19;
constexpr uint32_t bit_veh_installed_late      = 1u << 20;
constexpr uint32_t bit_shadow_map_failed       = 1u << 21;
constexpr uint32_t bit_scan_faulted            = 1u << 22;
constexpr uint32_t bit_eat_redirect            = 1u << 23;
constexpr uint32_t bit_export_missing          = 1u << 24;
constexpr uint32_t bit_iat_target_noncode      = 1u << 25;
constexpr uint32_t bit_module_list_mismatch    = 1u << 26;

struct snapshot
{
    uint32_t bits                 = 0;
    uint32_t module_count         = 0;
    uint32_t driver_count         = 0;
    uint32_t bad_modules          = 0;
    uint32_t bad_drivers          = 0;
    uint32_t ntdll_prologue_diffs = 0;
    uint32_t syscall_stub_bad     = 0;
    uint32_t hardware_bp_threads  = 0;
    uint32_t modules_iat_hooked   = 0;
    uint8_t  module_list_hash[32] = {};
    uint8_t  driver_list_hash[32] = {};
    uint64_t boot_time_seconds    = 0;
};

inline auto to_lower_ascii(char c) noexcept -> char
{
    return (c >= 'A' && c <= 'Z') ? char(c + 32) : c;
}

inline auto ends_with_ci(const std::wstring& s, const wchar_t* suffix) noexcept -> bool
{
    const size_t n = wcslen(suffix);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i)
    {
        wchar_t a = s[s.size() - n + i];
        wchar_t b = suffix[i];
        if (a >= L'A' && a <= L'Z') a = wchar_t(a + 32);
        if (b >= L'A' && b <= L'Z') b = wchar_t(b + 32);
        if (a != b) return false;
    }
    return true;
}

inline auto known_bad_user_module(const std::wstring& name) noexcept -> bool
{
    static const wchar_t* const bad[] = {
        xorstr_(L"cheatengine"),
        xorstr_(L"processhacker"),
        xorstr_(L"speedhack"),
        xorstr_(L"injectbox"),
        xorstr_(L"kdmapper"),
        xorstr_(L"extreminjector"),
        xorstr_(L"xenos64"),
        xorstr_(L"guidedhacking"),
        xorstr_(L"osiris.dll"),
        xorstr_(L"aimtux"),
    };
    std::wstring low;
    low.reserve(name.size());
    for (wchar_t c : name) low.push_back((c >= L'A' && c <= L'Z') ? wchar_t(c + 32) : c);
    for (const auto* b : bad)
        if (low.find(b) != std::wstring::npos) return true;
    return false;
}

inline auto known_bad_driver(const std::string& path) noexcept -> bool
{
    static const char* const bad[] = {
        xorstr_("rtcore64.sys"),
        xorstr_("gmer.sys"),
        xorstr_("hackshieldkiller.sys"),
        xorstr_("cheatengine"),
        xorstr_("kprocesshacker"),
        xorstr_("capcom.sys"),
        xorstr_("pcileech"),
        xorstr_("leechcore"),
        xorstr_("kdmapper.sys"),
        xorstr_("physmem.sys"),
    };
    std::string low;
    low.reserve(path.size());
    for (char c : path) low.push_back(to_lower_ascii(c));
    for (const auto* b : bad)
        if (low.find(b) != std::string::npos) return true;
    return false;
}

inline auto check_inline_hook(HMODULE ntdll, const char* export_name) noexcept -> bool
{
    if (!ntdll) return false;
    auto* proc = reinterpret_cast<uint8_t*>(GetProcAddress(ntdll, export_name));
    if (!proc) return false;
    return proc[0] == 0xE9 || proc[0] == 0xEB || (proc[0] == 0xFF && proc[1] == 0x25) || proc[0] == 0xC3;
}

inline auto is_module_signed(const wchar_t* path) noexcept -> bool
{
    if (!path || !*path) return false;

    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct       = sizeof(file_info);
    file_info.pcwszFilePath  = path;
    file_info.hFile          = nullptr;
    file_info.pgKnownSubject = nullptr;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wtd{};
    wtd.cbStruct            = sizeof(wtd);
    wtd.dwUIChoice          = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    wtd.dwUnionChoice       = WTD_CHOICE_FILE;
    wtd.dwStateAction       = WTD_STATEACTION_VERIFY;
    wtd.pFile               = &file_info;
    wtd.dwProvFlags         = WTD_REVOCATION_CHECK_CHAIN | WTD_LIFETIME_SIGNING_FLAG;

    const LONG rc = WinVerifyTrust(HWND(INVALID_HANDLE_VALUE), &policy, &wtd);

    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(HWND(INVALID_HANDLE_VALUE), &policy, &wtd);

    if (rc == ERROR_SUCCESS) return true;

    WINTRUST_DATA wtd2{};
    wtd2.cbStruct            = sizeof(wtd2);
    wtd2.dwUIChoice          = WTD_UI_NONE;
    wtd2.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd2.dwUnionChoice       = WTD_CHOICE_FILE;
    wtd2.dwStateAction       = WTD_STATEACTION_VERIFY;
    wtd2.pFile               = &file_info;
    wtd2.dwProvFlags         = WTD_CACHE_ONLY_URL_RETRIEVAL;

    const LONG rc2 = WinVerifyTrust(HWND(INVALID_HANDLE_VALUE), &policy, &wtd2);
    wtd2.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(HWND(INVALID_HANDLE_VALUE), &policy, &wtd2);

    return rc2 == ERROR_SUCCESS;
}

inline auto verify_iat_thunk(HMODULE self, PIMAGE_THUNK_DATA orig_thunk, PIMAGE_THUNK_DATA cur_thunk,
                             HMODULE resolved_module, uintptr_t module_base, size_t module_size) noexcept -> bool
{
    if (!cur_thunk || cur_thunk->u1.Function == 0) return true;
    if (!resolved_module) return true;
    (void)self;
    (void)orig_thunk;
    const uintptr_t addr = uintptr_t(cur_thunk->u1.Function);
    if (addr < module_base) return false;
    if (addr >= module_base + module_size) return false;
    return true;
}

inline auto check_scanner_iat_intact() noexcept -> bool
{
    HMODULE self = GetModuleHandleW(nullptr);
    if (!self) return true;
    auto* base = reinterpret_cast<uint8_t*>(self);
    auto* dos  = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return true;

    const auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) return true;

    auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + imp_dir.VirtualAddress);
    for (; desc->Name != 0; ++desc)
    {
        const char* dll_name = reinterpret_cast<const char*>(base + desc->Name);
        HMODULE dep = GetModuleHandleA(dll_name);
        if (!dep) continue;
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), dep, &mi, sizeof(mi))) continue;
        const auto mod_base = uintptr_t(mi.lpBaseOfDll);
        const auto mod_size = size_t(mi.SizeOfImage);

        auto* orig = desc->OriginalFirstThunk
                     ? reinterpret_cast<PIMAGE_THUNK_DATA>(base + desc->OriginalFirstThunk)
                     : nullptr;
        auto* cur  = reinterpret_cast<PIMAGE_THUNK_DATA>(base + desc->FirstThunk);
        for (; cur->u1.Function != 0; ++cur, orig ? ++orig : orig)
        {
            if (!verify_iat_thunk(self, orig, cur, dep, mod_base, mod_size))
                return false;
        }
    }
    return true;
}

inline auto enumerate_modules(uint8_t out_hash[32], uint32_t& out_count, uint32_t& out_bad,
                              uint32_t& out_bits) noexcept -> void
{
    HMODULE mods[512] = {};
    DWORD   needed    = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &needed, LIST_MODULES_ALL))
    {
        std::memset(out_hash, 0, 32);
        return;
    }
    const uint32_t total = needed / sizeof(HMODULE);
    out_count = total;
    out_bad   = 0;

    Cng::AlgHandle sha;
    if (!Cng::OpenAlg(sha, BCRYPT_SHA256_ALGORITHM))
    {
        std::memset(out_hash, 0, 32);
        return;
    }
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(sha.h, &hh, nullptr, 0, nullptr, 0, 0) != STATUS_SUCCESS)
    {
        std::memset(out_hash, 0, 32);
        return;
    }

    HMODULE self = GetModuleHandleW(nullptr);
    for (uint32_t i = 0; i < total && i < sizeof(mods) / sizeof(mods[0]); ++i)
    {
        wchar_t path[MAX_PATH] = {};
        if (!GetModuleFileNameExW(GetCurrentProcess(), mods[i], path, MAX_PATH)) continue;
        std::wstring wp = path;
        BCryptHashData(hh, reinterpret_cast<PUCHAR>(wp.data()),
                       ULONG(wp.size() * sizeof(wchar_t)), 0);
        if (known_bad_user_module(wp))
        {
            out_bad++;
            out_bits |= bit_known_bad_module;
        }
        if (mods[i] != self && !is_module_signed(wp.c_str()))
        {
            out_bits |= bit_unsigned_module_loaded;
        }
    }
    BCryptFinishHash(hh, out_hash, 32, 0);
    BCryptDestroyHash(hh);
}

inline auto enumerate_drivers(uint8_t out_hash[32], uint32_t& out_count, uint32_t& out_bad,
                              uint32_t& out_bits) noexcept -> void
{
    LPVOID drivers[512] = {};
    DWORD  needed       = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed))
    {
        std::memset(out_hash, 0, 32);
        return;
    }
    const uint32_t total = needed / sizeof(LPVOID);
    out_count = total;
    out_bad   = 0;

    Cng::AlgHandle sha;
    if (!Cng::OpenAlg(sha, BCRYPT_SHA256_ALGORITHM))
    {
        std::memset(out_hash, 0, 32);
        return;
    }
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(sha.h, &hh, nullptr, 0, nullptr, 0, 0) != STATUS_SUCCESS)
    {
        std::memset(out_hash, 0, 32);
        return;
    }

    for (uint32_t i = 0; i < total && i < sizeof(drivers) / sizeof(drivers[0]); ++i)
    {
        char name[256] = {};
        if (!GetDeviceDriverFileNameA(drivers[i], name, sizeof(name))) continue;
        BCryptHashData(hh, reinterpret_cast<PUCHAR>(name), ULONG(std::strlen(name)), 0);
        if (known_bad_driver(name))
        {
            out_bad++;
            out_bits |= bit_known_bad_driver;
        }
    }
    BCryptFinishHash(hh, out_hash, 32, 0);
    BCryptDestroyHash(hh);
}

struct SYSTEM_CODEINTEGRITY_INFORMATION_local
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
};

constexpr ULONG SystemCodeIntegrityInformation_local = 103;
constexpr ULONG kCiEnabled_local  = 0x01;
constexpr ULONG kCiTestSign_local = 0x02;
constexpr ULONG kCiUmci_local     = 0x04;
constexpr ULONG kCiKmci_local     = 0x40;

inline auto query_code_integrity(uint32_t& out_bits) noexcept -> void
{
    SYSTEM_CODEINTEGRITY_INFORMATION_local info{};
    info.Length = sizeof(info);
    ULONG returned = 0;
    NTSTATUS s = STATUS_ACCESS_DENIED;
    if (protection::syscalls::IsAvailable())
    {
        s = protection::syscalls::NtQuerySystemInformation(SystemCodeIntegrityInformation_local,
                                                           &info, sizeof(info), &returned);
    }
    if (s != STATUS_SUCCESS)
    {
        HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
        if (!nt) { out_bits |= bit_ntdll_missing; return; }
        using NtQSI_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto p = reinterpret_cast<NtQSI_t>(GetProcAddress(nt, xorstr_("NtQuerySystemInformation")));
        if (!p) return;
        s = p(SystemCodeIntegrityInformation_local, &info, sizeof(info), &returned);
    }
    if (s != 0) return;
    const bool testsign = (info.CodeIntegrityOptions & kCiTestSign_local) != 0;
    const bool enabled  = (info.CodeIntegrityOptions & kCiEnabled_local)  != 0;
    if (testsign)  out_bits |= bit_test_signing_enabled;
    if (!enabled)  out_bits |= bit_dse_disabled;
}

struct SYSTEM_KERNEL_DEBUGGER_INFORMATION_local
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
};
constexpr ULONG SystemKernelDebuggerInformation_local = 35;

inline auto query_kernel_debugger(uint32_t& out_bits) noexcept -> void
{
    SYSTEM_KERNEL_DEBUGGER_INFORMATION_local info{};
    ULONG returned = 0;
    NTSTATUS s = STATUS_ACCESS_DENIED;
    if (protection::syscalls::IsAvailable())
    {
        s = protection::syscalls::NtQuerySystemInformation(SystemKernelDebuggerInformation_local,
                                                           &info, sizeof(info), &returned);
    }
    if (s != STATUS_SUCCESS)
    {
        HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
        if (!nt) return;
        using NtQSI_t = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        auto p = reinterpret_cast<NtQSI_t>(GetProcAddress(nt, xorstr_("NtQuerySystemInformation")));
        if (!p) return;
        s = p(SystemKernelDebuggerInformation_local, &info, sizeof(info), &returned);
    }
    if (s == 0 && info.KernelDebuggerEnabled) out_bits |= bit_kd_debugger_enabled;
}

inline auto capture() noexcept -> snapshot
{
    snapshot s{};

    if (IsDebuggerPresent()) s.bits |= bit_debugger_present;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
        s.bits |= bit_debugger_present;

    if (!IsUserAnAdmin()) s.bits |= bit_admin_dropped;

    HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!ntdll) s.bits |= bit_ntdll_missing;
    else
    {
        static const char* const critical[] = {
            xorstr_("NtDeviceIoControl"), xorstr_("NtWriteFile"), xorstr_("NtProtectVirtualMemory"),
            xorstr_("NtCreateFile"),     xorstr_("NtQuerySystemInformation"), xorstr_("NtOpenProcess"),
        };
        for (const auto* n : critical)
        {
            if (check_inline_hook(ntdll, n))
            {
                s.bits |= bit_ntdll_inline_hook;
                break;
            }
        }
    }

    if (!protection::syscalls::IsAvailable()) s.bits |= bit_syscall_stubs_bad;

    if (!protection::IsWatchdogAlive(30)) s.bits |= bit_watchdog_dead;

    if (!check_scanner_iat_intact()) s.bits |= bit_iat_hook_detected;

    {
        const auto hr = hook_scanner::run_full_scan();
        if (hr.bits & hook_scanner::bit_ntdll_prologue_diff)     s.bits |= bit_ntdll_prologue_diff;
        if (hr.bits & hook_scanner::bit_syscall_stub_bad)        s.bits |= bit_syscall_stub_bad;
        if (hr.bits & hook_scanner::bit_hardware_breakpoint)     s.bits |= bit_hardware_breakpoint;
        if (hr.bits & hook_scanner::bit_any_module_iat_hooked)   s.bits |= bit_module_iat_hooked;
        if (hr.bits & hook_scanner::bit_veh_count_grew)          s.bits |= bit_veh_installed_late;
        if (hr.bits & hook_scanner::bit_ntdll_shadow_map_failed) s.bits |= bit_shadow_map_failed;
        if (hr.bits & hook_scanner::bit_scan_faulted)            s.bits |= bit_scan_faulted;
        if (hr.bits & hook_scanner::bit_eat_redirect)            s.bits |= bit_eat_redirect;
        if (hr.bits & hook_scanner::bit_export_missing)          s.bits |= bit_export_missing;
        if (hr.bits & hook_scanner::bit_iat_target_noncode)      s.bits |= bit_iat_target_noncode;
        if (hr.bits & hook_scanner::bit_ldr_module_list_mismatch) s.bits |= bit_module_list_mismatch;
        s.ntdll_prologue_diffs = hr.ntdll_prologue_diffs;
        s.syscall_stub_bad     = hr.syscall_stub_bad_count;
        s.hardware_bp_threads  = hr.hardware_bp_threads;
        s.modules_iat_hooked   = hr.modules_iat_hooked;
    }

    enumerate_modules(s.module_list_hash, s.module_count, s.bad_modules, s.bits);
    enumerate_drivers(s.driver_list_hash, s.driver_count, s.bad_drivers, s.bits);

    query_code_integrity(s.bits);
    query_kernel_debugger(s.bits);

    ULONGLONG up = GetTickCount64() / 1000ULL;
    s.boot_time_seconds = up;

    return s;
}

}
