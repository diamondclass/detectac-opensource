#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <intrin.h>

#include "hook_scanner.hpp"

#ifndef FAST_FAIL_FATAL_APP_EXIT
#  define FAST_FAIL_FATAL_APP_EXIT 7
#endif

namespace tamper_response
{

using status_t = LONG;
constexpr status_t kStatusUnhandled = static_cast<status_t>(0xC0000144L);
constexpr status_t kStatusAccessViolation = static_cast<status_t>(0xC0000005L);

struct unicode_string_local
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

inline std::atomic<int> g_triggered{ 0 };

inline auto show_message_best_effort(const wchar_t* title, const wchar_t* body) noexcept -> void
{
    HMODULE user = GetModuleHandleW(xorstr_(L"user32.dll"));
    if (!user) user = LoadLibraryW(xorstr_(L"user32.dll"));
    if (!user) return;

    using MessageBoxWFn = int (WINAPI*)(HWND, LPCWSTR, LPCWSTR, UINT);
    auto mb = reinterpret_cast<MessageBoxWFn>(GetProcAddress(user, xorstr_("MessageBoxW")));
    if (!mb) return;

    __try
    {
        mb(nullptr, body, title, MB_OK | MB_ICONERROR | MB_SYSTEMMODAL | MB_TOPMOST);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline auto raise_hard_error_best_effort(const wchar_t* body) noexcept -> void
{
    HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!nt) return;
    using NtRaiseHardErrorFn = status_t(NTAPI*)(
        status_t, ULONG, ULONG, PULONG_PTR, ULONG, PULONG);
    auto p = reinterpret_cast<NtRaiseHardErrorFn>(GetProcAddress(nt, xorstr_("NtRaiseHardError")));
    if (!p) return;

    unicode_string_local s{};
    s.Buffer        = const_cast<wchar_t*>(body);
    s.Length        = USHORT(wcslen(body) * sizeof(wchar_t));
    s.MaximumLength = s.Length + sizeof(wchar_t);
    ULONG_PTR args[1] = { reinterpret_cast<ULONG_PTR>(&s) };
    ULONG response = 0;
    __try
    {
        p(kStatusUnhandled, 1, 1, args, 1, &response);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline auto try_nt_terminate_direct() noexcept -> void
{
    __try
    {
        HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
        if (nt)
        {
            using NtTerminateProcessFn = status_t(NTAPI*)(HANDLE, status_t);
            auto p = reinterpret_cast<NtTerminateProcessFn>(GetProcAddress(nt, xorstr_("NtTerminateProcess")));
            if (p) p(reinterpret_cast<HANDLE>(intptr_t(-1)), kStatusAccessViolation);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline auto try_rtl_exit() noexcept -> void
{
    __try
    {
        HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
        if (!nt) return;
        using RtlExitUserProcessFn = VOID(NTAPI*)(status_t);
        auto p = reinterpret_cast<RtlExitUserProcessFn>(GetProcAddress(nt, xorstr_("RtlExitUserProcess")));
        if (p) p(kStatusAccessViolation);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline auto try_terminate_process() noexcept -> void
{
    __try
    {
        HMODULE k32 = GetModuleHandleW(xorstr_(L"kernel32.dll"));
        if (k32)
        {
            using TerminateProcessFn = BOOL(WINAPI*)(HANDLE, UINT);
            auto p = reinterpret_cast<TerminateProcessFn>(GetProcAddress(k32, xorstr_("TerminateProcess")));
            if (p) p(GetCurrentProcess(), 0xC0000005);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline auto try_raise_failfast() noexcept -> void
{
    __try
    {
        HMODULE k32 = GetModuleHandleW(xorstr_(L"kernel32.dll"));
        if (k32)
        {
            using RaiseFailFastExceptionFn = VOID(WINAPI*)(PEXCEPTION_RECORD, PCONTEXT, DWORD);
            auto p = reinterpret_cast<RaiseFailFastExceptionFn>(
                GetProcAddress(k32, xorstr_("RaiseFailFastException")));
            if (p) p(nullptr, nullptr, 0);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

inline DWORD WINAPI kill_thread(LPVOID) noexcept
{
    try_nt_terminate_direct();
    try_rtl_exit();
    try_terminate_process();
    try_raise_failfast();
    __fastfail(FAST_FAIL_FATAL_APP_EXIT);
    __ud2();
    *reinterpret_cast<volatile int*>(0) = 0xDEAD;
    for (;;) Sleep(1);
    return 0;
}

[[noreturn]] inline auto trigger(const wchar_t* reason) noexcept -> void
{
    int expected = 0;
    if (!g_triggered.compare_exchange_strong(expected, 1))
    {
        for (;;) Sleep(1000);
    }

    for (int i = 0; i < 4; ++i)
    {
        HANDLE h = CreateThread(nullptr, 0, kill_thread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }

    show_message_best_effort(xorstr_(L"Aegis: Security"), xorstr_(L"Tampering In Runtime Detected"));
    if (reason && *reason) raise_hard_error_best_effort(reason);

    try_nt_terminate_direct();
    try_rtl_exit();
    try_terminate_process();
    try_raise_failfast();

    __try { __fastfail(FAST_FAIL_FATAL_APP_EXIT); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try { __ud2(); }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try { *reinterpret_cast<volatile int*>(0) = 0xDEAD; }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    __try
    {
        volatile uint8_t* bad = reinterpret_cast<volatile uint8_t*>(0xFFFFFFFFFFFF0000ULL);
        for (int i = 0; i < 16; ++i) bad[i] = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}

    for (;;)
    {
        __try { __fastfail(FAST_FAIL_FATAL_APP_EXIT); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        __try { __ud2(); } __except (EXCEPTION_EXECUTE_HANDLER) {}
        Sleep(50);
    }
}

inline auto should_trigger_on(uint32_t hook_bits) noexcept -> bool
{
    constexpr uint32_t fatal =
        hook_scanner::bit_ntdll_prologue_diff |
        hook_scanner::bit_syscall_stub_bad    |
        hook_scanner::bit_hardware_breakpoint |
        hook_scanner::bit_any_module_iat_hooked |
        hook_scanner::bit_eat_redirect        |
        hook_scanner::bit_iat_target_noncode;
    return (hook_bits & fatal) != 0;
}

}
