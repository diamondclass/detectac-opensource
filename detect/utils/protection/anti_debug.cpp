#include <Windows.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <atomic>

#include "anti_debug.h"
#include "direct_syscall.h"
#include "nt_types.h"
#include "../crypt/xorstr.h"
#include "../logger/logger.h"

namespace protection {
namespace antidebug {

namespace {

std::atomic<bool> g_everDetected{false};

struct PebMin {
    BYTE   InheritedAddressSpace;
    BYTE   ReadImageFileExecOptions;
    BYTE   BeingDebugged;
    BYTE   _padBitField;
    PVOID  Mutant;
    PVOID  ImageBaseAddress;
    PVOID  Ldr;
    PVOID  ProcessParameters;
    PVOID  SubSystemData;
    PVOID  ProcessHeap;
};

PebMin* GetPeb() noexcept {
#ifdef _WIN64
    return reinterpret_cast<PebMin*>(__readgsqword(0x60));
#else
    return reinterpret_cast<PebMin*>(__readfsdword(0x30));
#endif
}

bool SehReadBeingDebugged(PebMin* peb) noexcept {
    if (!peb) return false;
    __try {
        return peb->BeingDebugged != 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

constexpr int kProcessDebugPort         = 7;
constexpr int kProcessDebugObjectHandle = 30;
constexpr int kProcessDebugFlags        = 31;
constexpr int kThreadHideFromDebugger = 17;

void Mark(unsigned& mask, unsigned bit, const char* tag, const char* code) noexcept {
    mask |= bit;
    g_everDetected = true;
    try {
        LOG(DETECTION, xorstr_("N/A")) << xorstr_("Attempted Hooking Onto Detect.ac: Ban this user immediately, they have attempted to hook/tamper with the detect.ac process in runtime [") << code << xorstr_("]");
    } catch (...) {}
}

bool CheckBeingDebugged() noexcept {
    try {
        return SehReadBeingDebugged(GetPeb());
    } catch (...) { return false; }
}

bool CheckDebugPort() noexcept {
    try {
        DWORD_PTR port = 0;
        ULONG ret = 0;
        NTSTATUS st = syscalls::NtQueryInformationProcess(
            GetCurrentProcess(),
            static_cast<ULONG>(kProcessDebugPort),
            &port, sizeof(port), &ret);
        return NT_SUCCESS(st) && port != 0;
    } catch (...) { return false; }
}

bool CheckDebugObjectHandle() noexcept {
    try {
        HANDLE h = nullptr;
        ULONG ret = 0;
        NTSTATUS st = syscalls::NtQueryInformationProcess(
            GetCurrentProcess(),
            static_cast<ULONG>(kProcessDebugObjectHandle),
            &h, sizeof(h), &ret);
        return NT_SUCCESS(st) && h != nullptr;
    } catch (...) { return false; }
}

bool CheckDebugFlags() noexcept {
    try {
        ULONG flags = 0;
        ULONG ret = 0;
        NTSTATUS st = syscalls::NtQueryInformationProcess(
            GetCurrentProcess(),
            static_cast<ULONG>(kProcessDebugFlags),
            &flags, sizeof(flags), &ret);
        return NT_SUCCESS(st) && flags == 0;
    } catch (...) { return false; }
}

bool CheckRemoteDebugger() noexcept {
    try {
        BOOL present = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &present)) {
            return present != FALSE;
        }
        return false;
    } catch (...) { return false; }
}

bool CheckHardwareBreakpoints() noexcept {
    try {
        DWORD pid = GetCurrentProcessId();
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        bool detected = false;
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                HANDLE th = OpenThread(THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                if (!th) continue;
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(th, &ctx)) {
                    if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) detected = true;
                }
                CloseHandle(th);
                if (detected) break;
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        return detected;
    } catch (...) { return false; }
}

} // namespace

unsigned RunAllChecks() noexcept {
    unsigned mask = 0;
    try {
        if (CheckBeingDebugged())          Mark(mask, kBeingDebugged,       xorstr_("PEB.BeingDebugged"),            xorstr_("x041"));
        if (CheckDebugPort())              Mark(mask, kDebugPort,           xorstr_("ProcessDebugPort"),             xorstr_("x9c2"));
        if (CheckDebugObjectHandle())      Mark(mask, kDebugObjectHandle,   xorstr_("ProcessDebugObjectHandle"),     xorstr_("x7b3"));
        if (CheckDebugFlags())             Mark(mask, kDebugFlags,          xorstr_("ProcessDebugFlags"),            xorstr_("x2e8"));
        if (CheckRemoteDebugger())         Mark(mask, kRemoteDebugger,      xorstr_("CheckRemoteDebuggerPresent"),   xorstr_("x56a"));
        if (CheckHardwareBreakpoints())    Mark(mask, kHardwareBreakpoint,  xorstr_("HardwareBreakpoint"),           xorstr_("xd13"));
    } catch (...) {}
    return mask;
}

void HideCurrentThread() noexcept {
    try {
        syscalls::NtSetInformationThread(
            GetCurrentThread(),
            static_cast<ULONG>(kThreadHideFromDebugger),
            nullptr, 0);
    } catch (...) {}
}

bool EverDetected() noexcept { return g_everDetected.load(); }

} // namespace antidebug
} // namespace protection
