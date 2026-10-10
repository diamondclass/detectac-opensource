#include "direct_syscall.h"
#include "nt_types.h"
#include "../crypt/xorstr.h"

#include <Windows.h>
#include <intrin.h>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>

namespace protection {
namespace syscalls {

namespace {

std::atomic<bool> g_initialized{false};
std::atomic<bool> g_available{false};

struct ResolvedSyscall {
    uint32_t ssn       = 0xFFFFFFFFu;
    void*    trampoline = nullptr;
    void*    indirectFn = nullptr;
};

std::unordered_map<std::string, ResolvedSyscall>& StubMap() noexcept {
    static std::unordered_map<std::string, ResolvedSyscall> m;
    return m;
}

std::mutex& StubMutex() noexcept {
    static std::mutex m;
    return m;
}

constexpr size_t kStubSize     = 16;
constexpr size_t kMaxStubs     = 64;
constexpr size_t kTrampolinePageSize = kStubSize * kMaxStubs;
void*  g_trampolinePage = nullptr;
size_t g_trampolineIndex = 0;

bool SehReadByte(const BYTE* p, BYTE* out) noexcept {
    __try {
        *out = *p;
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool SehReadDword(const BYTE* p, uint32_t* out) noexcept {
    __try {
        *out = *reinterpret_cast<const uint32_t*>(p);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool IsRangeReadable(const void* p, size_t len) noexcept {
    if (!p || len == 0) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    auto* addr = reinterpret_cast<const BYTE*>(p);
    const BYTE* end = addr + len;
    while (addr < end) {
        if (VirtualQuery(addr, &mbi, sizeof(mbi)) == 0) return false;
        if (mbi.State != MEM_COMMIT) return false;
        if (mbi.Protect & PAGE_GUARD) return false;
        DWORD accessBits = mbi.Protect & 0xFF;
        if (accessBits == 0 || accessBits == PAGE_NOACCESS) return false;
        const BYTE* regionEnd =
            reinterpret_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
        addr = regionEnd;
    }
    return true;
}

HMODULE NtdllBase() noexcept {
    static const std::wstring kWant = xorstr_(L"ntdll.dll");
    HMODULE h = GetModuleHandleW(kWant.c_str());
    return h;
}

void* GetExportAddress(HMODULE base, const char* name) noexcept {
    if (!base || !name) return nullptr;
    FARPROC p = GetProcAddress(base, name);
    return reinterpret_cast<void*>(p);
}

#ifdef _WIN64

bool TryReadSsn(const BYTE* fn, uint32_t& outSsn) noexcept {
    if (!fn) return false;
    if (!IsRangeReadable(fn, 8)) return false;

    BYTE b0 = 0, b1 = 0, b2 = 0, b3 = 0;
    if (!SehReadByte(fn,     &b0)) return false;
    if (!SehReadByte(fn + 1, &b1)) return false;
    if (!SehReadByte(fn + 2, &b2)) return false;
    if (!SehReadByte(fn + 3, &b3)) return false;

    if (b0 == 0x4C && b1 == 0x8B && b2 == 0xD1 && b3 == 0xB8) {
        uint32_t ssn = 0;
        if (!SehReadDword(fn + 4, &ssn)) return false;
        if (ssn < 0x8000) {
            outSsn = ssn;
            return true;
        }
    }
    return false;
}

bool HaloGateResolve(HMODULE ntdll, const char* fnName, uint32_t& outSsn) noexcept {
    auto* fn = reinterpret_cast<BYTE*>(GetExportAddress(ntdll, fnName));
    if (!fn) return false;

    if (TryReadSsn(fn, outSsn)) return true;

    constexpr int kMaxNeighbours = 500;
    constexpr int kStride        = 32;
    for (int i = 1; i < kMaxNeighbours; ++i) {
        uint32_t ssn = 0;
        if (TryReadSsn(fn + i * kStride, ssn)) {
            outSsn = ssn - static_cast<uint32_t>(i);
            return true;
        }
        if (TryReadSsn(fn - i * kStride, ssn)) {
            outSsn = ssn + static_cast<uint32_t>(i);
            return true;
        }
    }
    return false;
}

void* BuildTrampoline(uint32_t ssn) noexcept {
    try {
        if (!g_trampolinePage) return nullptr;
        if (g_trampolineIndex >= kMaxStubs) return nullptr;

        auto* slot = reinterpret_cast<BYTE*>(g_trampolinePage) + (g_trampolineIndex * kStubSize);
        BYTE stub[kStubSize] = {
            0x4C, 0x8B, 0xD1,
            0xB8, 0x00, 0x00, 0x00, 0x00,
            0x0F, 0x05,
            0xC3,
            0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
        };
        std::memcpy(stub + 4, &ssn, sizeof(ssn));
        std::memcpy(slot, stub, kStubSize);
        ++g_trampolineIndex;
        FlushInstructionCache(GetCurrentProcess(), slot, kStubSize);
        return slot;
    } catch (...) { return nullptr; }
}

#endif

const ResolvedSyscall* Resolve(const char* fnName) noexcept {
    try {
        std::lock_guard<std::mutex> lk(StubMutex());
        auto& map = StubMap();
        auto it = map.find(fnName);
        if (it != map.end()) return &it->second;

        HMODULE ntdll = NtdllBase();
        ResolvedSyscall rs;
        rs.indirectFn = GetExportAddress(ntdll, fnName);

#ifdef _WIN64
        uint32_t ssn = 0;
        if (HaloGateResolve(ntdll, fnName, ssn)) {
            rs.ssn = ssn;
            rs.trampoline = BuildTrampoline(ssn);
            if (rs.trampoline) g_available = true;
        }
#endif
        auto [ins, _] = map.emplace(fnName, rs);
        return &ins->second;
    } catch (...) {
        return nullptr;
    }
}

bool IsValidTrampoline(void* p) noexcept {
    if (!p || !g_trampolinePage) return false;
    auto base = reinterpret_cast<uintptr_t>(g_trampolinePage);
    auto cand = reinterpret_cast<uintptr_t>(p);
    if (cand < base) return false;
    if (cand >= base + kTrampolinePageSize) return false;
    if (((cand - base) % kStubSize) != 0) return false;
    return true;
}

void* Dispatcher(const char* fnName) noexcept {
    try {
        auto* rs = Resolve(fnName);
        if (!rs) return nullptr;
#ifdef _WIN64
        if (IsValidTrampoline(rs->trampoline)) return rs->trampoline;
#endif
        return rs->indirectFn;
    } catch (...) { return nullptr; }
}

} // namespace

bool Initialize() noexcept {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) return g_available.load();

    try {
#ifdef _WIN64
        g_trampolinePage = VirtualAlloc(
            nullptr, kTrampolinePageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (!g_trampolinePage) return false;
        std::memset(g_trampolinePage, 0xCC, kTrampolinePageSize);
#endif

        static const std::vector<std::string> kPrewarm = []() noexcept {
            std::vector<std::string> v;
            v.push_back(xorstr_("NtClose"));
            v.push_back(xorstr_("NtOpenFile"));
            v.push_back(xorstr_("NtCreateFile"));
            v.push_back(xorstr_("NtReadFile"));
            v.push_back(xorstr_("NtQueryInformationProcess"));
            v.push_back(xorstr_("NtQuerySystemInformation"));
            v.push_back(xorstr_("NtSetInformationThread"));
            return v;
        }();
        for (const auto& n : kPrewarm) (void)Resolve(n.c_str());

        return g_available.load();
    } catch (...) {
        return false;
    }
}

bool IsAvailable() noexcept { return g_available.load(); }

unsigned Reverify() noexcept {
    try {
        std::lock_guard<std::mutex> lk(StubMutex());
        unsigned changes = 0;
#ifdef _WIN64
        HMODULE ntdll = NtdllBase();
        for (auto& kv : StubMap()) {
            uint32_t ssn = 0;
            if (HaloGateResolve(ntdll, kv.first.c_str(), ssn) && ssn != kv.second.ssn) {
                ++changes;
            }
        }
#endif
        return changes;
    } catch (...) {
        return 0;
    }
}

NTSTATUS NtClose(HANDLE H) noexcept {
    using Fn = NTSTATUS(NTAPI*)(HANDLE);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtClose")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(H);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

NTSTATUS NtOpenFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    PVOID IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions) noexcept {
    using Fn = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtOpenFile")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(FileHandle, DesiredAccess, ObjectAttributes,
                 IoStatusBlock, ShareAccess, OpenOptions);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

NTSTATUS NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes,
    PVOID IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    PVOID EaBuffer, ULONG EaLength) noexcept {
    using Fn = NTSTATUS(NTAPI*)(
        PHANDLE, ACCESS_MASK, PVOID, PVOID, PLARGE_INTEGER, ULONG,
        ULONG, ULONG, ULONG, PVOID, ULONG);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtCreateFile")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(FileHandle, DesiredAccess, ObjectAttributes,
                 IoStatusBlock, AllocationSize, FileAttributes,
                 ShareAccess, CreateDisposition, CreateOptions,
                 EaBuffer, EaLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

NTSTATUS NtReadFile(
    HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine, PVOID ApcContext,
    PVOID IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) noexcept {
    using Fn = NTSTATUS(NTAPI*)(
        HANDLE, HANDLE, PVOID, PVOID, PVOID, PVOID, ULONG,
        PLARGE_INTEGER, PULONG);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtReadFile")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(FileHandle, Event, ApcRoutine, ApcContext,
                 IoStatusBlock, Buffer, Length, ByteOffset, Key);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle, ULONG ProcessInformationClass,
    PVOID ProcessInformation, ULONG ProcessInformationLength,
    PULONG ReturnLength) noexcept {
    using Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtQueryInformationProcess")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(ProcessHandle, ProcessInformationClass,
                 ProcessInformation, ProcessInformationLength,
                 ReturnLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

NTSTATUS NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength) noexcept {
    using Fn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtQuerySystemInformation")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(SystemInformationClass, SystemInformation,
                 SystemInformationLength, ReturnLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

NTSTATUS NtSetInformationThread(
    HANDLE ThreadHandle, ULONG ThreadInformationClass,
    PVOID ThreadInformation, ULONG ThreadInformationLength) noexcept {
    using Fn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG);
    Fn f = reinterpret_cast<Fn>(Dispatcher(xorstr_("NtSetInformationThread")));
    if (!f) return static_cast<NTSTATUS>(0xC0000001L);
    __try {
        return f(ThreadHandle, ThreadInformationClass,
                 ThreadInformation, ThreadInformationLength);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return static_cast<NTSTATUS>(0xC0000001L);
    }
}

} // namespace syscalls
} // namespace protection
