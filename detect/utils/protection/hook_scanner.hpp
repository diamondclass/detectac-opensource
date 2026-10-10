#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>

#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include "direct_syscall.h"
#include "nt_types.h"

#pragma comment(lib, "Psapi.lib")

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif

namespace hook_scanner
{

struct unicode_string_local
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct object_attributes_local
{
    ULONG                Length;
    HANDLE               RootDirectory;
    unicode_string_local* ObjectName;
    ULONG                Attributes;
    PVOID                SecurityDescriptor;
    PVOID                SecurityQualityOfService;
};

struct io_status_block_local
{
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } u;
    ULONG_PTR Information;
};

constexpr uint32_t bit_ntdll_prologue_diff       = 1u << 0;
constexpr uint32_t bit_syscall_stub_bad          = 1u << 1;
constexpr uint32_t bit_ntdll_shadow_map_failed   = 1u << 2;
constexpr uint32_t bit_hardware_breakpoint       = 1u << 3;
constexpr uint32_t bit_any_module_iat_hooked     = 1u << 4;
constexpr uint32_t bit_thread_walk_failed        = 1u << 5;
constexpr uint32_t bit_veh_count_grew            = 1u << 6;
constexpr uint32_t bit_ldr_module_list_mismatch  = 1u << 7;
constexpr uint32_t bit_scan_faulted              = 1u << 8;
constexpr uint32_t bit_eat_redirect              = 1u << 9;
constexpr uint32_t bit_export_missing            = 1u << 10;
constexpr uint32_t bit_iat_target_noncode        = 1u << 11;

constexpr size_t prologue_compare_bytes = 24;

struct disk_module
{
    std::vector<uint8_t> raw;
    bool                 valid = false;
};

struct raw_pe_view
{
    const uint8_t*             base       = nullptr;
    size_t                     size       = 0;
    const IMAGE_NT_HEADERS*    nt         = nullptr;
    const IMAGE_SECTION_HEADER* sections  = nullptr;
    WORD                       n_sections = 0;
    bool                       valid      = false;
};

inline auto close_disk_module(disk_module& m) noexcept -> void
{
    m.raw.clear();
    m.raw.shrink_to_fit();
    m.valid = false;
}

inline auto raw_pe_parse(const uint8_t* buf, size_t sz) noexcept -> raw_pe_view
{
    raw_pe_view v{};
    if (!buf || sz < sizeof(IMAGE_DOS_HEADER)) return v;
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buf);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return v;
    if (dos->e_lfanew < 0 || size_t(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS) > sz) return v;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(buf + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return v;
    if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER)) return v;

    v.base       = buf;
    v.size       = sz;
    v.nt         = nt;
    v.n_sections = nt->FileHeader.NumberOfSections;
    v.sections   = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
        reinterpret_cast<const uint8_t*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);
    if (uintptr_t(v.sections) + v.n_sections * sizeof(IMAGE_SECTION_HEADER) > uintptr_t(buf + sz))
        return v;
    v.valid = true;
    return v;
}

inline auto raw_rva_to_offset(const raw_pe_view& v, uint32_t rva) noexcept -> uint32_t
{
    if (!v.valid) return 0;
    for (WORD i = 0; i < v.n_sections; ++i)
    {
        const uint32_t va   = v.sections[i].VirtualAddress;
        const uint32_t vsz  = v.sections[i].Misc.VirtualSize;
        const uint32_t rsz  = v.sections[i].SizeOfRawData;
        const uint32_t roff = v.sections[i].PointerToRawData;
        const uint32_t span = vsz > rsz ? vsz : rsz;
        if (rva >= va && rva < va + span)
        {
            const uint32_t off = roff + (rva - va);
            if (off + 1 > v.size) return 0;
            return off;
        }
    }
    if (rva < v.size) return rva;
    return 0;
}

inline auto read_raw_ntdll_via_syscall(std::vector<uint8_t>& out) noexcept -> bool
{
    out.clear();
    wchar_t sys[MAX_PATH] = {};
    if (!GetSystemDirectoryW(sys, MAX_PATH)) return false;

    std::wstring nt_path = xorstr_(L"\\??\\");
    nt_path += sys;
    nt_path += xorstr_(L"\\ntdll.dll");

    unicode_string_local u{};
    u.Buffer        = const_cast<wchar_t*>(nt_path.c_str());
    u.Length        = USHORT(nt_path.size() * sizeof(wchar_t));
    u.MaximumLength = u.Length + sizeof(wchar_t);

    object_attributes_local oa{};
    oa.Length     = sizeof(oa);
    oa.ObjectName = &u;
    oa.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE h = nullptr;
    io_status_block_local iosb{};
    NTSTATUS s;

    if (protection::syscalls::IsAvailable())
    {
        s = protection::syscalls::NtCreateFile(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
            nullptr, FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            nullptr, 0);
    }
    else
    {
        HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
        if (!nt) return false;
        using NtCreateFileFn = NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID,
            PVOID, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
        auto p = reinterpret_cast<NtCreateFileFn>(GetProcAddress(nt, xorstr_("NtCreateFile")));
        if (!p) return false;
        s = p(&h, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
              nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN,
              FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0);
    }
    if (s != 0 || h == nullptr) return false;

    constexpr size_t max_ntdll_bytes = 8 * 1024 * 1024;
    out.reserve(2 * 1024 * 1024);
    uint8_t chunk[64 * 1024];
    LARGE_INTEGER offset{};
    for (;;)
    {
        io_status_block_local io{};
        NTSTATUS rs;
        if (protection::syscalls::IsAvailable())
        {
            rs = protection::syscalls::NtReadFile(h, nullptr, nullptr, nullptr,
                &io, chunk, sizeof(chunk), &offset, nullptr);
        }
        else
        {
            HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
            using NtReadFileFn = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID, PVOID, PVOID,
                PVOID, ULONG, PLARGE_INTEGER, PULONG);
            auto p = reinterpret_cast<NtReadFileFn>(GetProcAddress(nt, xorstr_("NtReadFile")));
            if (!p) { protection::syscalls::NtClose(h); return false; }
            rs = p(h, nullptr, nullptr, nullptr, &io, chunk, sizeof(chunk), &offset, nullptr);
        }
        if (rs != 0 || io.Information == 0) break;
        const size_t got = size_t(io.Information);
        out.insert(out.end(), chunk, chunk + got);
        offset.QuadPart += LONGLONG(got);
        if (out.size() > max_ntdll_bytes) break;
    }
    protection::syscalls::NtClose(h);
    return out.size() > 0x1000;
}

inline auto open_disk_shadow(const wchar_t* module_name, disk_module& out) noexcept -> bool
{
    close_disk_module(out);
    if (wcscmp(module_name, xorstr_(L"ntdll.dll")) != 0) return false;
    if (!read_raw_ntdll_via_syscall(out.raw)) return false;

    auto view = raw_pe_parse(out.raw.data(), out.raw.size());
    if (!view.valid) { close_disk_module(out); return false; }
    out.valid = true;
    return true;
}

inline auto find_export_rva_in_image(uint8_t* base, const char* name) noexcept -> uint32_t
{
    __try
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        const auto& d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (d.VirtualAddress == 0 || d.Size == 0) return 0;

        auto* exp = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + d.VirtualAddress);
        auto* funcs = reinterpret_cast<uint32_t*>(base + exp->AddressOfFunctions);
        auto* names = reinterpret_cast<uint32_t*>(base + exp->AddressOfNames);
        auto* ords  = reinterpret_cast<uint16_t*>(base + exp->AddressOfNameOrdinals);

        for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
        {
            const char* export_name = reinterpret_cast<const char*>(base + names[i]);
            if (std::strcmp(export_name, name) == 0)
            {
                const uint32_t rva = funcs[ords[i]];
                if (rva >= d.VirtualAddress && rva < d.VirtualAddress + d.Size)
                    return 0;
                return rva;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
    return 0;
}

inline auto find_export_rva_in_raw(const raw_pe_view& v, const char* name) noexcept -> uint32_t
{
    if (!v.valid) return 0;
    const auto& d = v.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (d.VirtualAddress == 0 || d.Size == 0) return 0;

    const uint32_t exp_off = raw_rva_to_offset(v, d.VirtualAddress);
    if (exp_off == 0 || exp_off + sizeof(IMAGE_EXPORT_DIRECTORY) > v.size) return 0;
    auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(v.base + exp_off);

    const uint32_t funcs_off = raw_rva_to_offset(v, exp->AddressOfFunctions);
    const uint32_t names_off = raw_rva_to_offset(v, exp->AddressOfNames);
    const uint32_t ords_off  = raw_rva_to_offset(v, exp->AddressOfNameOrdinals);
    if (funcs_off == 0 || names_off == 0 || ords_off == 0) return 0;

    auto* funcs = reinterpret_cast<const uint32_t*>(v.base + funcs_off);
    auto* names = reinterpret_cast<const uint32_t*>(v.base + names_off);
    auto* ords  = reinterpret_cast<const uint16_t*>(v.base + ords_off);

    for (uint32_t i = 0; i < exp->NumberOfNames; ++i)
    {
        const uint32_t name_off = raw_rva_to_offset(v, names[i]);
        if (name_off == 0) continue;
        const char* export_name = reinterpret_cast<const char*>(v.base + name_off);
        size_t safe_len = 0;
        while (name_off + safe_len < v.size && export_name[safe_len] != '\0' && safe_len < 256) ++safe_len;
        if (safe_len == 0) continue;
        if (std::strncmp(export_name, name, safe_len + 1) == 0)
        {
            const uint32_t rva = funcs[ords[i]];
            if (rva >= d.VirtualAddress && rva < d.VirtualAddress + d.Size) return 0;
            return rva;
        }
    }
    return 0;
}

inline auto safe_read_bytes(const uint8_t* src, uint8_t* dst, size_t n) noexcept -> bool
{
    __try
    {
        for (size_t i = 0; i < n; ++i) dst[i] = src[i];
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return false;
    }
}

inline auto looks_like_hook_pattern(const uint8_t* p) noexcept -> bool
{
    if (p[0] == 0xE9) return true;
    if (p[0] == 0xEB) return true;
    if (p[0] == 0xC3) return true;
    if (p[0] == 0xCC) return true;
    if (p[0] == 0xFF && p[1] == 0x25) return true;
    if (p[0] == 0x68 && p[5] == 0xC3) return true;
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) return true;
    if (p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE3) return true;
    return false;
}

inline auto check_module_prologues(HMODULE mem_mod, disk_module& disk,
                                   const char* const* names, size_t name_count,
                                   uint32_t& bits) noexcept -> uint32_t
{
    if (!mem_mod || !disk.valid) return 0;
    auto* mem_base = reinterpret_cast<uint8_t*>(mem_mod);
    const auto view = raw_pe_parse(disk.raw.data(), disk.raw.size());
    if (!view.valid) return 0;
    uint32_t hits = 0;

    for (size_t i = 0; i < name_count; ++i)
    {
        const char* n = names[i];
        const uint32_t disk_rva = find_export_rva_in_raw(view, n);
        const uint32_t mem_rva  = find_export_rva_in_image(mem_base, n);

        if (disk_rva == 0) continue;
        if (mem_rva == 0) { bits |= bit_export_missing; continue; }
        if (mem_rva != disk_rva) { bits |= bit_eat_redirect; hits++; continue; }

        const uint32_t disk_off = raw_rva_to_offset(view, disk_rva);
        if (disk_off == 0 || disk_off + prologue_compare_bytes > view.size) continue;

        const uint8_t* mem_proc  = mem_base + mem_rva;
        const uint8_t* disk_proc = view.base + disk_off;

        uint8_t mem_copy[prologue_compare_bytes] = {};
        if (!safe_read_bytes(mem_proc, mem_copy, prologue_compare_bytes))
        {
            bits |= bit_scan_faulted;
            hits++;
            continue;
        }

        bool differ = false;
        for (size_t b = 0; b < prologue_compare_bytes; ++b)
        {
            if (mem_copy[b] != disk_proc[b]) { differ = true; break; }
        }
        if (differ)
        {
            bits |= bit_ntdll_prologue_diff;
            hits++;
            if (looks_like_hook_pattern(mem_copy)) hits++;
        }
    }
    return hits;
}

inline auto verify_syscall_stub_opcode(const uint8_t* mem, const uint8_t* disk_proc, size_t disk_off, size_t disk_size) noexcept -> bool
{
    if (disk_off + 4 > disk_size) return true;
    if (!(disk_proc[0] == 0x4C && disk_proc[1] == 0x8B && disk_proc[2] == 0xD1 && disk_proc[3] == 0xB8))
        return true;

    uint8_t buf[4] = {};
    if (!safe_read_bytes(mem, buf, 4)) return false;
    return buf[0] == disk_proc[0] && buf[1] == disk_proc[1] && buf[2] == disk_proc[2] && buf[3] == disk_proc[3];
}

inline auto check_syscall_stubs(HMODULE ntdll_mem, disk_module& disk, uint32_t& bits) noexcept -> uint32_t
{
    if (!ntdll_mem || !disk.valid) return 0;
    auto* mem_base = reinterpret_cast<uint8_t*>(ntdll_mem);
    const auto view = raw_pe_parse(disk.raw.data(), disk.raw.size());
    if (!view.valid) return 0;

    static const char* const critical[] = {
        xorstr_("NtDeviceIoControlFile"), xorstr_("NtProtectVirtualMemory"), xorstr_("NtWriteFile"),
        xorstr_("NtQueryInformationProcess"), xorstr_("NtQuerySystemInformation"),
        xorstr_("NtOpenProcess"), xorstr_("NtReadVirtualMemory"), xorstr_("NtCreateFile"),
        xorstr_("NtAllocateVirtualMemory"), xorstr_("NtFreeVirtualMemory"),
        xorstr_("NtMapViewOfSection"), xorstr_("NtUnmapViewOfSection"),
        xorstr_("NtCreateThreadEx"), xorstr_("NtResumeThread"), xorstr_("NtGetContextThread"),
        xorstr_("NtSetContextThread"), xorstr_("NtSetInformationThread"),
        xorstr_("NtQueryVirtualMemory"), xorstr_("NtOpenFile"), xorstr_("NtOpenThread"),
        xorstr_("NtTerminateProcess"), xorstr_("NtTerminateThread"),
        xorstr_("NtDelayExecution"), xorstr_("NtWaitForSingleObject"),
    };
    uint32_t bad = 0;
    for (const auto* n : critical)
    {
        const uint32_t disk_rva = find_export_rva_in_raw(view, n);
        const uint32_t mem_rva  = find_export_rva_in_image(mem_base, n);
        if (disk_rva == 0 || mem_rva == 0) continue;
        if (mem_rva != disk_rva) { bits |= bit_eat_redirect; bad++; continue; }

        const uint32_t disk_off = raw_rva_to_offset(view, disk_rva);
        if (disk_off == 0) continue;
        const uint8_t* disk_proc = view.base + disk_off;
        auto* mem = mem_base + mem_rva;
        if (!verify_syscall_stub_opcode(mem, disk_proc, disk_off, view.size))
        {
            bits |= bit_syscall_stub_bad;
            bad++;
        }
    }
    return bad;
}

inline auto is_dr_slot_enabled(DWORD64 dr7, int slot) noexcept -> bool
{
    const DWORD64 local  = (dr7 >> (slot * 2)) & 0x1;
    const DWORD64 global = (dr7 >> (slot * 2 + 1)) & 0x1;
    return (local != 0) || (global != 0);
}

inline auto check_hardware_breakpoints(uint32_t& bits) noexcept -> uint32_t
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
    {
        bits |= bit_thread_walk_failed;
        return 0;
    }
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    uint32_t hits = 0;
    const DWORD me      = GetCurrentProcessId();
    const DWORD self_id = GetCurrentThreadId();

    auto inspect_ctx = [&](const CONTEXT& ctx) noexcept {
        const bool any_dr =
            (ctx.Dr0 && is_dr_slot_enabled(ctx.Dr7, 0)) ||
            (ctx.Dr1 && is_dr_slot_enabled(ctx.Dr7, 1)) ||
            (ctx.Dr2 && is_dr_slot_enabled(ctx.Dr7, 2)) ||
            (ctx.Dr3 && is_dr_slot_enabled(ctx.Dr7, 3));
        if (any_dr)
        {
            bits |= bit_hardware_breakpoint;
            hits++;
        }
    };

    if (Thread32First(snap, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != me) continue;

            if (te.th32ThreadID == self_id)
            {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(GetCurrentThread(), &ctx)) inspect_ctx(ctx);
                continue;
            }

            HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                                  FALSE, te.th32ThreadID);
            if (!h) continue;

            const DWORD suspend_result = SuspendThread(h);
            const bool  suspended      = (suspend_result != DWORD(-1));

            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(h, &ctx)) inspect_ctx(ctx);
            if (suspended) ResumeThread(h);
            CloseHandle(h);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hits;
}

inline auto address_is_executable(uintptr_t addr) noexcept -> bool
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == 0)
        return true;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ
                          | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return (mbi.Protect & exec_mask) != 0;
}

struct module_range
{
    HMODULE   mod  = nullptr;
    uintptr_t base = 0;
    size_t    size = 0;
};

using module_cache = std::vector<module_range>;

inline auto build_module_cache() noexcept -> module_cache
{
    module_cache out;
    HMODULE mods[512] = {};
    DWORD needed = 0;
    if (!EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &needed, LIST_MODULES_ALL))
        return out;
    const uint32_t total = needed / sizeof(HMODULE);
    out.reserve(total);
    for (uint32_t i = 0; i < total && i < sizeof(mods) / sizeof(mods[0]); ++i)
    {
        MODULEINFO mi{};
        if (!GetModuleInformation(GetCurrentProcess(), mods[i], &mi, sizeof(mi))) continue;
        out.push_back({ mods[i], uintptr_t(mi.lpBaseOfDll), mi.SizeOfImage });
    }
    return out;
}

inline auto find_containing_module(const module_cache& cache, uintptr_t addr) noexcept -> const module_range*
{
    for (const auto& m : cache)
        if (addr >= m.base && addr < m.base + m.size) return &m;
    return nullptr;
}

inline auto check_module_iat(HMODULE mod, const module_cache& cache, uint32_t& bits) noexcept -> bool
{
    if (!mod) return true;
    auto* base = reinterpret_cast<uint8_t*>(mod);

    __try
    {
        auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return true;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return true;

        const auto& imp_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (imp_dir.VirtualAddress == 0 || imp_dir.Size == 0) return true;

        auto* desc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + imp_dir.VirtualAddress);
        for (; desc->Name != 0; ++desc)
        {
            auto* orig = desc->OriginalFirstThunk
                         ? reinterpret_cast<PIMAGE_THUNK_DATA>(base + desc->OriginalFirstThunk)
                         : nullptr;
            auto* cur  = reinterpret_cast<PIMAGE_THUNK_DATA>(base + desc->FirstThunk);
            if (orig && orig->u1.Function == cur->u1.Function) continue;

            for (; cur->u1.Function != 0; ++cur)
            {
                const uintptr_t addr = uintptr_t(cur->u1.Function);
                const auto* hit = find_containing_module(cache, addr);
                if (!hit)
                {
                    if (!address_is_executable(addr))
                    {
                        bits |= bit_iat_target_noncode;
                    }
                    return false;
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { bits |= bit_scan_faulted; return true; }
    return true;
}

inline auto check_all_modules_iat(uint32_t& bits) noexcept -> uint32_t
{
    const auto cache = build_module_cache();
    if (cache.empty()) return 0;

    static const wchar_t* const critical[] = {
        nullptr,
        xorstr_(L"kernel32.dll"),
        xorstr_(L"kernelbase.dll"),
        xorstr_(L"user32.dll"),
        xorstr_(L"advapi32.dll"),
        xorstr_(L"wintrust.dll"),
        xorstr_(L"bcrypt.dll"),
        xorstr_(L"crypt32.dll"),
        xorstr_(L"ws2_32.dll"),
        xorstr_(L"winhttp.dll"),
    };

    uint32_t hooked = 0;
    for (const auto* name : critical)
    {
        HMODULE m = name ? GetModuleHandleW(name) : GetModuleHandleW(nullptr);
        if (!m) continue;
        if (!check_module_iat(m, cache, bits))
        {
            hooked++;
            bits |= bit_any_module_iat_hooked;
        }
    }
    return hooked;
}

struct veh_state
{
    std::mutex mu;
    PVOID      cookie_a = nullptr;
    PVOID      cookie_b = nullptr;
    bool       seeded   = false;
};

inline auto veh() -> veh_state&
{
    static veh_state v;
    return v;
}

inline auto veh_dummy_a(EXCEPTION_POINTERS*) -> LONG { return EXCEPTION_CONTINUE_SEARCH; }
inline auto veh_dummy_b(EXCEPTION_POINTERS*) -> LONG { return EXCEPTION_CONTINUE_SEARCH; }

inline auto seed_veh_baseline() noexcept -> void
{
    auto& v = veh();
    std::lock_guard lk(v.mu);
    if (v.seeded) return;
    v.cookie_a = AddVectoredExceptionHandler(0, veh_dummy_a);
    v.cookie_b = AddVectoredExceptionHandler(0, veh_dummy_b);
    v.seeded   = (v.cookie_a != nullptr && v.cookie_b != nullptr);
}

inline auto check_veh_baseline(uint32_t& bits) noexcept -> void
{
    auto& v = veh();
    std::lock_guard lk(v.mu);
    if (!v.seeded) return;

    bool tampered = false;
    if (v.cookie_b)
    {
        if (RemoveVectoredExceptionHandler(v.cookie_b) == 0) tampered = true;
        v.cookie_b = nullptr;
    }
    if (v.cookie_a)
    {
        if (RemoveVectoredExceptionHandler(v.cookie_a) == 0) tampered = true;
        v.cookie_a = nullptr;
    }
    if (tampered) bits |= bit_veh_count_grew;

    v.cookie_a = AddVectoredExceptionHandler(0, veh_dummy_a);
    v.cookie_b = AddVectoredExceptionHandler(0, veh_dummy_b);
    v.seeded   = (v.cookie_a != nullptr && v.cookie_b != nullptr);
}

inline auto peb_module_count() noexcept -> uint32_t
{
    auto* peb = protection::nt::CurrentPeb();
    if (!peb) return 0;

    __try
    {
        auto* ldr = peb->Ldr;
        if (!ldr) return 0;
        auto* head = &ldr->InMemoryOrderModuleList;
        auto* cur  = head->Flink;
        uint32_t count = 0;
        for (; cur != head && count < 4096; cur = cur->Flink)
        {
            ++count;
        }
        return count;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

inline auto check_module_list_consistency(uint32_t& bits, uint32_t& peb_n, uint32_t& psapi_n) noexcept -> void
{
    peb_n = peb_module_count();

    HMODULE mods[512] = {};
    DWORD needed = 0;
    psapi_n = 0;
    if (EnumProcessModulesEx(GetCurrentProcess(), mods, sizeof(mods), &needed, LIST_MODULES_ALL))
    {
        psapi_n = needed / sizeof(HMODULE);
    }
    if (peb_n == 0 || psapi_n == 0) return;
    const uint32_t hi = peb_n > psapi_n ? peb_n : psapi_n;
    const uint32_t lo = peb_n < psapi_n ? peb_n : psapi_n;
    if (hi - lo > 2)
    {
        bits |= bit_ldr_module_list_mismatch;
    }
}

struct hook_report
{
    uint32_t bits                    = 0;
    uint32_t ntdll_prologue_diffs    = 0;
    uint32_t syscall_stub_bad_count  = 0;
    uint32_t hardware_bp_threads     = 0;
    uint32_t modules_iat_hooked      = 0;
    uint32_t peb_module_count        = 0;
    uint32_t psapi_module_count      = 0;
};

inline auto run_full_scan() noexcept -> hook_report
{
    hook_report r{};
    seed_veh_baseline();

    disk_module ntdll_disk{};
    HMODULE     ntdll_mem = GetModuleHandleW(xorstr_(L"ntdll.dll"));

    if (!open_disk_shadow(xorstr_(L"ntdll.dll"), ntdll_disk))
    {
        r.bits |= bit_ntdll_shadow_map_failed;
    }
    else
    {
        static const char* const ntdll_hot[] = {
            xorstr_("NtDeviceIoControlFile"), xorstr_("NtProtectVirtualMemory"), xorstr_("NtWriteFile"),
            xorstr_("NtCreateFile"), xorstr_("NtOpenProcess"), xorstr_("NtQuerySystemInformation"),
            xorstr_("NtQueryInformationProcess"), xorstr_("NtReadVirtualMemory"),
            xorstr_("NtAllocateVirtualMemory"), xorstr_("NtCreateThreadEx"),
            xorstr_("NtOpenThread"), xorstr_("NtTerminateProcess"),
            xorstr_("LdrLoadDll"), xorstr_("LdrGetProcedureAddress"), xorstr_("RtlAllocateHeap"),
        };
        r.ntdll_prologue_diffs = check_module_prologues(
            ntdll_mem, ntdll_disk, ntdll_hot, sizeof(ntdll_hot) / sizeof(ntdll_hot[0]), r.bits);
        r.syscall_stub_bad_count = check_syscall_stubs(ntdll_mem, ntdll_disk, r.bits);
    }

    r.hardware_bp_threads = check_hardware_breakpoints(r.bits);
    r.modules_iat_hooked  = check_all_modules_iat(r.bits);
    check_veh_baseline(r.bits);
    check_module_list_consistency(r.bits, r.peb_module_count, r.psapi_module_count);

    close_disk_module(ntdll_disk);
    return r;
}

}
