#include <Windows.h>
#include <intrin.h>
#include <atomic>
#include <random>
#include <string>
#include <mutex>
#include <cstring>

#include "process_disguise.h"
#include "nt_types.h"
#include "../crypt/xorstr.h"

namespace protection {
namespace disguise {

namespace {

std::atomic<bool> g_initialized{false};
std::wstring g_realPath;
std::wstring g_disguisedName;
std::wstring g_disguisedFullPath;
std::mutex   g_mtx;

std::wstring MakeRandomName() noexcept {
    try {
        static const std::wstring kAlphabet = xorstr_(L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
        std::mt19937_64 rng{
            static_cast<unsigned long long>(GetTickCount64())
            ^ (static_cast<unsigned long long>(GetCurrentProcessId()) << 16)
            ^ static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(&rng))
        };
        std::uniform_int_distribution<int> letterDist{ 0, 51 };
        std::uniform_int_distribution<int> anyDist{ 0, 61 };
        std::uniform_int_distribution<int> lenDist{ 8, 14 };

        std::wstring name;
        int len = lenDist(rng);
        name.reserve(static_cast<size_t>(len) + 4);
        name.push_back(kAlphabet[letterDist(rng)]);
        for (int i = 1; i < len; ++i) name.push_back(kAlphabet[anyDist(rng)]);
        name += xorstr_(L".exe");
        return name;
    } catch (...) {
        return std::wstring(xorstr_(L"svc_runtime.exe"));
    }
}

bool ReplaceUnicodeString(protection::nt::UNICODE_STRING_X& us, const std::wstring& newValue) noexcept {
    try {
        size_t bytes = (newValue.size() + 1) * sizeof(wchar_t);
        HANDLE heap = GetProcessHeap();
        if (!heap) return false;
        auto* buf = static_cast<wchar_t*>(HeapAlloc(heap, HEAP_ZERO_MEMORY, bytes));
        if (!buf) return false;
        std::memcpy(buf, newValue.c_str(), newValue.size() * sizeof(wchar_t));
        us.Buffer = buf;
        us.Length = static_cast<USHORT>(newValue.size() * sizeof(wchar_t));
        us.MaximumLength = static_cast<USHORT>(bytes);
        return true;
    } catch (...) { return false; }
}

bool SpoofPebStrings() noexcept {
    using namespace protection::nt;
    try {
        PPEB_X peb = CurrentPeb();
        if (!peb || !peb->ProcessParameters) return false;
        auto* pp = peb->ProcessParameters;
        bool ok = true;
        ok &= ReplaceUnicodeString(pp->ImagePathName, g_disguisedFullPath);
        ok &= ReplaceUnicodeString(pp->CommandLine,   g_disguisedFullPath);
        return ok;
    } catch (...) { return false; }
}

bool SpoofLdrEntries() noexcept {
    using namespace protection::nt;
    try {
        PPEB_X peb = CurrentPeb();
        if (!peb || !peb->Ldr) return false;
        HMODULE selfBase = GetModuleHandleW(nullptr);
        if (!selfBase) return false;

        auto* head = &peb->Ldr->InMemoryOrderModuleList;
        for (auto* cur = head->Flink; cur != head; cur = cur->Flink) {
            auto* entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY_X>(
                reinterpret_cast<BYTE*>(cur) - offsetof(LDR_DATA_TABLE_ENTRY_X, InMemoryOrderLinks));
            if (!entry || entry->DllBase != reinterpret_cast<PVOID>(selfBase)) continue;

            bool ok = true;
            ok &= ReplaceUnicodeString(entry->FullDllName, g_disguisedFullPath);
            ok &= ReplaceUnicodeString(entry->BaseDllName, g_disguisedName);
            return ok;
        }
        return false;
    } catch (...) { return false; }
}

} // namespace

bool Initialize() noexcept {
    bool expected = false;
    if (!g_initialized.compare_exchange_strong(expected, true)) return true;

    try {
        std::lock_guard<std::mutex> lk(g_mtx);

        wchar_t pathBuf[MAX_PATH * 2] = {};
        DWORD len = GetModuleFileNameW(nullptr, pathBuf, _countof(pathBuf));
        if (len == 0 || len >= _countof(pathBuf)) return false;
        g_realPath.assign(pathBuf, len);

        g_disguisedName = MakeRandomName();

        wchar_t sysDir[MAX_PATH] = {};
        if (GetSystemDirectoryW(sysDir, _countof(sysDir)) == 0) {
            std::wstring fallback = xorstr_(L"C:\\Windows\\System32");
            lstrcpyW(sysDir, fallback.c_str());
        }
        g_disguisedFullPath.assign(sysDir);
        if (!g_disguisedFullPath.empty() && g_disguisedFullPath.back() != L'\\') {
            g_disguisedFullPath.push_back(L'\\');
        }
        g_disguisedFullPath += g_disguisedName;

        bool pebOk = SpoofPebStrings();
        bool ldrOk = SpoofLdrEntries();
        return pebOk || ldrOk;
    } catch (...) { return false; }
}

const std::wstring& GetRealOwnPath() noexcept { return g_realPath; }
const std::wstring& GetDisguisedName() noexcept { return g_disguisedName; }

} // namespace disguise
} // namespace protection
