#include "checks.h"
#include "ntdefs.h"
#include "trust.h"

namespace atlas {
namespace {

struct UnloadEvent {
    uint64_t BaseAddress;
    uint64_t SizeOfImage;
    uint32_t Sequence;
    uint32_t TimeDateStamp;
    uint32_t CheckSum;
    wchar_t  ImageName[32];
};

typedef VOID(NTAPI* PFN_RtlGetUnloadEventTraceEx)(PULONG*, PULONG*, PVOID*);

bool NameIsAccountedFor(const Target& t, const std::wstring& name,
                        std::string* whereOut) {
    std::wstring lower = ToLowerW(name);

    for (size_t i = 0; i < t.modules().size(); ++i) {
        const Module& m = t.modules()[i];
        if (ToLowerW(m.name) != lower) continue;
        if (m.trust != Trust::Unknown) {
            *whereOut = xorstr_("currently loaded from ") + WideToUtf8(m.path);
            return true;
        }
    }

    static std::vector<std::wstring>* roots = nullptr;
    if (!roots) {
        roots = new std::vector<std::wstring>();
        wchar_t sys[MAX_PATH] = {};
        if (GetSystemDirectoryW(sys, MAX_PATH)) {
            roots->push_back(std::wstring(sys) + xorstr_(L"\\"));
            roots->push_back(std::wstring(sys) + xorstr_(L"\\drivers\\"));
        }
        wchar_t win[MAX_PATH] = {};
        if (GetWindowsDirectoryW(win, MAX_PATH)) {
            roots->push_back(std::wstring(win) + xorstr_(L"\\SysWOW64\\"));
            roots->push_back(std::wstring(win) + xorstr_(L"\\"));
            std::wstring repo = std::wstring(win) + xorstr_(L"\\System32\\DriverStore\\FileRepository\\");
            WIN32_FIND_DATAW fd{};
            HANDLE h = FindFirstFileW((repo + xorstr_(L"*")).c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    if (fd.cFileName[0] == L'.') continue;
                    roots->push_back(repo + fd.cFileName + xorstr_(L"\\"));
                } while (FindNextFileW(h, &fd));
                FindClose(h);
            }
        }
    }

    std::vector<std::wstring> local;
    std::set<std::wstring> seenDirs;
    for (size_t i = 0; i < t.modules().size(); ++i) {
        const std::wstring& p = t.modules()[i].path;
        if (p.empty()) continue;
        std::wstring dir = DirNameOfW(p);
        if (dir.empty()) continue;
        if (seenDirs.insert(ToLowerW(dir)).second) local.push_back(dir + xorstr_(L"\\"));
    }
    std::wstring jreBin = DirNameOfW(t.imagePath());
    if (!jreBin.empty()) {
        local.push_back(jreBin + xorstr_(L"\\"));
        local.push_back(jreBin + xorstr_(L"\\server\\"));
    }

    for (int pass = 0; pass < 2; ++pass) {
        const std::vector<std::wstring>& list = (pass == 0) ? local : *roots;
        for (size_t i = 0; i < list.size(); ++i) {
            std::wstring cand = list[i] + name;
            if (GetFileAttributesW(cand.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
            std::string signer;
            Trust tr = ClassifyModule(cand, &signer);
            if (tr != Trust::Unknown) {
                *whereOut = WideToUtf8(cand) +
                            (signer.empty() ? std::string() : xorstr_(" (") + signer + xorstr_(")"));
                return true;
            }
        }
    }
    return false;
}

bool LooksLikeRandomName(const std::wstring& name) {
    std::wstring stem = name;
    size_t dot = stem.find_last_of(L'.');
    if (dot != std::wstring::npos) stem = stem.substr(0, dot);
    if (stem.size() < 8) return false;

    size_t digits = 0, hexish = 0;
    for (size_t i = 0; i < stem.size(); ++i) {
        wchar_t c = towlower(stem[i]);
        if (iswdigit(c)) ++digits;
        if (iswdigit(c) || (c >= L'a' && c <= L'f')) ++hexish;
    }
    if (digits >= 10) return true;
    if (hexish == stem.size() && stem.size() >= 12) return true;
    return false;
}

}

void CheckUnloadedModules(Target& t, Report& r) {
    HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!ntdll) return;
    PFN_RtlGetUnloadEventTraceEx pGet =
        (PFN_RtlGetUnloadEventTraceEx)GetProcAddress(ntdll, xorstr_("RtlGetUnloadEventTraceEx"));
    if (!pGet) {
        return;
    }

    PULONG pElementSize = nullptr, pElementCount = nullptr;
    PVOID  pTracePtr = nullptr;
    pGet(&pElementSize, &pElementCount, &pTracePtr);
    if (!pElementSize || !pElementCount || !pTracePtr) return;

    uint32_t elementSize = 0, elementCount = 0;
    uint64_t traceArray = 0;
    if (!t.Read((uint64_t)pElementSize, &elementSize, sizeof(elementSize)) ||
        !t.Read((uint64_t)pElementCount, &elementCount, sizeof(elementCount)) ||
        !t.Read((uint64_t)pTracePtr, &traceArray, t.ptrSize())) {
        return;
    }
    if (!traceArray || elementSize < sizeof(UnloadEvent) || elementSize > 512 ||
        elementCount == 0 || elementCount > 4096) {
        return;
    }

    std::vector<uint8_t> raw((size_t)elementSize * elementCount);
    if (!t.Read(traceArray, raw.data(), raw.size())) {
        return;
    }

    int total = 0, unexplained = 0;
    for (uint32_t i = 0; i < elementCount; ++i) {
        const UnloadEvent* e =
            reinterpret_cast<const UnloadEvent*>(raw.data() + (size_t)i * elementSize);
        if (e->BaseAddress == 0 && e->SizeOfImage == 0) continue;

        wchar_t nameBuf[33] = {};
        memcpy(nameBuf, e->ImageName, sizeof(e->ImageName));
        nameBuf[32] = L'\0';
        std::wstring name(nameBuf);
        if (name.empty()) continue;
        ++total;

        std::string where;
        if (NameIsAccountedFor(t, name, &where)) {
            continue;
        }
        ++unexplained;

        bool random = LooksLikeRandomName(name);

        Finding f;
        f.severity   = random ? Severity::Critical : Severity::Info;
        f.id         = xorstr_("UNLOADED_UNKNOWN_MODULE");
        r.Add(f);
    }

}

}
