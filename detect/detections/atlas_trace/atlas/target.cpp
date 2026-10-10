#include "target.h"
#include "ntdefs.h"
#include "trust.h"
#include "pe.h"

#include <tlhelp32.h>
#include <psapi.h>
#include <shellapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "version.lib")

namespace atlas {
namespace {

struct PebOffsets {
    size_t ptr;
    size_t peb_ProcessParameters;
    size_t pp_CurrentDirectory;
    size_t pp_ImagePathName;
    size_t pp_CommandLine;
    size_t pp_Environment;
};

const PebOffsets kPeb64 = { 8, 0x20, 0x38, 0x60, 0x70, 0x80 };
const PebOffsets kPeb32 = { 4, 0x10, 0x24, 0x38, 0x40, 0x48 };

std::vector<std::wstring> SplitArgs(const std::wstring& cmdline) {
    std::vector<std::wstring> out;
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(cmdline.c_str(), &argc);
    if (!argv) return out;
    for (int i = 0; i < argc; ++i) out.push_back(argv[i]);
    LocalFree(argv);
    return out;
}

std::vector<std::wstring> SplitPathList(const std::wstring& s) {
    std::vector<std::wstring> out;
    size_t start = 0;
    while (start <= s.size()) {
        size_t p = s.find(L';', start);
        if (p == std::wstring::npos) p = s.size();
        if (p > start) out.push_back(s.substr(start, p - start));
        start = p + 1;
    }
    return out;
}

}

const char* LauncherName(Launcher l) {
    static const std::string kVanilla  = xorstr_("Vanilla / Mojang launcher");
    static const std::string kForge    = xorstr_("Forge");
    static const std::string kOptifine = xorstr_("OptiFine");
    static const std::string kLunar    = xorstr_("Lunar Client");
    static const std::string kBadlion  = xorstr_("Badlion Client");
    static const std::string kFeather  = xorstr_("Feather Client");
    static const std::string kPrism    = xorstr_("Prism / MultiMC");
    static const std::string kModrinth = xorstr_("Modrinth App");
    static const std::string kLabymod  = xorstr_("LabyMod");
    static const std::string kUnknown  = xorstr_("unknown");
    switch (l) {
        case Launcher::Vanilla:  return kVanilla.c_str();
        case Launcher::Forge:    return kForge.c_str();
        case Launcher::Optifine: return kOptifine.c_str();
        case Launcher::Lunar:    return kLunar.c_str();
        case Launcher::Badlion:  return kBadlion.c_str();
        case Launcher::Feather:  return kFeather.c_str();
        case Launcher::Prism:    return kPrism.c_str();
        case Launcher::Modrinth: return kModrinth.c_str();
        case Launcher::Labymod:  return kLabymod.c_str();
        default:                 return kUnknown.c_str();
    }
}

const Section* Module::SectionOf(uint64_t addr) const {
    if (!Contains(addr)) return nullptr;
    uint64_t rva = addr - base;
    for (const Section& s : sections)
        if (rva >= s.rva && rva < s.rva + s.size) return &s;
    return nullptr;
}

Target::~Target() { Close(); }

void Target::Close() {
    if (h_) { CloseHandle(h_); h_ = nullptr; }
}

bool Target::Open(DWORD pid, std::string* err) {
    pid_ = pid;
    h_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h_) {
        h_ = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    }
    if (!h_) {
        return false;
    }

    BOOL wow = FALSE;
    IsWow64Process(h_, &wow);
    is64_ = !wow;

    wchar_t path[MAX_PATH * 2] = {};
    DWORD n = (DWORD)(sizeof(path) / sizeof(path[0]));
    if (QueryFullProcessImageNameW(h_, 0, path, &n)) imagePath_.assign(path, n);

    ReadPebStrings();
    if (!EnumRegions()) { return false; }
    EnumModules();
    BuildReservations();
    EnumThreads();
    IdentifyLauncher();
    IdentifyGameVersion();
    return true;
}

bool Target::Read(uint64_t addr, void* buf, size_t n) const {
    if (!h_ || !n) return false;
    SIZE_T got = 0;
    if (!ReadProcessMemory(h_, (LPCVOID)addr, buf, n, &got)) return false;
    return got == n;
}

bool Target::ReadRegion(const Region& r, std::vector<uint8_t>& out, size_t cap) const {
    size_t want = (size_t)(std::min)((uint64_t)cap, r.size);
    out.assign(want, 0);
    SIZE_T got = 0;
    if (!ReadProcessMemory(h_, (LPCVOID)r.base, out.data(), want, &got)) {
        out.assign(want, 0);
        bool any = false;
        for (size_t off = 0; off < want; off += 0x1000) {
            SIZE_T g = 0;
            size_t chunk = (std::min)((size_t)0x1000, want - off);
            if (ReadProcessMemory(h_, (LPCVOID)(r.base + off), out.data() + off, chunk, &g))
                any = true;
        }
        return any;
    }
    out.resize(got);
    return got > 0;
}

std::string Target::ReadCString(uint64_t addr, size_t maxLen) const {
    std::string s;
    char buf[128];
    while (s.size() < maxLen) {
        size_t want = (std::min)(sizeof(buf), maxLen - s.size());
        SIZE_T got = 0;
        if (!ReadProcessMemory(h_, (LPCVOID)(addr + s.size()), buf, want, &got) || got == 0)
            break;
        for (SIZE_T i = 0; i < got; ++i) {
            if (buf[i] == '\0') return s;
            s.push_back(buf[i]);
        }
    }
    return s;
}

bool Target::ReadPebStrings() {
    if (!nt::NtQueryInformationProcess) return false;

    uint64_t pebAddr = 0;
    const PebOffsets* o = &kPeb64;
    if (!is64_) {
        PVOID peb32 = nullptr;
        ULONG rl = 0;
        if (ATLAS_NT_SUCCESS(nt::NtQueryInformationProcess(h_, nt::ProcessWow64Information,
                                                           &peb32, sizeof(peb32), &rl)) &&
            peb32) {
            pebAddr = (uint64_t)peb32;
            o = &kPeb32;
        }
    }
    if (!pebAddr) {
        nt::PROCESS_BASIC_INFORMATION pbi{};
        ULONG len = 0;
        if (!ATLAS_NT_SUCCESS(nt::NtQueryInformationProcess(h_, nt::ProcessBasicInformation,
                                                            &pbi, sizeof(pbi), &len)))
            return false;
        if (!pbi.PebBaseAddress) return false;
        pebAddr = (uint64_t)pbi.PebBaseAddress;
        o = &kPeb64;
    }

    uint64_t ppAddr = 0;
    if (!Read(pebAddr + o->peb_ProcessParameters, &ppAddr, o->ptr)) return false;
    if (!ppAddr) return false;

    auto readUs = [&](size_t fieldOff, std::wstring* out) {
        uint16_t length = 0;
        if (!Read(ppAddr + fieldOff, &length, sizeof(length))) return;
        if (length == 0 || length > 0x8000) return;
        uint64_t buffer = 0;
        if (!Read(ppAddr + fieldOff + o->ptr, &buffer, o->ptr)) return;
        if (!buffer) return;
        out->assign(length / sizeof(wchar_t), L'\0');
        if (!Read(buffer, &(*out)[0], length)) out->clear();
    };
    uint64_t envPtr = 0;
    if (Read(ppAddr + o->pp_Environment, &envPtr, o->ptr) && envPtr) {
        std::vector<wchar_t> buf(32768, L'\0');
        SIZE_T got = 0;
        ReadProcessMemory(h_, (LPCVOID)envPtr, buf.data(), buf.size() * sizeof(wchar_t), &got);
        size_t chars = got / sizeof(wchar_t);
        size_t i = 0;
        while (i < chars) {
            size_t len = 0;
            while (i + len < chars && buf[i + len] != L'\0') ++len;
            if (len == 0) break;
            env_.push_back(std::wstring(&buf[i], len));
            i += len + 1;
        }
    }

    readUs(o->pp_CommandLine, &cmdLine_);
    readUs(o->pp_CurrentDirectory, &curDir_);
    if (imagePath_.empty()) readUs(o->pp_ImagePathName, &imagePath_);
    return true;
}

void Target::LoadSections(Module& m) {
    uint8_t hdr[0x1000];
    if (!Read(m.base, hdr, sizeof(hdr))) return;
    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hdr);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr))
        return;
    const IMAGE_NT_HEADERS32* nt32 =
        reinterpret_cast<const IMAGE_NT_HEADERS32*>(hdr + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return;

    WORD numSections = nt32->FileHeader.NumberOfSections;
    WORD optSize     = nt32->FileHeader.SizeOfOptionalHeader;
    if (numSections == 0 || numSections > 96) return;

    size_t secOff = (size_t)dos->e_lfanew + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + optSize;
    if (secOff + sizeof(IMAGE_SECTION_HEADER) * numSections > sizeof(hdr)) return;
    const IMAGE_SECTION_HEADER* secs =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(hdr + secOff);
    for (WORD i = 0; i < numSections; ++i) {
        char nb[9] = {};
        memcpy(nb, secs[i].Name, 8);
        Section s;
        s.name = nb;
        s.rva  = secs[i].VirtualAddress;
        s.size = secs[i].Misc.VirtualSize ? secs[i].Misc.VirtualSize : secs[i].SizeOfRawData;
        s.characteristics = secs[i].Characteristics;
        m.sections.push_back(s);
    }
    if (m.size == 0) {
        if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            const IMAGE_NT_HEADERS64* nt64 =
                reinterpret_cast<const IMAGE_NT_HEADERS64*>(hdr + dos->e_lfanew);
            m.size = nt64->OptionalHeader.SizeOfImage;
        } else {
            m.size = nt32->OptionalHeader.SizeOfImage;
        }
    }
}

bool MappedImageIs32Bit(HANDLE h, uint64_t base) {
    IMAGE_DOS_HEADER dos{};
    SIZE_T got = 0;
    if (!ReadProcessMemory(h, (LPCVOID)base, &dos, sizeof(dos), &got) || got != sizeof(dos))
        return false;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos.e_lfanew <= 0 || dos.e_lfanew > 0x10000) return false;
    DWORD sig = 0;
    IMAGE_FILE_HEADER fh{};
    if (!ReadProcessMemory(h, (LPCVOID)(base + dos.e_lfanew), &sig, sizeof(sig), &got) ||
        got != sizeof(sig) || sig != IMAGE_NT_SIGNATURE)
        return false;
    if (!ReadProcessMemory(h, (LPCVOID)(base + dos.e_lfanew + 4), &fh, sizeof(fh), &got) ||
        got != sizeof(fh))
        return false;
    return fh.Machine == IMAGE_FILE_MACHINE_I386;
}

std::wstring WowRedirectSystemPath(HANDLE h, uint64_t base,
                                   const std::wstring& path, bool targetIs64) {
    if (targetIs64 || path.empty()) return path;
    wchar_t win[MAX_PATH] = {};
    UINT n = GetWindowsDirectoryW(win, MAX_PATH);
    if (!n || n >= MAX_PATH) return path;
    std::wstring sys32 = std::wstring(win) + xorstr_(L"\\System32\\");
    if (path.size() <= sys32.size()) return path;
    if (_wcsnicmp(path.c_str(), sys32.c_str(), sys32.size()) != 0) return path;
    if (!MappedImageIs32Bit(h, base)) return path;
    std::wstring wow = std::wstring(win) + xorstr_(L"\\SysWOW64\\") + path.substr(sys32.size());
    if (GetFileAttributesW(wow.c_str()) == INVALID_FILE_ATTRIBUTES) return path;
    return wow;
}

bool Target::EnumModules() {
    modules_.clear();

    std::set<uint64_t> loaderBases;
    std::vector<HMODULE> mods(1024);
    DWORD needed = 0;
    for (int attempt = 0; attempt < 3; ++attempt) {
        if (!EnumProcessModulesEx(h_, mods.data(), (DWORD)(mods.size() * sizeof(HMODULE)),
                                  &needed, LIST_MODULES_ALL))
            break;
        if (needed <= mods.size() * sizeof(HMODULE)) {
            mods.resize(needed / sizeof(HMODULE));
            break;
        }
        mods.resize(needed / sizeof(HMODULE) + 64);
    }
    for (HMODULE hm : mods) {
        if (!hm) continue;
        Module m;
        m.base = (uint64_t)hm;
        m.inLoaderList = true;
        m.backedByFile = true;
        wchar_t buf[MAX_PATH * 2] = {};
        if (GetModuleFileNameExW(h_, hm, buf, (DWORD)(sizeof(buf) / sizeof(buf[0]))))
            m.path = WowRedirectSystemPath(h_, m.base, buf, is64_);
        MODULEINFO mi{};
        if (GetModuleInformation(h_, hm, &mi, sizeof(mi))) m.size = mi.SizeOfImage;
        m.name = FileNameOfW(m.path);
        LoadSections(m);
        m.trust = ClassifyModule(m.path, &m.signer);
        loaderBases.insert(m.base);
        modules_.push_back(m);
    }

    std::set<uint64_t> seenAlloc;
    for (const Region& r : regions_) {
        if (r.type != MEM_IMAGE || r.state == MEM_FREE) continue;
        if (loaderBases.count(r.allocBase)) continue;
        if (!seenAlloc.insert(r.allocBase).second) continue;

        Module m;
        m.base = r.allocBase;
        m.inLoaderList = false;
        m.backedByFile = !r.mappedFile.empty();
        m.path = WowRedirectSystemPath(h_, m.base, r.mappedFile, is64_);
        m.name = FileNameOfW(m.path);
        if (m.name.empty()) m.name = xorstr_(L"<unnamed image>");
        LoadSections(m);
        if (m.size == 0) {
            for (const Region& q : regions_)
                if (q.allocBase == r.allocBase) m.size = (q.base + q.size) - r.allocBase;
        }
        m.trust = ClassifyModule(m.path, &m.signer);
        modules_.push_back(m);
    }

    std::sort(modules_.begin(), modules_.end(),
              [](const Module& a, const Module& b) { return a.base < b.base; });
    return !modules_.empty();
}

bool Target::EnumRegions() {
    regions_.clear();
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uint64_t addr = (uint64_t)si.lpMinimumApplicationAddress;
    uint64_t maxAddr = (uint64_t)si.lpMaximumApplicationAddress;

    MEMORY_BASIC_INFORMATION mbi{};
    while (addr < maxAddr) {
        SIZE_T got = VirtualQueryEx(h_, (LPCVOID)addr, &mbi, sizeof(mbi));
        if (got != sizeof(mbi)) {
            addr += 0x1000;
            continue;
        }
        if (mbi.State != MEM_FREE) {
            Region r;
            r.base    = (uint64_t)mbi.BaseAddress;
            r.size    = (uint64_t)mbi.RegionSize;
            r.allocBase = (uint64_t)mbi.AllocationBase;
            r.state   = mbi.State;
            r.protect = mbi.Protect;
            r.allocProtect = mbi.AllocationProtect;
            r.type    = mbi.Type;
            if (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) {
                wchar_t nameBuf[MAX_PATH * 2] = {};
                if (GetMappedFileNameW(h_, mbi.BaseAddress, nameBuf,
                                       (DWORD)(sizeof(nameBuf) / sizeof(nameBuf[0])))) {
                    r.mappedFile = NtPathToDosPath(nameBuf);
                }
            }
            regions_.push_back(r);
        }
        uint64_t next = (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
        if (regions_.size() > 200000) break;
    }
    return !regions_.empty();
}

void Target::BuildReservations() {
    reservations_.clear();
    std::map<uint64_t, Reservation> byBase;
    for (const Region& r : regions_) {
        if (r.allocBase == 0) continue;
        Reservation& res = byBase[r.allocBase];
        res.base = r.allocBase;
        res.type = r.type;
        res.parts.push_back(&r);
        uint64_t end = r.base + r.size;
        if (end - res.base > res.totalSize) res.totalSize = end - res.base;
        if (r.state == MEM_RESERVE) res.hasReserve = true;
        if (r.state == MEM_COMMIT) {
            res.committedTotal += r.size;
            if (r.Executable()) res.committedExec += r.size;
        }
    }
    reservations_.reserve(byBase.size());
    for (std::map<uint64_t, Reservation>::iterator it = byBase.begin(); it != byBase.end(); ++it)
        reservations_.push_back(it->second);
}

bool Target::EnumThreads() {
    threads_.clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid_) continue;
            ThreadInfo ti;
            ti.tid = te.th32ThreadID;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!th) th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (th) {
                if (nt::NtQueryInformationThread) {
                    PVOID start = nullptr;
                    ULONG rl = 0;
                    if (ATLAS_NT_SUCCESS(nt::NtQueryInformationThread(
                            th, nt::ThreadQuerySetWin32StartAddress, &start, sizeof(start), &rl)))
                        ti.startAddress = (uint64_t)start;
                    else
                        ti.queryFailed = true;

                    nt::THREAD_BASIC_INFORMATION tbi{};
                    if (ATLAS_NT_SUCCESS(nt::NtQueryInformationThread(
                            th, nt::ThreadBasicInformation, &tbi, sizeof(tbi), &rl)))
                        ti.tebAddress = (uint64_t)tbi.TebBaseAddress;

                    BOOLEAN hidden = FALSE;
                    if (ATLAS_NT_SUCCESS(nt::NtQueryInformationThread(
                            th, nt::ThreadHideFromDebugger, &hidden, sizeof(hidden), &rl)))
                        ti.hiddenFromDebugger = (hidden != FALSE);
                }
                FILETIME c{}, e{}, k{}, u{};
                if (GetThreadTimes(th, &c, &e, &k, &u)) ti.createTime = c;
                CloseHandle(th);
            } else {
                ti.queryFailed = true;
            }
            threads_.push_back(ti);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return true;
}

bool Target::RefreshRegions() {
    bool ok = EnumRegions();
    BuildReservations();
    return ok;
}

bool Target::RefreshThreads() { return EnumThreads(); }

void Target::IdentifyGameVersion() {
    auto firstVersionIn = [](const std::wstring& s) -> std::string {
        for (size_t i = 0; i < s.size(); ++i) {
            if (s[i] < L'1' || s[i] > L'9') continue;
            if (i && (iswdigit(s[i - 1]) || s[i - 1] == L'.')) continue;
            size_t j = i, dots = 0;
            while (j < s.size() && (iswdigit(s[j]) || s[j] == L'.')) {
                if (s[j] == L'.') {
                    if (++dots > 2) break;
                    if (j + 1 >= s.size() || !iswdigit(s[j + 1])) break;
                }
                ++j;
            }
            if (dots >= 1 && j - i >= 3) {
                std::wstring v = s.substr(i, j - i);
                while (!v.empty() && v.back() == L'.') v.pop_back();
                return WideToUtf8(v);
            }
        }
        return std::string();
    };

    std::vector<std::wstring> args = SplitArgs(cmdLine_);
    for (size_t i = 0; i + 1 < args.size(); ++i) {
        if (_wcsicmp(args[i].c_str(), xorstr_(L"--version")) != 0) continue;
        std::string v = firstVersionIn(args[i + 1]);
        if (!v.empty()) { gameVersion_ = v; return; }
    }
    std::wstring lc = ToLowerW(cmdLine_);
    size_t at = lc.find(xorstr_(L"\\versions\\"));
    if (at != std::wstring::npos) {
        size_t start = at + 10;
        size_t end = lc.find(L'\\', start);
        if (end != std::wstring::npos && end > start) {
            std::string v = firstVersionIn(cmdLine_.substr(start, end - start));
            if (!v.empty()) gameVersion_ = v;
        }
    }
}

void Target::IdentifyLauncher() {
    std::wstring lc = ToLowerW(cmdLine_);

    if (IContainsW(lc, xorstr_(L"lunarclient")) || IContainsW(lc, xorstr_(L"com.moonsworth")))
        launcher_ = Launcher::Lunar;
    else if (IContainsW(lc, xorstr_(L"badlion")))
        launcher_ = Launcher::Badlion;
    else if (IContainsW(lc, xorstr_(L"feather")) || IContainsW(lc, xorstr_(L"\\.dawn\\")) ||
             IContainsW(lc, xorstr_(L"dawn (feather)")))
        launcher_ = Launcher::Feather;
    else if (IContainsW(lc, xorstr_(L"labymod")))
        launcher_ = Launcher::Labymod;
    else if (IContainsW(lc, xorstr_(L"prismlauncher")) || IContainsW(lc, xorstr_(L"multimc")) ||
             IContainsW(lc, xorstr_(L"org.prismlauncher")))
        launcher_ = Launcher::Prism;
    else if (IContainsW(lc, xorstr_(L"modrinth")))
        launcher_ = Launcher::Modrinth;
    else if (IContainsW(lc, xorstr_(L"fmllauncher")) || IContainsW(lc, xorstr_(L"forge")) ||
             IContainsW(lc, xorstr_(L"launchwrapper")))
        launcher_ = Launcher::Forge;
    else if (IContainsW(lc, xorstr_(L"optifine")))
        launcher_ = Launcher::Optifine;
    else if (IContainsW(lc, xorstr_(L"net.minecraft.client.main.main")))
        launcher_ = Launcher::Vanilla;

    std::vector<std::wstring> args = SplitArgs(cmdLine_);
    for (size_t i = 0; i < args.size(); ++i) {
        const std::wstring& a = args[i];
        if ((a == xorstr_(L"-cp") || a == xorstr_(L"-classpath") || a == xorstr_(L"--class-path")) && i + 1 < args.size()) {
            classpath_ = SplitPathList(args[i + 1]);
        } else if (a.compare(0, 11, xorstr_(L"-javaagent:")) == 0 ||
                   a.compare(0, 11, xorstr_(L"-agentpath:")) == 0 ||
                   a.compare(0, 10, xorstr_(L"-agentlib:")) == 0) {
            agentArgs_.push_back(a);
        }
    }

    const Module* jvm = ModuleByName(xorstr_(L"jvm.dll"));
    if (jvm && !jvm->path.empty()) {
        DWORD dummy = 0;
        DWORD sz = GetFileVersionInfoSizeW(jvm->path.c_str(), &dummy);
        if (sz) {
            std::vector<BYTE> buf(sz);
            if (GetFileVersionInfoW(jvm->path.c_str(), 0, sz, buf.data())) {
                VS_FIXEDFILEINFO* ffi = nullptr;
                UINT len = 0;
                if (VerQueryValueW(buf.data(), xorstr_(L"\\"), (LPVOID*)&ffi, &len) && ffi) {
                    javaVersion_ = Format(xorstr_("%u.%u.%u.%u"),
                                          HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
                                          HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
                }
            }
        }
    }
}

std::wstring Target::EnvValue(const wchar_t* name) const {
    std::wstring prefix = std::wstring(name) + xorstr_(L"=");
    for (size_t i = 0; i < env_.size(); ++i) {
        if (env_[i].size() <= prefix.size()) continue;
        if (_wcsnicmp(env_[i].c_str(), prefix.c_str(), prefix.size()) == 0)
            return env_[i].substr(prefix.size());
    }
    return std::wstring();
}

const Module* Target::ModuleAt(uint64_t addr) const {
    for (const Module& m : modules_)
        if (m.Contains(addr)) return &m;
    return nullptr;
}

const Module* Target::ModuleByName(const wchar_t* name) const {
    for (const Module& m : modules_)
        if (_wcsicmp(m.name.c_str(), name) == 0) return &m;
    return nullptr;
}

const Region* Target::RegionAt(uint64_t addr) const {
    for (const Region& r : regions_)
        if (r.Contains(addr)) return &r;
    return nullptr;
}

const Reservation* Target::ReservationAt(uint64_t addr) const {
    for (const Reservation& r : reservations_)
        if (addr >= r.base && addr < r.base + r.totalSize) return &r;
    return nullptr;
}

bool Target::IsCodeCache(uint64_t addr) const {
    const Region* r = RegionAt(addr);
    if (!r) return false;
    return codeCacheBases_.count(r->allocBase) != 0;
}

bool Target::IsUnbacked(uint64_t addr) const {
    const Region* r = RegionAt(addr);
    if (!r) return false;
    if (r->type == MEM_IMAGE) return false;
    if (r->type == MEM_MAPPED && !r->mappedFile.empty()) return false;
    return true;
}

std::vector<DWORD> FindMinecraftProcesses(std::string* note) {
    (void)note;
    std::vector<DWORD> out;
    std::vector<DWORD> javaPids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return out;
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring n = ToLowerW(pe.szExeFile);
            if (n == xorstr_(L"javaw.exe") || n == xorstr_(L"java.exe"))
                javaPids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    struct Cand { DWORD pid = 0; int score = 0; };
    std::vector<Cand> scored;
    for (DWORD pid : javaPids) {
        Target probe;
        if (!probe.Open(pid, nullptr)) continue;

        if (!probe.ModuleByName(xorstr_(L"jvm.dll"))) continue;

        Cand c;
        c.pid = pid;
        std::wstring lc = ToLowerW(probe.commandLine());
        if (IContainsW(lc, xorstr_(L"minecraft")))    c.score += 8;
        if (IContainsW(lc, xorstr_(L"net.minecraft")) || IContainsW(lc, xorstr_(L"net/minecraft"))) c.score += 4;
        if (IContainsW(lc, xorstr_(L"--gamedir")) || IContainsW(lc, xorstr_(L"--assetsdir")) ||
            IContainsW(lc, xorstr_(L"--versiontype"))) c.score += 4;
        if (probe.launcher() != Launcher::Unknown) c.score += 4;
        if (IContainsW(lc, xorstr_(L"lunar")) || IContainsW(lc, xorstr_(L"badlion")) ||
            IContainsW(lc, xorstr_(L"feather")) || IContainsW(lc, xorstr_(L"forge")) ||
            IContainsW(lc, xorstr_(L"fabric")) || IContainsW(lc, xorstr_(L"labymod")) ||
            IContainsW(lc, xorstr_(L"optifine"))) c.score += 2;
        scored.push_back(c);
    }

    std::stable_sort(scored.begin(), scored.end(),
                     [](const Cand& a, const Cand& b) { return a.score > b.score; });
    for (size_t i = 0; i < scored.size(); ++i) out.push_back(scored[i].pid);

    return out;
}

}
