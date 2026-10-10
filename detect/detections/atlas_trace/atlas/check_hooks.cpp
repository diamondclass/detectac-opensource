#include "checks.h"
#include "pe.h"
#include "trust.h"

namespace atlas {
namespace {

bool IsPriority(const std::wstring& name) {
    static const std::wstring kPriorityModules[] = {
        xorstr_(L"jvm.dll"), xorstr_(L"java.dll"), xorstr_(L"verify.dll"), xorstr_(L"zip.dll"), xorstr_(L"net.dll"), xorstr_(L"nio.dll"),
        xorstr_(L"awt.dll"), xorstr_(L"management.dll"), xorstr_(L"instrument.dll"), xorstr_(L"attach.dll"),
        xorstr_(L"opengl32.dll"), xorstr_(L"lwjgl64.dll"), xorstr_(L"lwjgl.dll"), xorstr_(L"openal64.dll"), xorstr_(L"openal.dll"),
        xorstr_(L"ntdll.dll"), xorstr_(L"kernel32.dll"), xorstr_(L"kernelbase.dll"), xorstr_(L"user32.dll"), xorstr_(L"win32u.dll"),
        xorstr_(L"gdi32.dll"), xorstr_(L"gdi32full.dll"), xorstr_(L"ws2_32.dll"), xorstr_(L"dinput8.dll"), xorstr_(L"xinput1_4.dll"),
        xorstr_(L"d3d9.dll"), xorstr_(L"dxgi.dll"), xorstr_(L"d3d11.dll"),
    };
    for (size_t i = 0; i < sizeof(kPriorityModules) / sizeof(kPriorityModules[0]); ++i)
        if (_wcsicmp(name.c_str(), kPriorityModules[i].c_str()) == 0) return true;
    return false;
}

bool IsRuntimeCore(const std::wstring& name) {
    static const std::wstring kRuntimeCoreModules[] = {
        xorstr_(L"jvm.dll"), xorstr_(L"java.dll"), xorstr_(L"jimage.dll"), xorstr_(L"jsvml.dll"), xorstr_(L"verify.dll"),
        xorstr_(L"zip.dll"), xorstr_(L"net.dll"), xorstr_(L"nio.dll"), xorstr_(L"management.dll"), xorstr_(L"instrument.dll"),
        xorstr_(L"attach.dll"), xorstr_(L"jdwp.dll"), xorstr_(L"awt.dll"), xorstr_(L"javaw.exe"), xorstr_(L"java.exe"),
    };
    for (size_t i = 0; i < sizeof(kRuntimeCoreModules) / sizeof(kRuntimeCoreModules[0]); ++i)
        if (_wcsicmp(name.c_str(), kRuntimeCoreModules[i].c_str()) == 0) return true;
    return false;
}

struct ScanStats {
    int reported = 0;
};

bool IsLoaderImportOptimization(const uint8_t* live, const uint8_t* disk, size_t avail) {
    if (avail < 6) return false;
    if (!(disk[0] == 0xFF && disk[1] == 0x25)) return false;
    return live[0] == 0xE9 || live[0] == 0xE8;
}

uint64_t FollowTrampoline(const Target& t, uint64_t dest, const Module& hooked,
                          int depth) {
    if (depth <= 0 || !dest) return 0;

    const Region* rg = t.RegionAt(dest);
    if (!rg) return 0;
    uint64_t avail = (rg->base + rg->size) - dest;
    size_t want = (size_t)(std::min)(avail, (uint64_t)64);
    uint8_t code[64] = {};
    if (want < 5 || !t.Read(dest, code, want)) return 0;

    uint64_t next = DecodeDetour(code, want, dest, t);
    if (next && next != dest) {
        const Module* nm = t.ModuleAt(next);
        if (nm && nm != &hooked) return next;
        if (!nm) return FollowTrampoline(t, next, hooked, depth - 1);
        return 0;
    }

    if (rg->size > (64u << 10)) return 0;
    std::vector<uint8_t> page;
    if (!t.ReadRegion(*rg, page, (size_t)rg->size) || page.size() < 8) return 0;
    for (size_t i = 0; i + 8 <= page.size(); ++i) {
        uint64_t v = 0;
        memcpy(&v, page.data() + i, 8);
        if (v < 0x10000ull || v > 0x7FFFFFFFFFFFull) continue;
        const Module* m = t.ModuleAt(v);
        if (!m || m == &hooked) continue;
        const Section* sec = m->SectionOf(v);
        if (sec && !sec->Executable()) continue;
        return v;
    }
    return 0;
}

enum class DestVerdict { Benign, Suspicious, Malicious };

DestVerdict JudgeDestination(const Target& t, const Module& from, uint64_t dest,
                             std::string* why) {
    (void)why;
    if (dest == 0) return DestVerdict::Suspicious;

    const Module* dm = t.ModuleAt(dest);
    if (!dm) {
        if (t.IsCodeCache(dest)) return DestVerdict::Malicious;
        uint64_t landed = FollowTrampoline(t, dest, from, 4);
        const Module* lm = landed ? t.ModuleAt(landed) : nullptr;
        if (lm) NoteRegionOwner(dest, lm->trust);
        if (lm && (lm->trust == Trust::TrustedVendor || lm->trust == Trust::PathTrusted))
            return DestVerdict::Benign;
        if (lm && lm->trust == Trust::Signed) return DestVerdict::Suspicious;
        return DestVerdict::Malicious;
    }
    if (!dm->inLoaderList) return DestVerdict::Malicious;
    if (dm->trust == Trust::Unknown) return DestVerdict::Malicious;
    if (dm == &from) return DestVerdict::Benign;
    if (dm->trust == Trust::TrustedVendor || dm->trust == Trust::PathTrusted)
        return DestVerdict::Benign;
    return DestVerdict::Suspicious;
}

void ReportHook(Target& t, Report& r, const Module& m, const char* kind,
                const std::string& symbol, uint64_t site, uint64_t dest,
                const std::string& shape, DestVerdict v, const std::string& why,
                const uint8_t* liveBytes, const uint8_t* diskBytes, size_t nb) {
    if (v == DestVerdict::Malicious) {
        SuspectRegion* sus = SuspectAt(dest);
        if (sus) ++sus->corroborations;
    }

    Finding f;
    f.severity = (v == DestVerdict::Malicious) ? Severity::Critical : Severity::Medium;
    f.id       = (v == DestVerdict::Malicious) ? xorstr_("CODE_HOOK") : xorstr_("CODE_HOOK_UNKNOWN_OWNER");
    r.Add(f);
}

void CheckOneModule(Target& t, Report& r, const Module& m, ScanStats* st) {
    int* reportedOut = &st->reported;
    const bool isCore = IsRuntimeCore(m.name);

    if (m.path.empty() || m.size == 0 || m.size > (64ull << 20)) {
        return;
    }

    DiskImage img;
    if (!LoadDiskImage(m.path, m.base, &img) || img.sizeOfImage == 0) {
        return;
    }

    std::vector<uint8_t> live;
    for (size_t si = 0; si < img.sections.size(); ++si) {
        const Section& s = img.sections[si];
        if (!s.Executable()) continue;
        if (s.Writable()) continue;
        if (s.size == 0 || s.rva + s.size > img.mapped.size()) continue;

        live.assign((size_t)s.size, 0);
        bool any = false;
        for (size_t off = 0; off < live.size(); off += 0x1000) {
            size_t chunk = (std::min)((size_t)0x1000, live.size() - off);
            SIZE_T got = 0;
            if (ReadProcessMemory(t.handle(), (LPCVOID)(m.base + s.rva + off),
                                  live.data() + off, chunk, &got) && got == chunk)
                any = true;
            else
                memcpy(live.data() + off, img.mapped.data() + s.rva + off, chunk);
        }
        if (!any) continue;

        const uint8_t* disk = img.mapped.data() + s.rva;
        size_t n = live.size();
        size_t modified = 0;
        int reportedHere = 0;

        const bool core = isCore;
        int quiet = 0;

        for (size_t i = 0; i < n; ) {
            if (live[i] == disk[i]) { ++i; continue; }
            size_t runStart = i;
            while (i < n && live[i] != disk[i]) { ++i; ++modified; }

            uint64_t siteVa = m.base + s.rva + runStart;
            size_t avail = (std::min)((size_t)16, n - runStart);

            if (IsLoaderImportOptimization(&live[runStart], disk + runStart, avail)) {
                continue;
            }

            uint64_t dest = DecodeDetour(&live[runStart], avail, siteVa, t);

            if (!dest) {
                if (core && quiet < 16) ++quiet;
                continue;
            }

            if (reportedHere >= 8 || *reportedOut >= 64) continue;

            DestVerdict v = JudgeDestination(t, m, dest, nullptr);
            if (v == DestVerdict::Benign) continue;

            ReportHook(t, r, m, nullptr, std::string(), siteVa, dest, std::string(), v, std::string(),
                       &live[runStart], disk + runStart, avail);
            ++reportedHere;
            ++(*reportedOut);
        }

        if (quiet > 0 && modified <= 4096) {
            Finding f;
            f.severity = Severity::Critical;
            f.id       = xorstr_("JVM_CODE_PATCHED");
            r.Add(f);
            ++(*reportedOut);
        }

    }

    std::vector<ImportThunk> imports;
    if (ReadImports(img, &imports)) {
        int reportedHere = 0;
        for (size_t i = 0; i < imports.size() && reportedHere < 8; ++i) {
            const ImportThunk& it = imports[i];
            uint64_t slot = m.base + it.iatRva;
            uint64_t dest = 0;
            if (!t.Read(slot, &dest, img.is64 ? 8u : 4u)) continue;
            if (dest == 0) continue;

            DestVerdict v = JudgeDestination(t, m, dest, nullptr);
            if (v != DestVerdict::Malicious) continue;

            SuspectRegion* sus = SuspectAt(dest);
            if (sus) ++sus->corroborations;

            Finding f;
            f.severity = Severity::Critical;
            f.id       = xorstr_("IAT_HOOK");
            r.Add(f);
            ++reportedHere;
            ++(*reportedOut);
        }
    }

    std::vector<ExportEntry> exports;
    if (ReadExports(img, &exports)) {
        int reportedHere = 0;
        for (size_t i = 0; i < exports.size() && reportedHere < 4; ++i) {
            if (exports[i].forwarder || exports[i].name.empty()) continue;
            uint64_t expected = m.base + exports[i].rva;
            (void)expected;
        }
        const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(img.mapped.data());
        if (img.mapped.size() > sizeof(IMAGE_DOS_HEADER) && dos->e_magic == IMAGE_DOS_SIGNATURE) {
            size_t ntOff = (size_t)dos->e_lfanew;
            const IMAGE_DATA_DIRECTORY* dirs = nullptr;
            if (img.is64 && ntOff + sizeof(IMAGE_NT_HEADERS64) <= img.mapped.size())
                dirs = reinterpret_cast<const IMAGE_NT_HEADERS64*>(img.mapped.data() + ntOff)
                           ->OptionalHeader.DataDirectory;
            else if (!img.is64 && ntOff + sizeof(IMAGE_NT_HEADERS32) <= img.mapped.size())
                dirs = reinterpret_cast<const IMAGE_NT_HEADERS32*>(img.mapped.data() + ntOff)
                           ->OptionalHeader.DataDirectory;
            if (dirs && dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
                uint32_t edRva = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                if (edRva + sizeof(IMAGE_EXPORT_DIRECTORY) <= img.mapped.size()) {
                    const IMAGE_EXPORT_DIRECTORY* ed =
                        reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(img.mapped.data() + edRva);
                    uint32_t cnt = ed->NumberOfFunctions;
                    if (cnt && cnt < 65536 &&
                        (size_t)ed->AddressOfFunctions + 4ull * cnt <= img.mapped.size()) {
                        std::vector<uint32_t> liveRvas(cnt);
                        if (t.Read(m.base + ed->AddressOfFunctions, liveRvas.data(), 4ull * cnt)) {
                            const uint32_t* diskRvas = reinterpret_cast<const uint32_t*>(
                                img.mapped.data() + ed->AddressOfFunctions);
                            for (uint32_t k = 0; k < cnt && reportedHere < 4; ++k) {
                                if (liveRvas[k] == diskRvas[k]) continue;
                                uint64_t dest = m.base + liveRvas[k];
                                DestVerdict v = JudgeDestination(t, m, dest, nullptr);
                                if (v == DestVerdict::Benign) continue;
                                ++reportedHere;
                                ++(*reportedOut);
                            }
                        }
                    }
                }
            }
        }
    }
}

}

void CheckHooks(Target& t, Report& r) {
    ScanStats st;

    for (size_t i = 0; i < t.modules().size(); ++i) {
        const Module& m = t.modules()[i];
        if (!m.inLoaderList || !IsPriority(m.name)) continue;
        CheckOneModule(t, r, m, &st);
    }
    for (size_t i = 0; i < t.modules().size(); ++i) {
        const Module& m = t.modules()[i];
        if (!m.inLoaderList || IsPriority(m.name)) continue;
        CheckOneModule(t, r, m, &st);
    }

}

}
