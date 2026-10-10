#include "checks.h"
#include "pe.h"
#include "trust.h"

namespace atlas {
namespace {

std::vector<SuspectRegion> g_suspects;

struct JvmPointerDensity {
    size_t sampled = 0;
    size_t hits    = 0;
    double ratio() const { return sampled ? (double)hits / (double)sampled : 0.0; }
};

JvmPointerDensity MeasureJvmPointerDensity(const Target& t, const Reservation& res,
                                           uint64_t jvmBase, uint64_t jvmEnd) {
    JvmPointerDensity d;
    if (!jvmBase) return d;
    const size_t kBudget = 2u << 20;
    size_t budget = kBudget;
    std::vector<uint8_t> buf;
    for (size_t i = 0; i < res.parts.size() && budget > 0; ++i) {
        const Region& r = *res.parts[i];
        if (r.state != MEM_COMMIT || !r.Readable()) continue;
        size_t want = (size_t)(std::min)((uint64_t)budget, r.size);
        if (!t.ReadRegion(r, buf, want)) continue;
        size_t n = buf.size() / 8;
        const uint64_t* q = reinterpret_cast<const uint64_t*>(buf.data());
        for (size_t k = 0; k < n; ++k) {
            ++d.sampled;
            if (q[k] >= jvmBase && q[k] < jvmEnd) ++d.hits;
        }
        budget -= (std::min)(budget, buf.size());
    }
    return d;
}

bool LooksLikeJitCodeCache(const Target& t, const Reservation& res,
                           uint64_t jvmBase, uint64_t jvmEnd, std::string* why) {
    (void)why;
    if (res.type != MEM_PRIVATE) return false;
    if (res.committedExec == 0) return false;
    if (res.totalSize < (4ull << 20)) return false;

    JvmPointerDensity d = MeasureJvmPointerDensity(t, res, jvmBase, jvmEnd);
    if (d.hits < 32) return false;
    if (d.ratio() < 0.002) return false;

    return true;
}

struct PeContentProbe {
    int dllNames = 0;
    int apiNames = 0;
    std::vector<std::string> found;
    bool Convincing() const { return dllNames >= 2 && apiNames >= 3; }
};

PeContentProbe ProbePeContent(const std::vector<uint8_t>& buf) {
    static const std::string kDlls[] = {
        xorstr_("kernel32.dll"), xorstr_("KERNEL32.dll"), xorstr_("KERNEL32.DLL"), xorstr_("ntdll.dll"), xorstr_("NTDLL.DLL"),
        xorstr_("user32.dll"), xorstr_("USER32.dll"), xorstr_("advapi32.dll"), xorstr_("ADVAPI32.dll"), xorstr_("ws2_32.dll"),
        xorstr_("WS2_32.dll"), xorstr_("gdi32.dll"), xorstr_("GDI32.dll"), xorstr_("shell32.dll"), xorstr_("SHELL32.dll"),
        xorstr_("ole32.dll"), xorstr_("OLE32.dll"), xorstr_("msvcrt.dll"), xorstr_("MSVCRT.dll"), xorstr_("opengl32.dll"),
        xorstr_("OPENGL32.dll"), xorstr_("crypt32.dll"), xorstr_("wininet.dll"), xorstr_("VCRUNTIME140.dll"),
        xorstr_("api-ms-win-crt-runtime-l1-1-0.dll"),
    };
    static const std::string kApis[] = {
        xorstr_("LoadLibraryA"), xorstr_("LoadLibraryW"), xorstr_("GetProcAddress"), xorstr_("VirtualAlloc"),
        xorstr_("VirtualProtect"), xorstr_("VirtualFree"), xorstr_("GetModuleHandleA"), xorstr_("GetModuleHandleW"),
        xorstr_("CreateThread"), xorstr_("CloseHandle"), xorstr_("GetLastError"), xorstr_("MultiByteToWideChar"),
        xorstr_("HeapAlloc"), xorstr_("RtlAddFunctionTable"), xorstr_("TerminateProcess"), xorstr_("QueryPerformanceCounter"),
    };
    PeContentProbe p;
    if (buf.empty()) return p;
    auto search = [&](const char* needle) -> bool {
        size_t len = strlen(needle);
        if (len + 1 > buf.size()) return false;
        const uint8_t* first = buf.data();
        const uint8_t* last = buf.data() + buf.size();
        const uint8_t* q = first;
        while (q + len <= last) {
            const uint8_t* hit = (const uint8_t*)memchr(q, needle[0], (size_t)(last - q) - len + 1);
            if (!hit) return false;
            if (memcmp(hit, needle, len) == 0) {
                size_t at = (size_t)(hit - first);
                if (at + len < buf.size() && buf[at + len] == 0) return true;
            }
            q = hit + 1;
        }
        return false;
    };
    for (size_t i = 0; i < sizeof(kDlls) / sizeof(kDlls[0]); ++i)
        if (search(kDlls[i].c_str())) { ++p.dllNames; if (p.found.size() < 6) p.found.push_back(kDlls[i]); }
    for (size_t i = 0; i < sizeof(kApis) / sizeof(kApis[0]); ++i)
        if (search(kApis[i].c_str())) { ++p.apiNames; if (p.found.size() < 10) p.found.push_back(kApis[i]); }
    return p;
}

struct OrphanProfile {
    uint64_t bytesRead    = 0;
    uint64_t zeroBytes    = 0;
    size_t   qwords       = 0;
    size_t   modulePtrs   = 0;
    size_t   branchesOut  = 0;
    size_t   branchesIn   = 0;
    size_t   selfPtrs     = 0;
    size_t   jvmPtrs      = 0;
    size_t   codeIdioms   = 0;

    double zeroFraction() const {
        return bytesRead ? (double)zeroBytes / (double)bytesRead : 1.0;
    }
    double codeDensity() const {
        return bytesRead ? (double)codeIdioms * 1024.0 / (double)bytesRead : 0.0;
    }
    bool WiredToCode() const {
        return modulePtrs > 0 || branchesOut > 0 || branchesIn > 0 || selfPtrs > 0;
    }
    bool LooksLikeCode() const { return codeDensity() >= 24.0; }
};

bool IsCodeIdiom(const uint8_t* q, size_t avail) {
    if (avail < 2) return false;
    if (q[0] == 0x48 || q[0] == 0x4C || q[0] == 0x49 || q[0] == 0x4D) {
        switch (q[1]) {
            case 0x89: case 0x8B: case 0x8D: case 0x83: case 0x85:
            case 0x01: case 0x03: case 0x29: case 0x2B: case 0x31:
            case 0x33: case 0x39: case 0x3B: case 0x63: case 0x87:
                return true;
            default: break;
        }
        return false;
    }
    if (q[0] == 0xFF && (q[1] == 0x15 || q[1] == 0x25 || q[1] == 0xD0 || q[1] == 0xE0))
        return true;
    if (q[0] == 0x0F && (q[1] == 0x1F || q[1] == 0x05 || q[1] == 0xB6 || q[1] == 0xB7))
        return true;
    if (q[0] == 0x66 && q[1] == 0x0F) return true;
    return false;
}

OrphanProfile ProfileOrphan(const Target& t, const Reservation& res, size_t* shared) {
    OrphanProfile p;
    std::vector<uint8_t> buf;
    size_t budget = (size_t)(std::min)((uint64_t)(4u << 20), (uint64_t)*shared);
    for (size_t i = 0; i < res.parts.size() && budget; ++i) {
        const Region& q = *res.parts[i];
        if (q.state != MEM_COMMIT || !q.Readable()) continue;
        size_t want = (size_t)(std::min)((uint64_t)budget, q.size);
        if (!t.ReadRegion(q, buf, want) || buf.empty()) continue;
        budget -= (std::min)(budget, buf.size());
        *shared -= (std::min)(*shared, buf.size());
        p.bytesRead += buf.size();
        for (size_t k = 0; k < buf.size(); ++k) {
            if (buf[k] == 0) ++p.zeroBytes;
            if (IsCodeIdiom(buf.data() + k, buf.size() - k)) ++p.codeIdioms;
        }

        uint64_t lo = res.base, hi = res.base + res.totalSize;
        size_t n = buf.size() / 8;
        for (size_t k = 0; k < n; ++k) {
            uint64_t v = 0;
            memcpy(&v, buf.data() + k * 8, 8);
            ++p.qwords;
            if (v >= lo && v < hi) { ++p.selfPtrs; continue; }
            if (v < 0x10000ull || v > 0x7FFFFFFFFFFFull) continue;
            const Module* m = t.ModuleAt(v);
            if (!m) continue;
            ++p.modulePtrs;
            if (_wcsicmp(m->name.c_str(), xorstr_(L"jvm.dll")) == 0) ++p.jvmPtrs;
        }
        if (hi <= 0x100000000ull) {
            for (size_t k = 0; k + 4 <= buf.size(); k += 4) {
                uint32_t v = 0;
                memcpy(&v, buf.data() + k, 4);
                if (v >= lo && v < hi) ++p.selfPtrs;
            }
        }

        if (p.WiredToCode()) break;

        if (buf.size() >= 5) {
            for (size_t k = 0; k + 5 <= buf.size(); ++k) {
                if (buf[k] != 0xE9 && buf[k] != 0xE8) continue;
                int32_t rel = 0;
                memcpy(&rel, buf.data() + k + 1, 4);
                uint64_t site = q.base + k;
                uint64_t dest = site + 5 + (int64_t)rel;
                if (dest >= res.base && dest < res.base + res.totalSize) {
                    ++p.branchesIn;
                    continue;
                }
                const Module* m = t.ModuleAt(dest);
                if (!m) continue;
                const Section* sec = m->SectionOf(dest);
                if (sec && !sec->Executable()) continue;
                ++p.branchesOut;
            }
        }
    }
    return p;
}

bool IsKnownBenignPrivateExec(const Target& t, const Reservation& res) {
    if (res.committedExec <= 0x2000) {
        const Module* before = t.ModuleAt(res.base - 1);
        if (before) return true;
    }
    return false;
}

}

std::vector<SuspectRegion>& Suspects() { return g_suspects; }

SuspectRegion* SuspectAt(uint64_t addr) {
    for (size_t i = 0; i < g_suspects.size(); ++i) {
        SuspectRegion& s = g_suspects[i];
        if (addr >= s.base && addr < s.base + s.size) return &s;
    }
    return nullptr;
}

void ResetSuspects() { g_suspects.clear(); }

bool TrustIsVouched(Trust t) {
    return t == Trust::Signed || t == Trust::PathTrusted || t == Trust::TrustedVendor;
}

void NoteRegionOwner(uint64_t addr, Trust trust) {
    if (!TrustIsVouched(trust)) return;
    SuspectRegion* s = SuspectAt(addr);
    if (!s) return;
    if (static_cast<int>(trust) > static_cast<int>(s->ownerTrust)) s->ownerTrust = trust;
}

void CheckMemory(Target& t, Report& r) {
    const Module* jvm = t.ModuleByName(xorstr_(L"jvm.dll"));
    uint64_t jvmBase = jvm ? jvm->base : 0;
    uint64_t jvmEnd  = jvm ? jvm->base + jvm->size : 0;

    int codeCaches = 0;
    uint64_t privateExecBytes = 0;
    size_t orphanBudget = 64u << 20;
    int orphanSkipped = 0;

    for (size_t ri = 0; ri < t.reservations().size(); ++ri) {
        const Reservation& res = t.reservations()[ri];

        if (res.committedExec == 0) continue;
        if (res.type == MEM_IMAGE) continue;

        if (LooksLikeJitCodeCache(t, res, jvmBase, jvmEnd, nullptr)) {
            t.MarkCodeCache(res.base);
            ++codeCaches;
            continue;
        }
        if (IsKnownBenignPrivateExec(t, res)) continue;

        privateExecBytes += res.committedExec;

        std::vector<uint8_t> head;
        bool readOk = false;
        for (size_t i = 0; i < res.parts.size(); ++i) {
            if (res.parts[i]->base == res.base && res.parts[i]->Readable()) {
                readOk = t.ReadRegion(*res.parts[i], head, 0x1000);
                break;
            }
        }
        PeProbe probe;
        if (readOk && head.size() >= 0x400)
            probe = ProbeForPeImage(head.data(), head.size());

        SuspectRegion s;
        s.base = res.base;
        s.size = res.totalSize;
        s.executable = true;
        s.isPeImage = probe.isPe;

        if (probe.isPe) {
            Finding f;
            f.severity = Severity::Critical;
            f.id       = xorstr_("MANUAL_MAP");
            r.Add(f);

            s.corroborations += 2;
            g_suspects.push_back(s);
            continue;
        }

        bool anonMapped = false;
        for (size_t i = 0; i < res.parts.size(); ++i) {
            const Region& q = *res.parts[i];
            if (q.type == MEM_MAPPED && q.Executable() && q.mappedFile.empty())
                anonMapped = true;
        }
        if (anonMapped) {
            s.corroborations += 1;
            g_suspects.push_back(s);
            continue;
        }

        bool rwx = false, roExec = false;
        uint64_t roExecBytes = 0;
        for (size_t i = 0; i < res.parts.size(); ++i) {
            const Region& q = *res.parts[i];
            if (!q.Executable() || q.state != MEM_COMMIT) continue;
            if (q.Writable()) rwx = true;
            else { roExec = true; roExecBytes += q.size; }
        }

        if (roExec && roExecBytes >= 0x2000) {
            std::vector<uint8_t> body;
            PeContentProbe probe2;
            for (size_t i = 0; i < res.parts.size(); ++i) {
                const Region& q = *res.parts[i];
                if (!q.Executable() || q.state != MEM_COMMIT || q.Writable()) continue;
                if (t.ReadRegion(q, body, 8u << 20)) {
                    PeContentProbe pc = ProbePeContent(body);
                    if (pc.dllNames + pc.apiNames > probe2.dllNames + probe2.apiNames) probe2 = pc;
                }
            }

            Finding f;
            f.severity = probe2.Convincing() ? Severity::Critical : Severity::High;
            f.id       = probe2.Convincing() ? xorstr_("MANUAL_MAP_STRIPPED") : xorstr_("UNBACKED_RX");
            r.Add(f);

            s.corroborations += probe2.Convincing() ? 2 : 1;
            g_suspects.push_back(s);
            continue;
        }

        if (res.type == MEM_PRIVATE && res.committedExec >= 0x1000 &&
            res.totalSize < (64ull << 20)) {
            OrphanProfile op = ProfileOrphan(t, res, &orphanBudget);
            bool blank    = op.zeroFraction() >= 0.50;
            bool complete = op.bytesRead >= res.committedTotal;
            if (!complete && !op.WiredToCode()) ++orphanSkipped;
            if (complete && !blank && !op.WiredToCode() && !op.LooksLikeCode() &&
                op.bytesRead >= 0x1000) {
                uint8_t head[32] = {};
                size_t hn = 0;
                for (size_t i = 0; i < res.parts.size() && !hn; ++i) {
                    const Region& q = *res.parts[i];
                    if (q.state != MEM_COMMIT || !q.Readable()) continue;
                    if (t.Read(q.base, head, sizeof(head))) hn = sizeof(head);
                }

                Finding f;
                f.severity   = Severity::Critical;
                f.id         = xorstr_("ORPHAN_EXEC_ALLOC");
                r.Add(f);

                s.corroborations += 1;
                g_suspects.push_back(s);
                continue;
            }
        }

        (void)rwx;
        g_suspects.push_back(s);

    }

    for (size_t i = 0; i < t.regions().size(); ++i) {
        const Region& q = t.regions()[i];
        if (q.type != MEM_IMAGE || q.state != MEM_COMMIT) continue;
        if (!(q.Executable() && q.Writable())) continue;
        const Module* m = t.ModuleAt(q.base);
        const Section* sec = m ? m->SectionOf(q.base) : nullptr;
        if (sec && sec->Writable()) continue;

    }


}

}
