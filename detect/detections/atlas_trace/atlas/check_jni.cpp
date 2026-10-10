#include "checks.h"
#include "pe.h"
#include "trust.h"
#include "jni_names.h"

namespace atlas {
namespace {

const int kJniStablePrefix = 233;

struct DataRange {
    std::string name;
    uint64_t    va = 0;
    bool        writable = false;
    std::vector<uint8_t> bytes;
};

bool CollectDataSections(const Target& t, const Module& m, std::vector<DataRange>* out) {
    for (size_t i = 0; i < m.sections.size(); ++i) {
        const Section& s = m.sections[i];
        if (s.Executable()) continue;
        if (s.name == xorstr_(".reloc") || s.name == xorstr_(".rsrc") || s.name == xorstr_(".pdata")) continue;
        if (s.size == 0 || s.size > (64ull << 20)) continue;

        DataRange d;
        d.writable = s.Writable();
        d.name = s.name;
        d.va   = m.base + s.rva;
        d.bytes.assign((size_t)s.size, 0);
        SIZE_T got = 0;
        if (!ReadProcessMemory(t.handle(), (LPCVOID)d.va, d.bytes.data(), d.bytes.size(), &got)) {
            bool any = false;
            for (size_t off = 0; off < d.bytes.size(); off += 0x1000) {
                size_t chunk = (std::min)((size_t)0x1000, d.bytes.size() - off);
                SIZE_T g = 0;
                if (ReadProcessMemory(t.handle(), (LPCVOID)(d.va + off),
                                      d.bytes.data() + off, chunk, &g))
                    any = true;
            }
            if (!any) continue;
        } else {
            d.bytes.resize(got);
        }
        out->push_back(d);
    }
    return !out->empty();
}

struct CodeRange { uint64_t lo, hi; };

std::vector<CodeRange> ExecRanges(const Module& m) {
    std::vector<CodeRange> v;
    for (size_t i = 0; i < m.sections.size(); ++i) {
        if (!m.sections[i].Executable()) continue;
        CodeRange c;
        c.lo = m.base + m.sections[i].rva;
        c.hi = c.lo + m.sections[i].size;
        v.push_back(c);
    }
    if (v.empty()) {
        CodeRange c;
        c.lo = m.base;
        c.hi = m.base + m.size;
        v.push_back(c);
    }
    return v;
}

bool InRanges(const std::vector<CodeRange>& v, uint64_t a) {
    for (size_t i = 0; i < v.size(); ++i)
        if (a >= v[i].lo && a < v[i].hi) return true;
    return false;
}

void Widen(const std::vector<uint8_t>& bytes, size_t ptrSize, std::vector<uint64_t>* out) {
    size_t n = bytes.size() / ptrSize;
    out->assign(n, 0);
    if (ptrSize == 8) {
        memcpy(out->data(), bytes.data(), n * 8);
    } else {
        const uint32_t* p = reinterpret_cast<const uint32_t*>(bytes.data());
        for (size_t i = 0; i < n; ++i) (*out)[i] = p[i];
    }
}

bool IsFastFieldAccessor(int index) {
    return index >= 96 && index <= 103;
}

bool DestinationIsExecutable(const Target& t, uint64_t dest) {
    const Module* m = t.ModuleAt(dest);
    if (m) {
        const Section* s = m->SectionOf(dest);
        return s ? s->Executable() : true;
    }
    const Region* rg = t.RegionAt(dest);
    return rg && rg->state == MEM_COMMIT && rg->Executable();
}

void ReportForeignEntry(Target& t, Report& r, const char* tableName,
                        const char* entryName, int index,
                        uint64_t tableVa, uint64_t dest) {
    const Module* dm = t.ModuleAt(dest);
    SuspectRegion* sus = SuspectAt(dest);

    if (IsFastFieldAccessor(index) && !dm) {
        if (t.IsCodeCache(dest)) return;
        if (!sus || (sus->corroborations == 0 && !sus->isPeImage)) {
            return;
        }
    }

    if (sus) ++sus->corroborations;

    Finding f;
    f.id = xorstr_("JNI_TABLE_HOOK");
    if (!dm || !dm->inLoaderList || dm->trust == Trust::Unknown) {
        f.severity = Severity::Critical;
    } else {
        f.severity = Severity::High;
    }
    r.Add(f);
}

struct Span { uint64_t lo, hi; };
std::vector<Span> g_knownTables;

bool InsideKnownTable(uint64_t va) {
    for (size_t i = 0; i < g_knownTables.size(); ++i)
        if (va >= g_knownTables[i].lo && va < g_knownTables[i].hi) return true;
    return false;
}

int ScanJniTables(Target& t, Report& r, const Module& jvm,
                  const std::vector<DataRange>& data,
                  const std::vector<CodeRange>& code) {
    const size_t ps = t.ptrSize();

    struct Candidate {
        uint64_t va = 0;
        size_t   di = 0;
        size_t   o  = 0;
        int      inCode = 0;
        int      nonNull = 0;
    };
    std::vector<Candidate> cands;
    std::vector<std::vector<uint64_t> > widened(data.size());

    auto pointsToCode = [&](uint64_t a) -> bool {
        if (!a) return false;
        if (InRanges(code, a)) return true;
        const Region* rg = t.RegionAt(a);
        return rg && rg->state == MEM_COMMIT && rg->Executable();
    };

    for (size_t di = 0; di < data.size(); ++di) {
        const DataRange& d = data[di];
        if (d.bytes.size() < (size_t)(kJniStablePrefix + 4) * ps) continue;

        if (!d.writable) continue;

        Widen(d.bytes, ps, &widened[di]);
        const uint64_t* q = widened[di].data();
        size_t count = widened[di].size();

        for (size_t o = 0; o + kJniStablePrefix <= count; ++o) {
            if (q[o] || q[o + 1] || q[o + 2]) continue;
            if (o + 4 >= count) break;
            if (!InRanges(code, q[o + 4])) continue;

            int inCode = 0, nonNull = 0, dead = 0;
            for (int i = 4; i < kJniStablePrefix; ++i) {
                uint64_t pv = q[o + i];
                if (!pv) continue;
                ++nonNull;
                if (InRanges(code, pv)) ++inCode;
                else if (!pointsToCode(pv)) ++dead;
            }
            if (nonNull < 200 || inCode < 180 || dead > 2) continue;

            Candidate c;
            c.va = d.va + (uint64_t)o * ps;
            c.di = di;
            c.o  = o;
            c.inCode = inCode;
            c.nonNull = nonNull;
            cands.push_back(c);
            o += kJniStablePrefix - 1;
        }
    }

    if (cands.empty()) return 0;

    for (size_t i = 0; i < cands.size(); ++i) {
        Span sp;
        sp.lo = cands[i].va;
        sp.hi = cands[i].va + (uint64_t)kJniStablePrefix * ps;
        g_knownTables.push_back(sp);
    }

    for (size_t ci = 0; ci < cands.size(); ++ci) {
    const Candidate& c = cands[ci];
    const DataRange& d = data[c.di];
    const uint64_t* q = widened[c.di].data();
    uint64_t tableVa = c.va;

    int bad = 0;
    for (int i = 4; i < kJniStablePrefix; ++i) {
        uint64_t pv = q[c.o + i];
        const char* name = JniEntryName(i);
        if (pv == 0) {
            ++bad;
            continue;
        }
        if (InRanges(code, pv)) continue;
        ReportForeignEntry(t, r, xorstr_("JNI function table"), name, i, tableVa, pv);
        ++bad;
    }

    }
    return (int)cands.size();
}

void ScanGenericTables(Target& t, Report& r, const Module& jvm,
                       const std::vector<DataRange>& data,
                       const std::vector<CodeRange>& code,
                       int jniTablesFound) {
    const size_t kMinRun = 48;
    const size_t ps = t.ptrSize();
    int reported = 0;

    for (size_t di = 0; di < data.size(); ++di) {
        const DataRange& d = data[di];
        if (d.bytes.size() < kMinRun * ps) continue;
        std::vector<uint64_t> ptrs;
        Widen(d.bytes, ps, &ptrs);
        const uint64_t* q = ptrs.data();
        size_t count = ptrs.size();

        size_t i = 0;
        while (i < count) {
            if (!InRanges(code, q[i])) { ++i; continue; }
            size_t start = i;
            size_t inCode = 0, foreign = 0;
            std::vector<size_t> foreignIdx;
            while (i < count) {
                uint64_t p = q[i];
                if (InRanges(code, p)) { ++inCode; ++i; continue; }
                if (p == 0) break;
                if (p < 0x10000) break;
                if (!DestinationIsExecutable(t, p)) break;
                if (foreign >= 8) break;
                foreignIdx.push_back(i);
                ++foreign;
                ++i;
            }
            size_t runLen = i - start;
            if (runLen < kMinRun || inCode * 10 < runLen * 9) continue;
            if (foreign == 0) continue;

            for (size_t k = 0; k < foreignIdx.size(); ++k) {
                size_t idx = foreignIdx[k];
                uint64_t dest = q[idx];
                const Module* dm = t.ModuleAt(dest);
                if (dm && (dm->trust == Trust::TrustedVendor || dm->trust == Trust::PathTrusted))
                    continue;
                if (t.IsCodeCache(dest)) continue;
                if (InsideKnownTable(d.va + (uint64_t)idx * ps)) continue;
                if (reported >= 24) break;

                SuspectRegion* sus = SuspectAt(dest);
                if (sus) ++sus->corroborations;

                uint64_t entryVa = d.va + (uint64_t)idx * ps;
                Finding f;
                f.severity = dm ? Severity::High : Severity::Critical;
                f.id       = xorstr_("JVM_TABLE_HOOK");
                r.Add(f);
                ++reported;
            }
        }
    }
}

}

void CheckJniTables(Target& t, Report& r) {
    const Module* jvm = t.ModuleByName(xorstr_(L"jvm.dll"));
    if (!jvm) {
        return;
    }

    std::vector<DataRange> data;
    if (!CollectDataSections(t, *jvm, &data)) {
        return;
    }
    std::vector<CodeRange> code = ExecRanges(*jvm);

    g_knownTables.clear();
    int found = ScanJniTables(t, r, *jvm, data, code);
    ScanGenericTables(t, r, *jvm, data, code, found);
}

}
