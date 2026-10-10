#include "checks.h"
#include "java_state.h"
#include "trust.h"

namespace atlas {
namespace {

bool InKnownNamespace(const std::string& n) {
    static const std::string kKnownNamespaces[] = {
        xorstr_("java/"), xorstr_("javax/"), xorstr_("jdk/"), xorstr_("sun/"), xorstr_("com/sun/"), xorstr_("org/w3c/"), xorstr_("org/xml/"),
        xorstr_("org/ietf/"), xorstr_("org/jcp/"), xorstr_("net/minecraft/"), xorstr_("com/mojang/"), xorstr_("optifine/"),
        xorstr_("net/optifine/"), xorstr_("com/moonsworth/"), xorstr_("com/lunarclient/"), xorstr_("net/badlion/"),
        xorstr_("com/badlion/"), xorstr_("org/lwjgl/"), xorstr_("org/lwjglx/"), xorstr_("org/apache/"), xorstr_("org/slf4j/"),
        xorstr_("io/netty/"), xorstr_("com/google/"), xorstr_("it/unimi/"), xorstr_("org/objectweb/"), xorstr_("org/ow2/"),
        xorstr_("net/minecraftforge/"), xorstr_("cpw/mods/"), xorstr_("org/spongepowered/"), xorstr_("com/jcraft/"),
        xorstr_("paulscode/"), xorstr_("com/ibm/icu/"), xorstr_("org/joml/"), xorstr_("kotlin/"), xorstr_("scala/"),
        xorstr_("com/electronwill/"), xorstr_("org/json"), xorstr_("com/github/"), xorstr_("net/java/games/"),
        xorstr_("org/newdawn/"), xorstr_("org/cadixdev/"), xorstr_("me/jellysquid/"), xorstr_("net/fabricmc/"),
        xorstr_("org/quiltmc/"), xorstr_("com/logisticscraft/"), xorstr_("org/checkerframework/"),
        xorstr_("javassist/"), xorstr_("com/fasterxml/"), xorstr_("org/yaml/"), xorstr_("io/github/"),
    };
    for (size_t i = 0; i < sizeof(kKnownNamespaces) / sizeof(kKnownNamespaces[0]); ++i) {
        const std::string& p = kKnownNamespaces[i];
        if (n.size() >= p.size() && n.compare(0, p.size(), p) == 0) return true;
    }
    return false;
}

bool IsRuntimeGenerated(const std::string& n) {
    static const std::string kMarkers[] = {
        xorstr_("$$Lambda"), xorstr_("$Lambda$"), xorstr_("com/sun/proxy/"), xorstr_("jdk/proxy"), xorstr_("$Proxy"),
        xorstr_("GeneratedMethodAccessor"), xorstr_("GeneratedConstructorAccessor"),
        xorstr_("GeneratedSerializationConstructorAccessor"), xorstr_("$$EnhancerBy"),
        xorstr_("$$FastClassBy"), xorstr_("ByteBuddy"), xorstr_("$MockitoMock$"), xorstr_("/$$"),
    };
    for (size_t i = 0; i < sizeof(kMarkers) / sizeof(kMarkers[0]); ++i)
        if (n.find(kMarkers[i]) != std::string::npos) return true;
    return false;
}

bool IsImpostorMinecraftNamespace(const std::string& n) {
    static const std::string kRoots[] = { xorstr_("net/minecraft"), xorstr_("com/mojang"), xorstr_("optifine") };
    for (size_t i = 0; i < sizeof(kRoots) / sizeof(kRoots[0]); ++i) {
        const std::string& p = kRoots[i];
        if (n.size() <= p.size()) continue;
        if (n.compare(0, p.size(), p) != 0) continue;
        char next = n[p.size()];
        if (next == '/') return false;
        if (next == '_' || next == '-' || next == '.' ||
            (next >= '0' && next <= '9')) return true;
    }
    return false;
}

struct TableRef {
    uint64_t table = 0;
    int      entries = 0;
    int      referencedFrom = 0;
    std::vector<uint64_t> referrers;
};

std::vector<TableRef> FindDispatchTableReferences(const Target& t, const Module& jvm) {
    std::vector<TableRef> out;

    std::vector<std::pair<uint64_t, uint64_t> > code;
    for (size_t i = 0; i < jvm.sections.size(); ++i) {
        if (!jvm.sections[i].Executable()) continue;
        code.push_back(std::make_pair(jvm.base + jvm.sections[i].rva,
                                      jvm.base + jvm.sections[i].rva + jvm.sections[i].size));
    }
    if (code.empty()) return out;
    auto inCode = [&](uint64_t a) {
        for (size_t i = 0; i < code.size(); ++i)
            if (a >= code[i].first && a < code[i].second) return true;
        return false;
    };

    for (size_t si = 0; si < jvm.sections.size(); ++si) {
        const Section& s = jvm.sections[si];
        if (s.Executable() || s.size == 0 || s.size > (32u << 20)) continue;
        if (s.name == xorstr_(".reloc") || s.name == xorstr_(".pdata") || s.name == xorstr_(".rsrc")) continue;

        std::vector<uint8_t> buf((size_t)s.size, 0);
        bool any = false;
        for (size_t off = 0; off < buf.size(); off += 0x1000) {
            size_t chunk = (std::min)((size_t)0x1000, buf.size() - off);
            SIZE_T got = 0;
            if (ReadProcessMemory(t.handle(), (LPCVOID)(jvm.base + s.rva + off),
                                  buf.data() + off, chunk, &got) && got == chunk)
                any = true;
        }
        if (!any) continue;

        const uint64_t* q = reinterpret_cast<const uint64_t*>(buf.data());
        size_t n = buf.size() / 8;
        for (size_t i = 0; i < n; ) {
            size_t start = i, hits = 0, nulls = 0;
            while (i < n) {
                if (inCode(q[i])) { ++hits; ++i; continue; }
                if (q[i] == 0 && nulls < 12) { ++nulls; ++i; continue; }
                break;
            }
            size_t len = i - start;
            if (len >= 80 && hits >= 70) {
                TableRef tr;
                tr.table = jvm.base + s.rva + (uint64_t)start * 8;
                tr.entries = (int)len;
                out.push_back(tr);
            }
            if (i == start) ++i;
        }
    }
    if (out.empty()) return out;

    struct Span { uint64_t lo, hi; size_t idx; };
    std::vector<Span> spans;
    for (size_t i = 0; i < out.size(); ++i) {
        Span sp;
        sp.lo = out[i].table;
        sp.hi = out[i].table + (uint64_t)out[i].entries * 8;
        sp.idx = i;
        spans.push_back(sp);
    }

    size_t budget = 512u << 20;
    for (size_t ri = 0; ri < t.regions().size() && budget > 0; ++ri) {
        const Region& rg = t.regions()[ri];
        if (rg.state != MEM_COMMIT || !rg.Readable()) continue;
        if (rg.type == MEM_IMAGE) continue;
        if (rg.size > (64u << 20)) continue;
        std::vector<uint8_t> buf;
        size_t want = (size_t)(std::min)(rg.size, (uint64_t)(std::min)(budget, (size_t)(16u << 20)));
        if (!t.ReadRegion(rg, buf, want) || buf.size() < 8) continue;
        budget -= (std::min)(budget, buf.size());
        const uint64_t* q = reinterpret_cast<const uint64_t*>(buf.data());
        size_t n = buf.size() / 8;
        for (size_t k = 0; k < n; ++k) {
            uint64_t v = q[k];
            if (v < jvm.base || v >= jvm.base + jvm.size) continue;
            for (size_t sp = 0; sp < spans.size(); ++sp) {
                if (v < spans[sp].lo || v >= spans[sp].hi) continue;
                TableRef& tr = out[spans[sp].idx];
                ++tr.referencedFrom;
                if (tr.referrers.size() < 8) tr.referrers.push_back(rg.base + (uint64_t)k * 8);
                break;
            }
        }
    }
    return out;
}

struct CapabilityBlock {
    uint64_t rva = 0;
    uint64_t address = 0;
    int      populated = 0;
    bool     paired = false;
    uint64_t unit[6] = {};
    std::vector<std::string> units;

};

bool FindJvmtiCapabilityBlock(const Target& t, const Module& jvm, CapabilityBlock* out) {
    for (size_t si = 0; si < jvm.sections.size(); ++si) {
        const Section& s = jvm.sections[si];
        if (s.Executable() || !s.Writable()) continue;
        if (s.size < 96 || s.size > (32u << 20)) continue;

        std::vector<uint8_t> buf((size_t)s.size, 0);
        bool any = false;
        for (size_t off = 0; off < buf.size(); off += 0x1000) {
            size_t chunk = (std::min)((size_t)0x1000, buf.size() - off);
            SIZE_T got = 0;
            if (ReadProcessMemory(t.handle(), (LPCVOID)(jvm.base + s.rva + off),
                                  buf.data() + off, chunk, &got) && got == chunk)
                any = true;
        }
        if (!any) continue;

        for (size_t x = 0; x + 96 <= buf.size(); x += 16) {
            const uint8_t* u = buf.data() + x;
            bool shapeOk = true;
            int populated = 0, pointers = 0;
            uint64_t unit[6] = {};
            for (int k = 0; k < 6 && shapeOk; ++k) {
                const uint8_t* q = u + k * 16;
                for (int b = 6; b < 16; ++b)
                    if (q[b]) { shapeOk = false; break; }
                if (!shapeOk) break;
                memcpy(&unit[k], q, 6);
                if (!unit[k]) continue;
                ++populated;
                if (t.ModuleAt(unit[k])) ++pointers;
            }
            if (!shapeOk || populated < 3 || pointers > 0) continue;

            if (unit[0] == 0 || unit[2] == 0) continue;
            if ((unit[4] & ~unit[2]) || (unit[5] & ~unit[3])) continue;

            out->rva = s.rva + x;
            out->address = jvm.base + s.rva + x;
            out->populated = populated;
            out->paired = memcmp(u + 4 * 16, u + 2 * 16, 16) == 0 &&
                          memcmp(u + 5 * 16, u + 3 * 16, 16) == 0;
            memcpy(out->unit, unit, sizeof(unit));
            out->units.clear();
            for (int k = 0; k < 6; ++k)
                out->units.push_back(HexBytes(u + k * 16, 6));
            return true;
        }
    }
    return false;
}

}

void CheckJavaState(Target& t, Report& r) {
    JvmCounters c = ReadJvmCounters(t);
    if (!c.ok) {
    } else {
        long long loaded = c.Num(xorstr_("java.cls.loadedClasses"));
        long long unloaded = c.Num(xorstr_("java.cls.unloadedClasses"));
        long long threads = c.Num(xorstr_("java.threads.started"));

        const std::string* cause = c.Find(xorstr_("sun.gc.lastCause"));
        if (cause) {
            if (*cause == xorstr_("JvmtiEnv ForceGarbageCollection")) {
                Finding f;
                f.severity   = Severity::Critical;
                f.id         = xorstr_("JVMTI_AGENT_OPERATED");
                r.Add(f);
            } else if (*cause == xorstr_("System.gc()")) {
            } else {
            }
        }
    }

    if (c.ok) {
        long long fullGc = c.Num(xorstr_("sun.gc.collector.1.invocations"), 0);
        long long oldUsed = c.Num(xorstr_("sun.gc.generation.1.space.0.used"), 0);
        long long maxOld = c.Num(xorstr_("sun.gc.policy.maxOldCapacity"), 0);
        double occupancy = (maxOld > 0) ? (double)oldUsed / (double)maxOld : 1.0;

    }

    MetaspaceNames ms = ScanMetaspaceClassNames(t);
    if (ms.names.empty()) {
        return;
    }

    std::set<std::string> jarClasses;
    int jarsRead = 0, jarsMissing = 0;
    bool haveJars = ReadClasspathClassNames(t, &jarClasses, &jarsRead, &jarsMissing);

    std::vector<std::string> impostors, instrument, unaccounted;
    for (std::set<std::string>::const_iterator it = ms.names.begin();
         it != ms.names.end(); ++it) {
        const std::string& n = *it;
        if (IsImpostorMinecraftNamespace(n)) { impostors.push_back(n); continue; }
        if (n.compare(0, 21, xorstr_("java/lang/instrument/")) == 0 ||
            n.compare(0, 16, xorstr_("sun/instrument/")) == 0)
            instrument.push_back(n);
        if (!haveJars) continue;
        if (InKnownNamespace(n) || IsRuntimeGenerated(n)) continue;
        if (jarClasses.count(n)) continue;
        unaccounted.push_back(n);
    }

    if (!impostors.empty()) {
        Finding f;
        f.severity   = Severity::Critical;
        f.id         = xorstr_("IMPOSTOR_MC_NAMESPACE");
        for (size_t i = 0; i < impostors.size() && i < 20; ++i) f.Ev(impostors[i]);
        r.Add(f);
    }



    const Module* jvm = t.ModuleByName(xorstr_(L"jvm.dll"));
    if (jvm) {
        CapabilityBlock cb;
        (void)FindJvmtiCapabilityBlock(t, *jvm, &cb);
        std::vector<TableRef> tables = FindDispatchTableReferences(t, *jvm);
        int reported = 0;
        for (size_t i = 0; i < tables.size(); ++i) {
            const TableRef& tr = tables[i];
            if (tr.referencedFrom == 0) continue;
            if (tr.entries < 80 || tr.entries > 300) continue;
            if (tr.referencedFrom > 3) continue;
            if (!t.agentArgs().empty()) continue;
            if (++reported > 4) break;

        }
    }

    std::vector<NamedObject> objs = EnumNamedObjects(t);
    static const std::wstring kTells[] = {
        xorstr_(L"_MMapEvent_"), xorstr_(L"manualmap"), xorstr_(L"ManualMap"), xorstr_(L"injector"), xorstr_(L"Injector"),
        xorstr_(L"vape"), xorstr_(L"Vape"), xorstr_(L"karma"), xorstr_(L"Karma"), xorstr_(L"c0ld"), xorstr_(L"C0LD"), xorstr_(L"coldclient"),
        xorstr_(L"doomsday"), xorstr_(L"Doomsday"), xorstr_(L"novoline"), xorstr_(L"astolfo"), xorstr_(L"rise_"), xorstr_(L"cheat"),
        xorstr_(L"aimbot"), xorstr_(L"killaura"),
    };
    for (size_t i = 0; i < objs.size(); ++i) {
        for (size_t k = 0; k < sizeof(kTells) / sizeof(kTells[0]); ++k) {
            if (!IContainsW(objs[i].name, kTells[k])) continue;
            Finding f;
            f.severity = Severity::Critical;
            f.id       = xorstr_("CHEAT_NAMED_OBJECT");
            f.Ev(objs[i].type + xorstr_(": ") + WideToUtf8(objs[i].name));
            r.Add(f);
            break;
        }
    }
}

}
