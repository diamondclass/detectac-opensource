#include "checks.h"
#include "trust.h"

#include <unordered_map>

namespace atlas {
namespace {

bool LooksLikeGameCode(const std::string& n) {
    if (n.empty()) return false;

    if (n.compare(0, 13, xorstr_("net/minecraft")) == 0) return true;
    if (n.compare(0, 11, xorstr_("com/mojang/")) == 0) {
        if (n.compare(0, 18, xorstr_("com/mojang/authlib")) == 0) return false;
        if (n.compare(0, 18, xorstr_("com/mojang/logging")) == 0) return false;
        if (n.compare(0, 15, xorstr_("com/mojang/util")) == 0) return false;
        return true;
    }
    if (n.compare(0, 9, xorstr_("optifine/")) == 0) return true;
    if (n.compare(0, 13, xorstr_("net/optifine/")) == 0) return true;

    if (n.find('/') != std::string::npos) return false;
    if (n.find(xorstr_("$$Lambda")) != std::string::npos) return false;
    if (n.find(xorstr_("LambdaForm")) != std::string::npos) return false;
    if (n[0] == '[') return false;

    size_t base = n.find('$');
    if (base == std::string::npos) base = n.size();
    if (base < 1 || base > 4) return false;
    for (size_t i = 0; i < base; ++i) {
        char c = n[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return false;
    }
    return true;
}

struct Chunk {
    uint64_t base = 0;
    std::vector<uint8_t> bytes;
    bool Has(uint64_t a, size_t n) const {
        return a >= base && a + n <= base + bytes.size();
    }
};

struct Snapshot {
    std::vector<Chunk> chunks;
    std::vector<std::pair<uint64_t, uint64_t> > image;

    const Chunk* ChunkAt(uint64_t a) const {
        size_t lo = 0, hi = chunks.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (a < chunks[mid].base) hi = mid;
            else if (a >= chunks[mid].base + chunks[mid].bytes.size()) lo = mid + 1;
            else return &chunks[mid];
        }
        return nullptr;
    }
    bool Qword(uint64_t a, uint64_t* out) const {
        const Chunk* c = ChunkAt(a);
        if (!c || !c->Has(a, 8)) return false;
        memcpy(out, c->bytes.data() + (a - c->base), 8);
        return true;
    }
    uint64_t imgLo = ~0ull, imgHi = 0;

    void FinishImage() {
        std::sort(image.begin(), image.end());
        for (size_t i = 0; i < image.size(); ++i) {
            imgLo = (std::min)(imgLo, image[i].first);
            imgHi = (std::max)(imgHi, image[i].second);
        }
    }
    bool InImage(uint64_t a) const {
        if (a < imgLo || a >= imgHi) return false;
        size_t lo = 0, hi = image.size();
        while (lo < hi) {
            size_t mid = (lo + hi) / 2;
            if (a < image[mid].first) hi = mid;
            else if (a >= image[mid].second) lo = mid + 1;
            else return true;
        }
        return false;
    }
    bool SymbolText(uint64_t a, std::string* out) const {
        const Chunk* c = ChunkAt(a);
        if (!c || !c->Has(a, 10)) return false;
        const uint8_t* p = c->bytes.data() + (a - c->base);

        struct Shape { size_t lenAt, bodyAt; };
        static const Shape kShapes[] = { { 4, 6 }, { 0, 8 } };
        for (size_t k = 0; k < sizeof(kShapes) / sizeof(kShapes[0]); ++k) {
            size_t lo = kShapes[k].lenAt, bo = kShapes[k].bodyAt;
            uint16_t len = (uint16_t)(p[lo] | (p[lo + 1] << 8));
            if (len < 1 || len > 250) continue;
            if (!c->Has(a + bo, len)) continue;
            std::string t((const char*)p + bo, len);
            bool ok = true;
            for (size_t i = 0; i < t.size() && ok; ++i) {
                unsigned char ch = (unsigned char)t[i];
                if (ch < 32 || ch >= 127) ok = false;
            }
            if (!ok) continue;
            out->swap(t);
            return true;
        }
        return false;
    }
};

const uint64_t kMaxRegion = 1024ull << 20;

bool Capture(const Target& t, Snapshot* s) {
    for (size_t i = 0; i < t.modules().size(); ++i)
        s->image.push_back(std::make_pair(t.modules()[i].base,
                                          t.modules()[i].base + t.modules()[i].size));

    s->FinishImage();

    struct Ranked {
        const Region* r;
        double density;
        bool operator<(const Ranked& o) const { return density > o.density; }
    };
    std::vector<Ranked> ranked;
    std::vector<uint8_t> sample;

    for (size_t i = 0; i < t.regions().size(); ++i) {
        const Region& r = t.regions()[i];
        if (r.state != MEM_COMMIT || !r.Readable()) continue;
        if (r.type == MEM_IMAGE) continue;
        if (r.size > kMaxRegion || r.size < 0x1000) continue;

        if (r.size <= (256u << 10)) {
            Ranked e;
            e.r = &r;
            e.density = 1.0;
            ranked.push_back(e);
            continue;
        }

        const int kProbes = 4;
        double best = 0.0;
        for (int pi = 0; pi < kProbes; ++pi) {
            uint64_t at = r.base + (r.size / kProbes) * pi;
            uint64_t left = (r.base + r.size) - at;
            size_t want = (size_t)(std::min)(left, (uint64_t)(16u << 10));
            if (want < 0x400) continue;

            Region probe = r;
            probe.base = at;
            probe.size = want;
            if (!t.ReadRegion(probe, sample, want) || sample.size() < 0x400) continue;

            size_t n = sample.size() / 8, hits = 0;
            const uint64_t* q = reinterpret_cast<const uint64_t*>(sample.data());
            for (size_t k = 0; k < n; ++k)
                if (q[k] >= 0x10000ull && s->InImage(q[k]))
                    ++hits;
            double d = n ? (double)hits / (double)n : 0.0;
            if (d > best) best = d;
        }

        Ranked e;
        e.r = &r;
        e.density = best;
        ranked.push_back(e);
    }
    std::sort(ranked.begin(), ranked.end());

    const double kFloor = 0.0002;
    uint64_t budget = 1536ull << 20;
    for (size_t i = 0; i < ranked.size(); ++i) {
        if (ranked[i].density < kFloor) break;
        const Region& r = *ranked[i].r;
        if (r.size > budget) continue;
        Chunk c;
        c.base = r.base;
        if (!t.ReadRegion(r, c.bytes, (size_t)r.size) || c.bytes.size() < 0x100) continue;
        budget -= (std::min)(budget, (uint64_t)c.bytes.size());
        s->chunks.push_back(Chunk());
        s->chunks.back().base = c.base;
        s->chunks.back().bytes.swap(c.bytes);
    }

    std::sort(s->chunks.begin(), s->chunks.end(),
              [](const Chunk& a, const Chunk& b) { return a.base < b.base; });
    return !s->chunks.empty();
}

const uint64_t kNameOffsets[] = { 0x18, 0x10 };

uint64_t FindKlassVtable(const Snapshot& s, uint64_t* nameOffset, int* confidence) {
    std::unordered_map<uint64_t, int> hist;
    hist.reserve(1 << 16);
    for (size_t ci = 0; ci < s.chunks.size(); ++ci) {
        const Chunk& c = s.chunks[ci];
        size_t n = c.bytes.size() / 8;
        const uint64_t* q = reinterpret_cast<const uint64_t*>(c.bytes.data());
        for (size_t i = 0; i < n; ++i) {
            uint64_t v = q[i];
            if (v < 0x10000ull) continue;
            if (!s.InImage(v)) continue;
            ++hist[v];
        }
    }

    std::vector<std::pair<int, uint64_t> > ranked;
    for (std::unordered_map<uint64_t, int>::const_iterator it = hist.begin();
         it != hist.end(); ++it)
        ranked.push_back(std::make_pair(it->second, it->first));
    std::sort(ranked.begin(), ranked.end(), std::greater<std::pair<int, uint64_t> >());

    uint64_t best = 0, bestOff = kNameOffsets[0];
    int bestOk = 0;
    const size_t kOffsets = sizeof(kNameOffsets) / sizeof(kNameOffsets[0]);

    for (size_t k = 0; k < ranked.size() && k < 24; ++k) {
        uint64_t cand = ranked[k].second;
        for (size_t oi = 0; oi < kOffsets; ++oi) {
            uint64_t off = kNameOffsets[oi];
            int tried = 0, ok = 0;
            for (size_t ci = 0; ci < s.chunks.size() && tried < 40; ++ci) {
                const Chunk& c = s.chunks[ci];
                size_t n = c.bytes.size() / 8;
                const uint64_t* q = reinterpret_cast<const uint64_t*>(c.bytes.data());
                for (size_t i = 0; i < n && tried < 40; ++i) {
                    if (q[i] != cand) continue;
                    ++tried;
                    uint64_t nameSym = 0;
                    std::string txt;
                    if (s.Qword(c.base + i * 8 + off, &nameSym) && s.SymbolText(nameSym, &txt))
                        ++ok;
                }
            }
            if (ok > bestOk) { bestOk = ok; best = cand; bestOff = off; }
        }
        if (bestOk >= 38) break;
    }
    if (confidence)  *confidence = bestOk;
    if (nameOffset)  *nameOffset = bestOff;
    return bestOk >= 20 ? best : 0;
}

}

void CheckJniStaticFieldIds(Target& t, Report& r) {
    const Module* jvm = t.ModuleByName(xorstr_(L"jvm.dll"));
    if (!jvm) return;

    Snapshot snap;
    if (!Capture(t, &snap)) {
        return;
    }

    int confidence = 0;
    uint64_t nameOffset = 0;
    uint64_t vtable = FindKlassVtable(snap, &nameOffset, &confidence);
    if (!vtable) {
        uint64_t bytes = 0;
        for (size_t i = 0; i < snap.chunks.size(); ++i) bytes += snap.chunks[i].bytes.size();
        return;
    }

    std::map<uint64_t, std::string> klasses;
    for (size_t ci = 0; ci < snap.chunks.size(); ++ci) {
        const Chunk& c = snap.chunks[ci];
        size_t n = c.bytes.size() / 8;
        const uint64_t* q = reinterpret_cast<const uint64_t*>(c.bytes.data());
        for (size_t i = 0; i < n; ++i) {
            if (q[i] != vtable) continue;
            uint64_t klass = c.base + i * 8;
            uint64_t nameSym = 0;
            std::string name;
            if (!snap.Qword(klass + nameOffset, &nameSym)) continue;
            if (!snap.SymbolText(nameSym, &name)) continue;
            klasses[klass] = name;
        }
    }
    const int examined = (int)klasses.size();

    uint64_t klo = ~0ull, khi = 0;
    std::vector<uint64_t> sortedKlasses;
    sortedKlasses.reserve(klasses.size());
    for (std::map<uint64_t, std::string>::const_iterator it = klasses.begin();
         it != klasses.end(); ++it) {
        sortedKlasses.push_back(it->first);
        klo = (std::min)(klo, it->first);
        khi = (std::max)(khi, it->first);
    }

    std::map<uint64_t, std::vector<uint64_t> > candidates;
    for (size_t ci = 0; ci < snap.chunks.size(); ++ci) {
        const Chunk& c = snap.chunks[ci];
        size_t n = c.bytes.size() / 8;
        const uint64_t* q = reinterpret_cast<const uint64_t*>(c.bytes.data());
        for (size_t i = 0; i < n; ++i) {
            uint64_t v = q[i];
            if (v < klo || v > khi) continue;
            if (!std::binary_search(sortedKlasses.begin(), sortedKlasses.end(), v)) continue;
            std::map<uint64_t, std::string>::const_iterator k = klasses.find(v);
            if (k == klasses.end()) continue;
            uint64_t here = c.base + i * 8;
            if (here == v) continue;
            candidates[v].push_back(here);
        }
    }

    int carrying = 0;
    std::vector<std::pair<std::string, uint64_t> > unaccounted;
    for (std::map<uint64_t, std::vector<uint64_t> >::const_iterator it = candidates.begin();
         it != candidates.end(); ++it) {
        uint64_t klass = it->first;
        bool linked = false;
        uint64_t at = 0;
        for (uint64_t off = 0x20; off < 0x300 && !linked; off += 8) {
            uint64_t p = 0;
            if (!snap.Qword(klass + off, &p)) continue;
            for (size_t j = 0; j < it->second.size(); ++j) {
                if (p == it->second[j]) { linked = true; at = off; break; }
            }
        }
        if (!linked) continue;
        ++carrying;
        const std::string& name = klasses[klass];
        if (LooksLikeGameCode(name)) unaccounted.push_back(std::make_pair(name, at));
    }

    if (unaccounted.empty()) return;

    Finding f;
    f.severity   = Severity::Critical;
    f.id         = xorstr_("JNI_STATIC_FIELD_HANDLE");
    r.Add(f);
}

}
