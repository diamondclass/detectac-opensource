#include "checks.h"
#include "trust.h"
#include <functional>

namespace atlas {
namespace {

enum class Kind {
    MinecraftClass,
    MinecraftMember,
    JvmLookup,
    JniUse,
    CheatFeature,
    CheatBrand,
};

struct Needle {
    std::string text;
    Kind        kind;
};

const Needle kNeedles[] = {
    { xorstr_("net/minecraft/client/Minecraft"),                    Kind::MinecraftClass },
    { xorstr_("net/minecraft/client/entity/EntityPlayerSP"),        Kind::MinecraftClass },
    { xorstr_("net/minecraft/client/multiplayer/WorldClient"),      Kind::MinecraftClass },
    { xorstr_("net/minecraft/client/multiplayer/PlayerControllerMP"), Kind::MinecraftClass },
    { xorstr_("net/minecraft/client/network/NetHandlerPlayClient"), Kind::MinecraftClass },
    { xorstr_("net/minecraft/client/renderer/EntityRenderer"),      Kind::MinecraftClass },
    { xorstr_("net/minecraft/client/gui/"),                         Kind::MinecraftClass },
    { xorstr_("net/minecraft/entity/Entity"),                       Kind::MinecraftClass },
    { xorstr_("net/minecraft/entity/player/EntityPlayer"),          Kind::MinecraftClass },
    { xorstr_("net/minecraft/util/Vec3"),                           Kind::MinecraftClass },
    { xorstr_("net/minecraft/util/MovingObjectPosition"),           Kind::MinecraftClass },
    { xorstr_("net/minecraft/util/AxisAlignedBB"),                  Kind::MinecraftClass },
    { xorstr_("net/minecraft/util/BlockPos"),                       Kind::MinecraftClass },
    { xorstr_("net/minecraft/network/play/client/"),                Kind::MinecraftClass },
    { xorstr_("net/minecraft/network/play/server/"),                Kind::MinecraftClass },
    { xorstr_("net/minecraft/network/Packet"),                      Kind::MinecraftClass },
    { xorstr_("net/minecraft/world/World"),                         Kind::MinecraftClass },
    { xorstr_("net/minecraft/block/Block"),                         Kind::MinecraftClass },
    { xorstr_("net/minecraft/item/Item"),                           Kind::MinecraftClass },
    { xorstr_("net/minecraft/"),                                    Kind::MinecraftClass },
    { xorstr_("(Lnet/minecraft/"),                                  Kind::MinecraftClass },
    { xorstr_("Lnet/minecraft/"),                                   Kind::MinecraftClass },
    { xorstr_("net.minecraft.client.Minecraft"),                    Kind::MinecraftClass },
    { xorstr_("com/mojang/"),                                       Kind::MinecraftClass },
    { xorstr_("optifine/"),                                         Kind::MinecraftClass },

    { xorstr_("thePlayer"),            Kind::MinecraftMember },
    { xorstr_("theWorld"),             Kind::MinecraftMember },
    { xorstr_("getMinecraft"),         Kind::MinecraftMember },
    { xorstr_("sendQueue"),            Kind::MinecraftMember },
    { xorstr_("rotationYaw"),          Kind::MinecraftMember },
    { xorstr_("rotationPitch"),        Kind::MinecraftMember },
    { xorstr_("motionX"),              Kind::MinecraftMember },
    { xorstr_("motionY"),              Kind::MinecraftMember },
    { xorstr_("motionZ"),              Kind::MinecraftMember },
    { xorstr_("onGround"),             Kind::MinecraftMember },
    { xorstr_("distanceTo"),           Kind::MinecraftMember },
    { xorstr_("getDistanceToEntity"),  Kind::MinecraftMember },
    { xorstr_("loadedEntityList"),     Kind::MinecraftMember },
    { xorstr_("objectMouseOver"),      Kind::MinecraftMember },
    { xorstr_("leftClickCounter"),     Kind::MinecraftMember },
    { xorstr_("currentScreen"),        Kind::MinecraftMember },
    { xorstr_("swingItem"),            Kind::MinecraftMember },
    { xorstr_("isBlockNormalCube"),    Kind::MinecraftMember },

    { xorstr_("JNI_GetCreatedJavaVMs"), Kind::JvmLookup },
    { xorstr_("AttachCurrentThread"),   Kind::JvmLookup },
    { xorstr_("AttachCurrentThreadAsDaemon"), Kind::JvmLookup },

    { xorstr_("GetMethodID"),       Kind::JniUse },
    { xorstr_("GetStaticMethodID"), Kind::JniUse },
    { xorstr_("GetFieldID"),        Kind::JniUse },
    { xorstr_("GetStaticFieldID"),  Kind::JniUse },
    { xorstr_("RegisterNatives"),   Kind::JniUse },
    { xorstr_("FindClass"),         Kind::JniUse },
    { xorstr_("NewGlobalRef"),      Kind::JniUse },
    { xorstr_("CallObjectMethod"),  Kind::JniUse },

    { xorstr_("KillAura"),     Kind::CheatFeature },
    { xorstr_("Killaura"),     Kind::CheatFeature },
    { xorstr_("Triggerbot"),   Kind::CheatFeature },
    { xorstr_("TriggerBot"),   Kind::CheatFeature },
    { xorstr_("Aimbot"),       Kind::CheatFeature },
    { xorstr_("AimAssist"),    Kind::CheatFeature },
    { xorstr_("AutoClicker"),  Kind::CheatFeature },
    { xorstr_("Autoclicker"),  Kind::CheatFeature },
    { xorstr_("Reach"),        Kind::CheatFeature },
    { xorstr_("Velocity"),     Kind::CheatFeature },
    { xorstr_("AntiKnockback"),Kind::CheatFeature },
    { xorstr_("Scaffold"),     Kind::CheatFeature },
    { xorstr_("AutoBlock"),    Kind::CheatFeature },
    { xorstr_("Backtrack"),    Kind::CheatFeature },
    { xorstr_("NoFall"),       Kind::CheatFeature },
    { xorstr_("FastPlace"),    Kind::CheatFeature },
    { xorstr_("ClickGUI"),     Kind::CheatFeature },
    { xorstr_("Bhop"),         Kind::CheatFeature },
    { xorstr_("BHop"),         Kind::CheatFeature },
    { xorstr_("HitBox"),       Kind::CheatFeature },
    { xorstr_("Hitboxes"),     Kind::CheatFeature },
    { xorstr_("Nuker"),        Kind::CheatFeature },
    { xorstr_("Xray"),         Kind::CheatFeature },
    { xorstr_("XRay"),         Kind::CheatFeature },
    { xorstr_("ESP"),          Kind::CheatFeature },
    { xorstr_("Tracers"),      Kind::CheatFeature },
    { xorstr_("AutoPot"),      Kind::CheatFeature },
    { xorstr_("Wtap"),         Kind::CheatFeature },
    { xorstr_("Stap"),         Kind::CheatFeature },
    { xorstr_("LegitAura"),    Kind::CheatFeature },
    { xorstr_("AntiBot"),      Kind::CheatFeature },
    { xorstr_("FakeLag"),      Kind::CheatFeature },
    { xorstr_("Blink"),        Kind::CheatFeature },

    { xorstr_("Vape"),       Kind::CheatBrand },
    { xorstr_("Novoline"),   Kind::CheatBrand },
    { xorstr_("Rise"),       Kind::CheatBrand },
    { xorstr_("Astolfo"),    Kind::CheatBrand },
    { xorstr_("Entropy"),    Kind::CheatBrand },
    { xorstr_("Moon"),       Kind::CheatBrand },
    { xorstr_("Prestige"),   Kind::CheatBrand },
    { xorstr_("Exhibition"), Kind::CheatBrand },
    { xorstr_("Doomsday"),   Kind::CheatBrand },
    { xorstr_("Trigon"),     Kind::CheatBrand },
    { xorstr_("Sigma"),      Kind::CheatBrand },
    { xorstr_("Slinky"),     Kind::CheatBrand },
    { xorstr_("Ariza"),      Kind::CheatBrand },
    { xorstr_("ZeroDay"),    Kind::CheatBrand },
    { xorstr_("Loki"),       Kind::CheatBrand },
    { xorstr_("Wurst"),      Kind::CheatBrand },
    { xorstr_("Impact"),     Kind::CheatBrand },
    { xorstr_("LiquidBounce"), Kind::CheatBrand },
    { xorstr_("Meteor"),     Kind::CheatBrand },
    { xorstr_("Raven"),      Kind::CheatBrand },
    { xorstr_("Flux"),       Kind::CheatBrand },
    { xorstr_("Wildfire"),   Kind::CheatBrand },
};

struct Hits {
    std::map<Kind, std::vector<std::string> > byKind;
    size_t total = 0;

    void Add(Kind k, const std::string& s) {
        std::vector<std::string>& v = byKind[k];
        for (size_t i = 0; i < v.size(); ++i) if (v[i] == s) return;
        if (v.size() < 12) v.push_back(s);
        ++total;
    }
    bool Has(Kind k) const {
        std::map<Kind, std::vector<std::string> >::const_iterator it = byKind.find(k);
        return it != byKind.end() && !it->second.empty();
    }
    size_t Count(Kind k) const {
        std::map<Kind, std::vector<std::string> >::const_iterator it = byKind.find(k);
        return it == byKind.end() ? 0 : it->second.size();
    }
    std::string List(Kind k, size_t max = 8) const {
        std::map<Kind, std::vector<std::string> >::const_iterator it = byKind.find(k);
        if (it == byKind.end()) return std::string();
        std::string s;
        for (size_t i = 0; i < it->second.size() && i < max; ++i) {
            if (i) s += xorstr_(", ");
            s += xorstr_("\"") + it->second[i] + xorstr_("\"");
        }
        if (it->second.size() > max) s += xorstr_(", ...");
        return s;
    }
};

bool LooksLikeStringLiteral(const std::vector<uint8_t>& buf, size_t at, size_t len) {
    size_t end = at + len;
    if (end < buf.size()) {
        uint8_t after = buf[end];
        bool ok = (after == 0) || (after >= 0x20 && after < 0x7F);
        if (!ok) return false;
    }
    if (at > 0) {
        uint8_t before = buf[at - 1];
        bool ok = (before == 0) || (before >= 0x20 && before < 0x7F);
        if (!ok) return false;
    }
    return true;
}

void ScanBuffer(const std::vector<uint8_t>& buf, Hits* hits) {
    if (buf.empty()) return;
    for (size_t n = 0; n < sizeof(kNeedles) / sizeof(kNeedles[0]); ++n) {
        const std::string& text = kNeedles[n].text;
        size_t len = text.size();
        if (len == 0 || len > buf.size()) continue;
        const uint8_t* first = buf.data();
        const uint8_t* last  = buf.data() + buf.size();
        const uint8_t* p = first;
        int found = 0;
        while (p + len <= last && found < 4) {
            const uint8_t* q = (const uint8_t*)memchr(p, (unsigned char)text[0], (size_t)(last - p) - len + 1);
            if (!q) break;
            if (memcmp(q, text.data(), len) == 0 &&
                LooksLikeStringLiteral(buf, (size_t)(q - first), len)) {
                hits->Add(kNeedles[n].kind, text);
                ++found;
            }
            p = q + 1;
        }
    }
}

bool ReadRange(const Target& t, uint64_t base, uint64_t size,
               std::vector<uint8_t>* out, size_t cap) {
    size_t want = (size_t)(std::min)((uint64_t)cap, size);
    out->assign(want, 0);
    bool any = false;
    for (size_t off = 0; off < want; off += 0x10000) {
        size_t chunk = (std::min)((size_t)0x10000, want - off);
        SIZE_T got = 0;
        if (ReadProcessMemory(t.handle(), (LPCVOID)(base + off), out->data() + off, chunk, &got))
            any = true;
    }
    return any;
}

void ReportHits(Target& t, Report& r, const std::string& where, uint64_t base,
                bool unbacked, const Hits& hits, const std::wstring& path,
                bool pathTrusted) {
    bool mc      = hits.Has(Kind::MinecraftClass);
    bool member  = hits.Has(Kind::MinecraftMember);
    bool lookup  = hits.Has(Kind::JvmLookup);
    bool jni     = hits.Has(Kind::JniUse);
    bool feature = hits.Count(Kind::CheatFeature) >= 3;
    bool brand   = hits.Has(Kind::CheatBrand);

    if (!mc && !member && !lookup && !feature && !brand) return;

    if (pathTrusted && !mc) return;

    Finding f;

    if (!mc && !member) {
        if (lookup) {
            Finding g;
            g.severity = unbacked ? Severity::High : Severity::Medium;
            g.id       = xorstr_("NATIVE_JVM_LOOKUP");
            SuspectRegion* s2 = SuspectAt(base);
            if (s2) ++s2->corroborations;
            r.Add(g);
        }
        return;
    }

    if (mc) {
        f.severity = unbacked ? Severity::Critical : Severity::High;
        f.id       = xorstr_("NATIVE_MC_JNI");
        if (member) f.severity = Severity::Critical;
    } else {
        f.severity = Severity::High;
        f.id       = xorstr_("NATIVE_MC_MEMBERS");
    }

    SuspectRegion* sus = SuspectAt(base);
    if (sus) sus->corroborations += 2;
    r.Add(f);
}

}

void CheckArtifacts(Target& t, Report& r) {
    if (!g_opt.deepStrings) return;

    const size_t kPerRegionCap = 24u << 20;
    size_t scannedBytes = 0;
    int scannedRegions = 0;

    for (size_t i = 0; i < Suspects().size(); ++i) {
        SuspectRegion& s = Suspects()[i];
        std::vector<uint8_t> buf;
        if (!ReadRange(t, s.base, s.size, &buf, kPerRegionCap)) continue;
        scannedBytes += buf.size();
        ++scannedRegions;
        Hits hits;
        ScanBuffer(buf, &hits);
        if (hits.total)
            ReportHits(t, r, std::string(), s.base, true, hits,
                       std::wstring(), false);
    }

    for (size_t i = 0; i < t.modules().size(); ++i) {
        const Module& m = t.modules()[i];
        bool pathTrusted = (m.trust == Trust::PathTrusted);
        bool untrusted = (m.trust == Trust::Unknown) || pathTrusted || !m.inLoaderList;
        if (!untrusted) continue;
        if (m.size == 0 || m.size > (64ull << 20)) continue;
        if (SuspectAt(m.base)) continue;

        std::vector<uint8_t> buf;
        if (!ReadRange(t, m.base, m.size, &buf, kPerRegionCap)) continue;
        scannedBytes += buf.size();
        ++scannedRegions;
        Hits hits;
        ScanBuffer(buf, &hits);
        if (hits.total)
            ReportHits(t, r, std::string(), m.base, !m.inLoaderList, hits, m.path,
                       pathTrusted);
    }

}

}
