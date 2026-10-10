#include "common.h"
#include <cstdio>

namespace atlas {
namespace {

struct MethodCode {
    std::string id;
    std::string code;
};

const MethodCode* GetCodes(size_t* countOut) {
    static const MethodCode kCodes[] = {
        { xorstr_("MANUAL_MAP"),              xorstr_("MM") },
        { xorstr_("MANUAL_MAP_STRIPPED"),     xorstr_("MS") },
        { xorstr_("ANON_EXEC_SECTION"),       xorstr_("AS") },
        { xorstr_("UNBACKED_RX"),             xorstr_("RX") },
        { xorstr_("ORPHAN_EXEC_ALLOC"),       xorstr_("OA") },
        { xorstr_("UNLINKED_MODULE"),         xorstr_("UM") },
        { xorstr_("JVM_CODE_PATCHED"),        xorstr_("CP") },
        { xorstr_("CODE_HOOK"),               xorstr_("CH") },
        { xorstr_("IAT_HOOK"),                xorstr_("IH") },
        { xorstr_("JNI_TABLE_HOOK"),          xorstr_("JT") },
        { xorstr_("JVM_TABLE_HOOK"),          xorstr_("VT") },
        { xorstr_("THREAD_UNBACKED"),         xorstr_("TU") },
        { xorstr_("THREAD_IN_HIDDEN_MODULE"), xorstr_("TH") },
        { xorstr_("UNSIGNED_JVMTI_AGENT"),    xorstr_("UA") },
        { xorstr_("JVMTI_AGENT_OPERATED"),    xorstr_("AO") },
        { xorstr_("NATIVE_MC_JNI"),           xorstr_("NJ") },
        { xorstr_("NATIVE_MC_MEMBERS"),       xorstr_("NM") },
        { xorstr_("CHEAT_NAMED_OBJECT"),      xorstr_("NO") },
        { xorstr_("IMPOSTOR_MC_NAMESPACE"),   xorstr_("IN") },
        { xorstr_("JAVA_AGENT_INJECTION"),    xorstr_("JA") },
        { xorstr_("CORROBORATED_INJECTION"),  xorstr_("CI") },
        { xorstr_("UNLOADED_UNKNOWN_MODULE"), xorstr_("UD") },
    };
    *countOut = sizeof(kCodes) / sizeof(kCodes[0]);
    return kCodes;
}

const char* CodeFor(const std::string& id) {
    size_t count = 0;
    const MethodCode* codes = GetCodes(&count);
    for (size_t i = 0; i < count; ++i)
        if (id == codes[i].id) return codes[i].code.c_str();
    return nullptr;
}

std::string ClientNamedBy(const Finding& f) {
    if (f.id == xorstr_("IMPOSTOR_MC_NAMESPACE")) {
        for (size_t i = 0; i < f.evidence.size(); ++i)
            if (f.evidence[i].find(xorstr_("net/minecraft_")) != std::string::npos)
                return xorstr_("ATLAS Trace:Doomsday Has Been Injected And Self Destructed In Current Minecraft Session");
    }
    if (f.id == xorstr_("CHEAT_NAMED_OBJECT")) {
        for (size_t i = 0; i < f.evidence.size(); ++i) {
            if (IContains(f.evidence[i], xorstr_("{C0LD-")))
                return xorstr_("ATLAS Trace:Cold Client Is Currently Injected Into Minecraft");
        }
    }
    return std::string();
}

}

void CollectDetections(const Report& r, std::vector<std::string>* out) {
    std::set<std::string> said;
    const std::vector<Finding>& fs = r.findings();

    auto say = [&](const std::string& line) {
        if (said.insert(line).second) out->push_back(line);
    };

    for (size_t i = 0; i < fs.size(); ++i) {
        if (fs[i].severity != Severity::Critical) continue;
        std::string who = ClientNamedBy(fs[i]);
        if (!who.empty()) say(who);
    }

    for (size_t i = 0; i < fs.size(); ++i) {
        if (fs[i].severity != Severity::Critical) continue;
        if (fs[i].id != xorstr_("JNI_STATIC_FIELD_HANDLE")) continue;
        say(xorstr_("ATLAS Trace:Minecraft has been injected with a cheat client"));
    }

    for (size_t i = 0; i < fs.size(); ++i) {
        if (fs[i].severity != Severity::Critical) continue;
        if (fs[i].id == xorstr_("JNI_STATIC_FIELD_HANDLE")) continue;
        if (!ClientNamedBy(fs[i]).empty()) continue;
        const char* code = CodeFor(fs[i].id);
        if (code)
            say(Format(xorstr_("ATLAS Trace [%s]:Minecraft has been injected with a cheat client"), code));
    }
}

}
