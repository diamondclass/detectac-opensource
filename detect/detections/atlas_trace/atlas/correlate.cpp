#include "checks.h"

namespace atlas {

void Correlate(Target& t, Report& r) {
    for (size_t i = 0; i < Suspects().size(); ++i) {
        SuspectRegion& s = Suspects()[i];
        if (s.corroborations < 2) continue;
        if (s.isPeImage) continue;
        if (TrustIsVouched(s.ownerTrust)) continue;

        Finding f;
        f.severity = Severity::Critical;
        f.id       = xorstr_("CORROBORATED_INJECTION");
        r.Add(f);
    }

    bool runtimeAgent = false, foreignArchive = false;
    for (size_t i = 0; i < r.findings().size(); ++i) {
        const std::string& id = r.findings()[i].id;
        if (id == xorstr_("RUNTIME_JAVAAGENT")) runtimeAgent = true;
        if (id == xorstr_("OFFCLASSPATH_ARCHIVE") || id == xorstr_("UNEXPECTED_OPEN_FILE") ||
            id == xorstr_("OPEN_DELETED_FILE"))
            foreignArchive = true;
    }
    if (runtimeAgent && foreignArchive) {
        Finding f;
        f.severity = Severity::Critical;
        f.id       = xorstr_("JAVA_AGENT_INJECTION");
        r.Add(f);
    }

    r.SortBySeverity();
}

}
