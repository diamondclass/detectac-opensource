#include "checks.h"
#include "pe.h"
#include "trust.h"

namespace atlas {
namespace {

bool PathIsSuspiciousLocation(const std::wstring& path) {
    std::wstring p = ToLowerW(path);
    static const std::wstring kBad[] = {
        xorstr_(L"\\appdata\\local\\temp\\"),
        xorstr_(L"\\windows\\temp\\"),
        xorstr_(L"\\downloads\\"),
        xorstr_(L"\\$recycle.bin\\"),
        xorstr_(L"\\programdata\\temp\\"),
        xorstr_(L"\\users\\public\\"),
    };
    for (size_t i = 0; i < sizeof(kBad) / sizeof(kBad[0]); ++i)
        if (p.find(kBad[i]) != std::wstring::npos) return true;
    return false;
}

bool FileStillExists(const std::wstring& path) {
    if (path.empty()) return false;
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES;
}

struct ExportProfile {
    bool jvmtiAgent = false;
    bool jniLibrary = false;
    int  javaNatives = 0;
    std::vector<std::string> agentEntries;
};

ExportProfile ProfileExports(const std::vector<ExportEntry>& exports) {
    ExportProfile p;
    for (size_t i = 0; i < exports.size(); ++i) {
        const std::string& n = exports[i].name;
        if (n.empty()) continue;
        if (n == xorstr_("Agent_OnLoad") || n == xorstr_("Agent_OnAttach") || n == xorstr_("Agent_OnUnload") ||
            n == xorstr_("Agent_OnAttach_L") || n == xorstr_("Agent_OnLoad_L")) {
            p.jvmtiAgent = true;
            p.agentEntries.push_back(n);
        }
        if (n == xorstr_("JNI_OnLoad") || n == xorstr_("JNI_OnUnload")) p.jniLibrary = true;
        if (n.compare(0, 5, xorstr_("Java_")) == 0) { ++p.javaNatives; p.jniLibrary = true; }
    }
    return p;
}

}

void CheckModules(Target& t, Report& r) {
    int untrusted = 0, unlinked = 0;

    for (size_t i = 0; i < t.modules().size(); ++i) {
        const Module& m = t.modules()[i];

        bool winmd = IEndsWithW(m.path, xorstr_(L".winmd")) ||
                     IContainsW(m.path, xorstr_(L"\\WinMetadata\\"));

        if (!m.inLoaderList && !winmd) {
            Finding f;
            f.severity = Severity::Critical;
            f.id       = xorstr_("UNLINKED_MODULE");
            r.Add(f);
            ++unlinked;

            SuspectRegion s;
            s.base = m.base;
            s.size = m.size;
            s.executable = true;
            s.isPeImage  = true;
            s.corroborations += 2;
            Suspects().push_back(s);
            continue;
        }


        if (m.trust == Trust::Unknown) {
            ++untrusted;

            DiskImage img;
            ExportProfile prof;
            bool haveDisk = !m.path.empty() && LoadDiskImage(m.path, m.base, &img);
            if (haveDisk) {
                std::vector<ExportEntry> exports;
                if (ReadExports(img, &exports)) prof = ProfileExports(exports);
            }

            Finding f;

            if (prof.jvmtiAgent) {
                f.severity = Severity::Critical;
                f.id       = xorstr_("UNSIGNED_JVMTI_AGENT");
            } else if (prof.jniLibrary) {
                f.severity = Severity::High;
                f.id       = xorstr_("UNSIGNED_JNI_LIBRARY");
            } else if (PathIsSuspiciousLocation(m.path)) {
                f.severity = Severity::High;
                f.id       = xorstr_("MODULE_FROM_TEMP");
            } else {
                f.severity = Severity::Medium;
                f.id       = xorstr_("UNSIGNED_MODULE");
            }
            r.Add(f);
        }
    }

    if (t.ModuleByName(xorstr_(L"instrument.dll")) && t.agentArgs().empty()) {
        Finding f;
        f.severity = Severity::High;
        f.id       = xorstr_("RUNTIME_JAVAAGENT");
        const Module* im = t.ModuleByName(xorstr_(L"instrument.dll"));
        r.Add(f);
    }

    for (size_t i = 0; i < t.agentArgs().size(); ++i) {
        const std::wstring& a = t.agentArgs()[i];
        size_t colon = a.find(L':');
        std::wstring agentPath = (colon == std::wstring::npos) ? std::wstring()
                                                               : a.substr(colon + 1);
        size_t eq = agentPath.find(L'=');
        if (eq != std::wstring::npos) agentPath = agentPath.substr(0, eq);

        std::string signer;
        Trust at = agentPath.empty() ? Trust::Unknown : ClassifyModule(agentPath, &signer);
        bool ownedByLauncher = !agentPath.empty() && IsLauncherOwnedPath(agentPath);
        bool trusted = (at == Trust::TrustedVendor) || (at == Trust::PathTrusted) ||
                       ownedByLauncher;

        Finding f;
        f.id = xorstr_("AGENT_ARGUMENT");
        if (trusted) {
            f.severity = Severity::Info;
        } else {
            f.severity = Severity::High;
        }
        r.Add(f);
    }

    std::set<std::wstring> cp;
    for (size_t i = 0; i < t.classpath().size(); ++i)
        cp.insert(ToLowerW(FileNameOfW(t.classpath()[i])));

    std::set<std::wstring> reportedJars;
    for (size_t i = 0; i < t.regions().size(); ++i) {
        const Region& q = t.regions()[i];
        if (q.mappedFile.empty()) continue;
        std::wstring lower = ToLowerW(q.mappedFile);
        if (!IEndsWithW(lower, xorstr_(L".jar")) && !IEndsWithW(lower, xorstr_(L".zip"))) continue;
        std::wstring name = FileNameOfW(lower);
        if (cp.count(name)) continue;
        if (!reportedJars.insert(lower).second) continue;
        if (IContainsW(lower, xorstr_(L"\\mods\\")) || IContainsW(lower, xorstr_(L"\\resourcepacks\\")) ||
            IContainsW(lower, xorstr_(L"\\libraries\\")) || IContainsW(lower, xorstr_(L"\\versions\\")) ||
            IContainsW(lower, xorstr_(L"\\lib\\")) || IContainsW(lower, xorstr_(L"\\jre")) ||
            IContainsW(lower, xorstr_(L"\\jdk")))
            continue;

        Finding f;
        f.severity = PathIsSuspiciousLocation(q.mappedFile) ? Severity::High : Severity::Medium;
        f.id       = xorstr_("OFFCLASSPATH_ARCHIVE");
        r.Add(f);
    }

}

}
