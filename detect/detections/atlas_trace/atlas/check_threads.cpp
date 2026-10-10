#include "checks.h"
#include "pe.h"
#include "trust.h"

namespace atlas {
namespace {

uint64_t ResolveExport(const Target& t, const Module& m, const char* name) {
    if (m.path.empty()) return 0;
    DiskImage img;
    if (!LoadDiskImage(m.path, m.base, &img)) return 0;
    std::vector<ExportEntry> ex;
    if (!ReadExports(img, &ex)) return 0;
    for (size_t i = 0; i < ex.size(); ++i)
        if (ex[i].name == name && !ex[i].forwarder) return m.base + ex[i].rva;
    return 0;
}

uint64_t FileTimeToU64(const FILETIME& ft) {
    return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
}

std::string ThreadDescription(DWORD tid) {
    typedef HRESULT(WINAPI * PFN)(HANDLE, PWSTR*);
    static PFN pGet = (PFN)GetProcAddress(GetModuleHandleW(xorstr_(L"kernel32.dll")),
                                          xorstr_("GetThreadDescription"));
    if (!pGet) return std::string();
    HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!th) return std::string();
    PWSTR desc = nullptr;
    std::string out;
    if (SUCCEEDED(pGet(th, &desc)) && desc) {
        out = WideToUtf8(desc);
        LocalFree(desc);
    }
    CloseHandle(th);
    return out;
}

}

void CheckThreads(Target& t, Report& r) {
    FILETIME pc{}, pe{}, pk{}, pu{};
    uint64_t procStart = 0;
    if (GetProcessTimes(t.handle(), &pc, &pe, &pk, &pu)) procStart = FileTimeToU64(pc);

    const Module* jvm = t.ModuleByName(xorstr_(L"jvm.dll"));
    uint64_t enqueueOp = 0;
    if (jvm) enqueueOp = ResolveExport(t, *jvm, xorstr_("JVM_EnqueueOperation"));

    int foreign = 0, hidden = 0, attachThreads = 0;

    for (size_t i = 0; i < t.threads().size(); ++i) {
        const ThreadInfo& th = t.threads()[i];

        std::string desc = ThreadDescription(th.tid);
        if (desc == xorstr_("Attach Listener")) {
            ++attachThreads;
            uint64_t created = FileTimeToU64(th.createTime);
            double   age = (procStart && created > procStart)
                         ? (double)(created - procStart) / 1e7 : -1.0;

            const double kEagerStartWindow = 5.0;
            bool late = (age < 0.0) || (age > kEagerStartWindow);

            continue;
        }

        if (enqueueOp && th.startAddress == enqueueOp) {
            ++attachThreads;
            uint64_t created = FileTimeToU64(th.createTime);
            double secondsIn = procStart && created > procStart
                             ? (double)(created - procStart) / 1e7 : -1.0;

            continue;
        }

        if (th.hiddenFromDebugger) {
            ++hidden;
        }

        if (th.startAddress == 0) continue;
        const Module* m = t.ModuleAt(th.startAddress);
        if (m) {
            if (!m->inLoaderList) {
                ++foreign;
                Finding f;
                f.severity = Severity::Critical;
                f.id       = xorstr_("THREAD_IN_HIDDEN_MODULE");
                r.Add(f);
            }
            continue;
        }

        ++foreign;
        SuspectRegion* sus = SuspectAt(th.startAddress);
        if (sus) sus->corroborations += 2;

        Finding f;
        f.severity = Severity::Critical;
        f.id       = xorstr_("THREAD_UNBACKED");
        uint8_t code[16] = {};
        uint64_t created = FileTimeToU64(th.createTime);
        r.Add(f);
    }
}

}
