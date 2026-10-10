#pragma once
#include "common.h"
#include "target.h"

namespace atlas {

struct SuspectRegion {
    uint64_t    base = 0;
    uint64_t    size = 0;
    bool        isPeImage = false;
    bool        executable = false;
    int         corroborations = 0;
    Trust       ownerTrust = Trust::Unknown;
};

bool TrustIsVouched(Trust t);

std::vector<SuspectRegion>& Suspects();
SuspectRegion* SuspectAt(uint64_t addr);
void ResetSuspects();
void NoteRegionOwner(uint64_t addr, Trust trust);

void CheckMemory(Target& t, Report& r);
void CheckModules(Target& t, Report& r);
void CheckJniTables(Target& t, Report& r);
void CheckHooks(Target& t, Report& r);
void CheckThreads(Target& t, Report& r);
void CheckArtifacts(Target& t, Report& r);
void CheckUnloadedModules(Target& t, Report& r);
void CheckJniStaticFieldIds(Target& t, Report& r);
void CheckJavaState(Target& t, Report& r);

void CollectDetections(const Report& r, std::vector<std::string>* out);

void Correlate(Target& t, Report& r);

}
