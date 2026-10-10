#include "c_atlas_trace.h"

#include "atlas/common.h"
#include "atlas/ntdefs.h"
#include "atlas/target.h"
#include "atlas/checks.h"

void c_atlas_trace::start_atlas_trace_scan ( )
{
    try
    {
        if ( !atlas::nt::Init ( ) )
            return;

        atlas::nt::EnableDebugPrivilege ( );

        std::vector<DWORD> pids = atlas::FindMinecraftProcesses ( nullptr );
        if ( pids.empty ( ) )
            return;

        atlas::Target target;
        if ( !target.Open ( pids [ 0 ] , nullptr ) )
            return;

        atlas::ResetSuspects ( );
        atlas::Report report;

        atlas::CheckMemory ( target , report );
        atlas::CheckModules ( target , report );
        atlas::CheckJniTables ( target , report );
        atlas::CheckHooks ( target , report );
        atlas::CheckThreads ( target , report );
        atlas::CheckArtifacts ( target , report );
        atlas::CheckUnloadedModules ( target , report );
        atlas::CheckJniStaticFieldIds ( target , report );
        atlas::CheckJavaState ( target , report );
        atlas::Correlate ( target , report );

        std::vector<std::string> detections;
        atlas::CollectDetections ( report , &detections );

        for ( const std::string& line : detections )
            LOG ( DETECTION , xorstr_ ( "N/A" ) ) << line;
    }
    catch ( ... )
    {
    }
}
