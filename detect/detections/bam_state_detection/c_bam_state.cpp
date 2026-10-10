#include "c_bam_state.h"

SC_HANDLE bam_state::scm_handle = nullptr;
SC_HANDLE bam_state::service_handle = nullptr;
SERVICE_STATUS_PROCESS bam_state::service_status = {};

bool bam_state::open_sc_manager()
{
    try{
    scm_handle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm_handle)
    {
        return false;
    }
    return true;
    }
    catch (...) {}
}

bool bam_state::open_service(const std::wstring& service_name)
{
    try{
    if (!scm_handle)
    {
        return false;
    }

    service_handle = OpenServiceW(scm_handle, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!service_handle)
    {
        return false;
    }

    return true;
    }
    catch (...) {}
}

bool bam_state::query_service_status()
{
    try{
    if (!service_handle)
    {
        return false;
    }

    DWORD bytes_needed = 0;
    if (!QueryServiceStatusEx(service_handle, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&service_status),
        sizeof(service_status), &bytes_needed))
    {
        return false;
    }

    return true;
    }
    catch (...) {}
}

void bam_state::print_service_state()
{
    try{
    if (service_status.dwCurrentState == SERVICE_RUNNING)
    {
        return;
    }

    interpret_service_state(service_status.dwCurrentState);
    }
    catch (...) {}
}


void bam_state::interpret_service_state(DWORD state)
{
    try{
    static const std::unordered_map<DWORD, std::string> stateMessages = {
        {SERVICE_STOPPED, xorstr_( "BAM Stopped" ) },
        {SERVICE_STOP_PENDING, xorstr_( "BAM Stopped" ) },
        {SERVICE_START_PENDING, xorstr_( "BAM Restarted" ) },
        {SERVICE_PAUSE_PENDING, xorstr_( "BAM Paused" ) },
        {SERVICE_PAUSED, xorstr_( "BAM Paused" ) },
    };

    auto it = stateMessages.find(state);
    const std::string& message = (it != stateMessages.end()) ? it->second : xorstr_( "BAM Offline" );

    LOG ( WARNING, xorstr_ ( "N/A" ) ) << xorstr_ ( "Service Modified:" ) << message.c_str();
    }
    catch (...) {}
}


void bam_state::start_bam_state_detection()
{
    try{
        if (!bam_state::open_sc_manager())
        {
            return;
        }

        if (!bam_state::open_service( xorstr_( L"bam" ) ) )
        {
            return;
        }

        if (!bam_state::query_service_status())
        {
            return;
        }

        bam_state::print_service_state();
    }
    catch (...) {}
}