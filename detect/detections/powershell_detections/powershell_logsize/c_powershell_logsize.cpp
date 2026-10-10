#include "c_powershell_logsize.h"

bool PowerShellEventLogCheck::GetChannelMaxSizeBytes(const wchar_t* channelName, unsigned long long& outBytes)
{
    try{
    outBytes = 0;

    EVT_HANDLE hCfg = EvtOpenChannelConfig(nullptr, channelName, 0);
    if (!hCfg)
        return false;

    DWORD bufferUsed = 0;

    if (!EvtGetChannelConfigProperty(
        hCfg,
        EvtChannelLoggingConfigMaxSize,
        0,
        0,
        nullptr,
        &bufferUsed))
    {
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            EvtClose(hCfg);
            return false;
        }
    }

    PEVT_VARIANT v = (PEVT_VARIANT)std::malloc(bufferUsed);
    if (!v)
    {
        EvtClose(hCfg);
        return false;
    }

    if (!EvtGetChannelConfigProperty(
        hCfg,
        EvtChannelLoggingConfigMaxSize,
        0,
        bufferUsed,
        v,
        &bufferUsed))
    {
        std::free(v);
        EvtClose(hCfg);
        return false;
    }

    bool ok = false;
    if (v->Type == EvtVarTypeUInt64)
    {
        outBytes = v->UInt64Val;
        ok = true;
    }
    else if (v->Type == EvtVarTypeUInt32)
    {
        outBytes = static_cast<unsigned long long>(v->UInt32Val);
        ok = true;
    }

    std::free(v);
    EvtClose(hCfg);
    return ok;
    }
    catch (...) {}
}

bool PowerShellEventLogCheck::IsMaxSize1028KB()
{
    try{
    const unsigned long long targetBytes = 1028ULL * 1024ULL;

    const wchar_t* channels[] =
    {
        xorstr_(L"Windows PowerShell"),
        xorstr_(L"Microsoft-Windows-PowerShell/Operational")
    };

    for (const auto* ch : channels)
    {
        unsigned long long maxBytes = 0;
        if (GetChannelMaxSizeBytes(ch, maxBytes))
        {
            return maxBytes == targetBytes;
        }
    }

    return false;
    }
    catch (...) {}
}

void PowerShellEventLogCheck::start_powershell_logsize_check()
{
    try{
    if (PowerShellEventLogCheck::IsMaxSize1028KB())
    {
        LOG ( WARNING , xorstr_("N/A")) << xorstr_("Powershell Bypass Flush Found:Windows PowerShell Eventlog Max Size Modified");
    }

    return;
    }
    catch (...) {}
}