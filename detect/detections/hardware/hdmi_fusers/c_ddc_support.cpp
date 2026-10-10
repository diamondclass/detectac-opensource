#include "c_ddc_support.h"


BOOL CALLBACK c_ddc_support::MonitorEnumProc(HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) {
    try{
    DWORD monitorCount;
    if (!GetNumberOfPhysicalMonitorsFromHMONITOR(hMonitor, &monitorCount)) {
        return TRUE;
    }

    std::vector<PHYSICAL_MONITOR> physicalMonitors(monitorCount);
    if (!GetPhysicalMonitorsFromHMONITOR(hMonitor, monitorCount, physicalMonitors.data())) {
        return TRUE;
    }

    for (DWORD i = 0; i < monitorCount; ++i) {
        DWORD capabilities = 0, colorTemperatures = 0;
        if (GetMonitorCapabilities(physicalMonitors[i].hPhysicalMonitor, &capabilities, &colorTemperatures)) {
            std::wcout << xorstr_(L"Monitor: ") << physicalMonitors[i].szPhysicalMonitorDescription << std::endl;
            if (!(capabilities & MC_CAPS_BRIGHTNESS)) {
                LOG ( WARNING , xorstr_("N/A")) << xorstr_("Possible HDMI Fuser Detected [BETA]:DDC/CI not supported");
            }
        }
        DestroyPhysicalMonitors(1, &physicalMonitors[i]);
    }

    return TRUE;
    }
    catch (...) {}
    return FALSE;
}

void c_ddc_support::start_ddc_scan() {
    try{
    if (!EnumDisplayMonitors(NULL, NULL, MonitorEnumProc, 0)) {
        return;
    }
    return;
    }
    catch (...) {}
}