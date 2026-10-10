#include "c_dma_protection.h"

void dma_protection_scan::check_kernel_dma_protection() {
    try {
        HKEY hKey = nullptr;
        LONG status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\DmaGuard\\Scenarios\\Default"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey);

        if (status != ERROR_SUCCESS || !hKey)
            return;

        DWORD enabled = 0;
        DWORD size    = sizeof(enabled);
        DWORD type    = 0;

        LONG queryStatus = RegQueryValueExW(
            hKey,
            xorstr_(L"Enabled"),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&enabled),
            &size);

        RegCloseKey(hKey);

        if (queryStatus != ERROR_SUCCESS || type != REG_DWORD)
            return;

        if (enabled != 1) {
            LOG(INFO, xorstr_("N/A")) << xorstr_("Kernel DMA Protection (DMA Guard) Disabled:")
                << xorstr_("System RAM is exposed to hardware-level DMA attacks (IOMMU sandboxing inactive for the current boot session).");
        }
    }
    catch (...) {}
}

void dma_protection_scan::check_iommu_fault_events() {
    EVT_HANDLE hResults = nullptr;

    try {
        // Both string args are inlined so the temporary xor_string objects
        // returned by xorstr_(...) live until EvtQuery returns. Caching the
        // pointer in a local would leave it dangling into freed stack storage.
        hResults = EvtQuery(
            nullptr,
            xorstr_(L"System"),
            xorstr_(
                L"*[System[Provider[@Name='Microsoft-Windows-Kernel-IoIommu'] and "
                L"(EventID=7 or EventID=8 or EventID=12)]]"),
            EvtQueryChannelPath | EvtQueryReverseDirection);

        if (!hResults)
            return;

        EVT_HANDLE hEvent  = nullptr;
        DWORD dwReturned   = 0;

        if (EvtNext(hResults, 1, &hEvent, 2000, 0, &dwReturned)
            && dwReturned > 0
            && hEvent) {
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("IOMMU Hardware Block Detected:")
                << xorstr_("A physical device attempted to bypass memory protections and was blocked by the Windows Kernel (IOMMU fault). Definitive indicator of a DMA device.");
            EvtClose(hEvent);
        }
    }
    catch (...) {}

    if (hResults)
        EvtClose(hResults);
}

void dma_protection_scan::start_dma_protection() {
    try {
        check_kernel_dma_protection();
        check_iommu_fault_events();
    }
    catch (...) {}
}
