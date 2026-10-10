#pragma once

#include "../../../pch.h"

class dma_protection_scan {

public:

    // Checks the HKLM\SYSTEM\CurrentControlSet\Control\DmaGuard\Scenarios\Default
    // "Enabled" DWORD. If the OS supports Kernel DMA Protection but it is turned
    // off for the current boot session, emits a warning.
    static void check_kernel_dma_protection();

    // Queries the System event log for Microsoft-Windows-Kernel-IoIommu
    // EventID 7, 8 or 12 (IOMMU page-fault / DMA-remapping fault / external
    // device blocked). The mere existence of any such event is treated as a
    // hard detection - this is what the kernel logs when a PCIe / Thunderbolt
    // device tries to read or write memory it doesn't own (textbook DMA card).
    static void check_iommu_fault_events();

    static void start_dma_protection();

};

inline auto c_dma_protection = std::make_unique<dma_protection_scan>();
