#pragma once

#include "../../../pch.h"

struct PCIDevice {
    std::string vendorID;
    std::string deviceID;
    std::string timestamp;
    std::string vendorName;
    std::string deviceName;
    std::string verificationSource;
    std::string detectionSource;
    bool isKnown = false;
};

class PCIDeviceScanner {
public:
    static bool DownloadPCIDatabaseToMemory();
    static std::vector<PCIDevice> ExtractPCIDevicesFromRegistry();
    static std::vector<PCIDevice> ExtractPCIDevicesFromLogs();
    static void VerifyDevice(PCIDevice& dev);
    static bool IsDMARelated(const std::string& text);
    static bool CheckForDMAKeywords(const std::string& vendorName, const std::string& deviceName);
    static bool CheckDeviceHunt(const std::string& vendorID, const std::string& deviceID, std::string& responseData);
    static bool CheckLinuxHardware(const std::string& vendorID, const std::string& deviceID, std::string& responseData);
    static inline std::map<std::string, std::map<std::string, std::string>> pciDB;
    static inline std::map<std::string, std::map<std::string, PCIDevice>> deviceCache;
    static bool IsWhitelisted(const std::string& vendorID, const std::string& deviceID);

    static void start_pci_scanning();
};

inline auto c_dma = std::make_unique<PCIDeviceScanner>();