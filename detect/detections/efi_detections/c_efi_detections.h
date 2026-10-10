#pragma once

#include "../../pch.h"

class EfiDetections {
public:
    static void start_efi_detections();

private:
    static DWORD get_registry_secure_boot_state();
    static bool get_core_isolation_state();
    static std::string get_registry_policy_publisher();
    static bool get_firmware_secure_boot_state();
    static bool enable_privilege(const wchar_t* privilege);
};

inline auto c_efidet = std::make_unique<EfiDetections>();
