#include "c_efi_detections.h"

bool EfiDetections::enable_privilege(const wchar_t* privilege) {
    try {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            return false;

        TOKEN_PRIVILEGES tp{};
        if (!LookupPrivilegeValueW(nullptr, privilege, &tp.Privileges[0].Luid)) {
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        DWORD lastError = GetLastError();
        CloseHandle(hToken);

        return lastError == ERROR_SUCCESS;
    }
    catch (...) { return false; }
}

DWORD EfiDetections::get_registry_secure_boot_state() {
    try {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            xorstr_("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"),
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return 0;

        DWORD value = 0;
        DWORD size = sizeof(DWORD);
        DWORD type = 0;
        result = RegQueryValueExA(
            hKey,
            xorstr_("UEFISecureBootEnabled"),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);

        if (result == ERROR_SUCCESS && type == REG_DWORD)
            return value;

        return 0;
    }
    catch (...) { return 0; }
}

bool EfiDetections::get_core_isolation_state() {
    try {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            xorstr_("SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return false;

        DWORD value = 0;
        DWORD size = sizeof(DWORD);
        DWORD type = 0;
        result = RegQueryValueExA(
            hKey,
            xorstr_("Enabled"),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        RegCloseKey(hKey);

        if (result == ERROR_SUCCESS && type == REG_DWORD)
            return value == 1;

        return false;
    }
    catch (...) { return false; }
}

std::string EfiDetections::get_registry_policy_publisher() {
    try {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            xorstr_("SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"),
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return "";

        char buffer[256]{};
        DWORD size = sizeof(buffer);
        DWORD type = 0;
        result = RegQueryValueExA(
            hKey,
            xorstr_("PolicyPublisher"),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(buffer),
            &size
        );

        RegCloseKey(hKey);

        if (result == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ)) {
            buffer[255] = '\0';
            return std::string(buffer);
        }

        return "";
    }
    catch (...) { return ""; }
}

bool EfiDetections::get_firmware_secure_boot_state() {
    try {
        enable_privilege(xorstr_(L"SeSystemEnvironmentPrivilege"));

        BYTE value = 0;
        DWORD ret = GetFirmwareEnvironmentVariableW(
            xorstr_(L"SecureBoot"),
            xorstr_(L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"),
            &value,
            sizeof(value)
        );

        if (ret == 0)
            return false;

        return value == 1;
    }
    catch (...) { return false; }
}

void EfiDetections::start_efi_detections() {
    try {
        DWORD regState = get_registry_secure_boot_state();
        bool firmwareState = get_firmware_secure_boot_state();

        if (!firmwareState) {
            LOG(WARNING, xorstr_("N/A")) << xorstr_("Secure Boot Disabled:EFI Firmware Reports Secure Boot Is Disabled On The System, This Is Common In EFI Bypasses.");
        }

        if (!get_core_isolation_state()) {
            LOG(WARNING, xorstr_("N/A")) << xorstr_("Core Isolation Disabled:Memory Integrity (HVCI) Is Turned Off, This Allows Unsigned And Vulnerable Drivers To Load.");
        }

        if (regState == 1 && !firmwareState) {
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("EFI Bypass:Secure Boot Mismatch - Registry Shows ON While Hardware Reports OFF");

            std::string publisher = get_registry_policy_publisher();
            if (publisher == xorstr_("{77fa9abd-0359-4d32-bd60-28f4e78f784b}")) {
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("EFI Bypass:Fake PolicyPublisher GUID Detected");
            }
        }
    }
    catch (...) {}
}