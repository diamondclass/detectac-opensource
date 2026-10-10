#include "c_usb_bypass_registry.h"

bool UsbBypassRegistry::KeyExists(HKEY hRoot, const wchar_t* subKey)
{
    try {
        HKEY hKey = nullptr;
        LONG status = RegOpenKeyExW(hRoot, subKey, 0,
            KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (status == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        if (status == ERROR_FILE_NOT_FOUND ||
            status == ERROR_PATH_NOT_FOUND ||
            status == ERROR_BAD_PATHNAME) {
            return false;
        }
        return true;
    }
    catch (...) { return true; }
}

void UsbBypassRegistry::start_usb_bypass_check()
{
    try {
        auto checkOne = [](const wchar_t* widePath, const char* narrowDisplay) {
            if (!KeyExists(HKEY_LOCAL_MACHINE, widePath)) {
                LOG(DETECTION, xorstr_("N/A"))
                    << xorstr_("USB Bypass Detected:") << narrowDisplay
                    << xorstr_("USB Artifact Registry Key Has Been Manually Cleaned");
            }
        };

        checkOne(
            xorstr_(L"SYSTEM\\CurrentControlSet\\Enum\\USB"),
            xorstr_("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB"));

        checkOne(
            xorstr_(L"SYSTEM\\MountedDevices"),
            xorstr_("HKLM\\SYSTEM\\MountedDevices"));

        checkOne(
            xorstr_(L"SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache"),
            xorstr_("HKLM\\SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache"));

        checkOne(
            xorstr_(L"SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"),
            xorstr_("HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"));
    }
    catch (...) {}
}
