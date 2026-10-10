#include "c_cfg_check.h"

void cfg_check::start_cfg_check()
{
    try {
        HKEY hKey = nullptr;
        LONG r = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\kernel"),
            0,
            KEY_QUERY_VALUE,
            &hKey);
        if (r != ERROR_SUCCESS) return;

        BYTE buf[64] = {};
        DWORD size = sizeof(buf);
        DWORD type = 0;
        r = RegQueryValueExW(
            hKey,
            xorstr_(L"MitigationOptions"),
            nullptr,
            &type,
            buf,
            &size);
        RegCloseKey(hKey);

        if (r != ERROR_SUCCESS) return;
        if (type != REG_BINARY) return;
        if (size < 4) return;

        const BYTE cfg_nibble = static_cast<BYTE>((buf[3] >> 4) & 0x0F);

        if (cfg_nibble == 2) {
            LOG(WARNING, xorstr_("N/A")) << xorstr_("Control Flow Guard (CFG) Is Disabled:This Is A Common Indicator Of MachoCheats Client");
        }
    }
    catch (...) {}
}
