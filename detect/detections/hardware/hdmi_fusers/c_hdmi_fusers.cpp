#include "c_hdmi_fusers.h"

bool MonitorEDID::ValidateEDIDChecksum(const std::vector<uint8_t>& edid) {
    try{
    uint8_t sum = 0;
    for (size_t i = 0; i < 128; i++)
        sum += edid[i];
    return (sum % 256) == 0;
    }
    catch (...) {}
    return false;
}

void MonitorEDID::PrintManufacturerID(const std::vector<uint8_t>& edid) {
    try{
    char manufacturer[4] = {
        (char)(((edid[8] >> 2) & 31) + 'A' - 1),
        (char)(((edid[8] & 3) << 3 | (edid[9] >> 5)) + 'A' - 1),
        (char)((edid[9] & 31) + 'A' - 1),
        '\0'
    };
    }
    catch (...) {}
}

void MonitorEDID::ValidateEDID(const std::vector<uint8_t>& edid) {
    try{
    if (edid.size() != 128) {
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Possible Spoofed HDMI Fuser Plugged In: Invalid EDID Size");
        return;
    }

    if (!ValidateEDIDChecksum(edid))
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Possible Spoofed HDMI Fuser Plugged In: Invalid EDID Checksum");

    PrintManufacturerID(edid);

    uint16_t productCode = edid[10] | (edid[11] << 8);
    uint32_t serialNumber = edid[12] | (edid[13] << 8) | (edid[14] << 16) | (edid[15] << 24);

    uint16_t h_res = ((edid[56] + ((edid[58] & 0xF0) << 4)));
    uint16_t v_res = ((edid[59] + ((edid[61] & 0xF0) << 4)));

    if (h_res < 640 || v_res < 480)
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Possible Spoofed HDMI Fuser Plugged In: Unusually Low Resolution");
    }
    catch (...) {}
}

void MonitorEDID::GetMonitorEDID() {
    try{
    HDEVINFO hDevInfo;
    SP_DEVINFO_DATA DeviceInfoData;
    DWORD i;

    hDevInfo = SetupDiGetClassDevs(&GUID_DEVCLASS_MONITOR, 0, 0, DIGCF_PRESENT);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        return;
    }

    DeviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    for (i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &DeviceInfoData); i++) {
        HKEY hKey = SetupDiOpenDevRegKey(hDevInfo, &DeviceInfoData, DICS_FLAG_GLOBAL, 0, DIREG_DEV, KEY_READ);
        if (hKey == INVALID_HANDLE_VALUE)
            continue;

        BYTE edidData[128] = { 0 };
        DWORD dataSize = sizeof(edidData);
        DWORD regType;

        if (RegQueryValueExA(hKey, xorstr_("EDID"), NULL, &regType, edidData, &dataSize) == ERROR_SUCCESS && dataSize == 128) {
            std::vector<uint8_t> edid(edidData, edidData + 128);
            ValidateEDID(edid);
        }

        RegCloseKey(hKey);
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    }
    catch (...) {}
}

void MonitorEDID::start_hdmifuser_scan() {
    try{
    MonitorEDID::GetMonitorEDID();
    return;
    }
    catch (...) {}
}