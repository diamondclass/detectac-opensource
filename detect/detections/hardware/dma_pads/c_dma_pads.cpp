#include "c_dma_pads.h"

std::string dma_pads_scan::Narrow(const std::wstring& w) {
    try {
        if (w.empty()) return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0, nullptr, nullptr);
        if (n <= 0) return {};
        std::string s(n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
        return s;
    }
    catch (...) { return {}; }
}

std::wstring dma_pads_scan::WideUpper(std::wstring s) {
    try {
        CharUpperBuffW(s.data(), static_cast<DWORD>(s.size()));
        return s;
    }
    catch (...) { return s; }
}

bool dma_pads_scan::IsGuidAllFF(const GUID& g) {
    try {
        auto p = reinterpret_cast<const BYTE*>(&g);
        for (size_t i = 0; i < sizeof(GUID); i++)
            if (p[i] != 0xFF) return false;
        return true;
    }
    catch (...) { return false; }
}

std::string dma_pads_scan::ParseHexField(const std::wstring& hwId, const wchar_t* prefix) {
    try {
        std::wstring u = WideUpper(hwId);
        std::wstring pfx = WideUpper(std::wstring(prefix));
        auto pos = u.find(pfx);
        if (pos == std::wstring::npos) return xorstr_("????");
        pos += pfx.size();
        std::wstring val;
        while (pos < u.size() && u[pos] != L'&' && u[pos] != L'\\')
            val += u[pos++];
        return Narrow(val);
    }
    catch (...) { return xorstr_("????"); }
}

std::wstring dma_pads_scan::ReadStr(HDEVINFO di, PSP_DEVINFO_DATA dd, const DEVPROPKEY* k) {
    try {
        DEVPROPTYPE t;
        DWORD sz = 0;
        SetupDiGetDevicePropertyW(di, dd, k, &t, nullptr, 0, &sz, 0);
        if (!sz) return {};
        std::vector<BYTE> buf(sz);
        if (!SetupDiGetDevicePropertyW(di, dd, k, &t, buf.data(), sz, nullptr, 0))
            return {};
        return (t == DEVPROP_TYPE_STRING || t == DEVPROP_TYPE_STRING_LIST)
            ? std::wstring(reinterpret_cast<wchar_t*>(buf.data()))
            : std::wstring{};
    }
    catch (...) { return {}; }
}

bool dma_pads_scan::ReadGuid(HDEVINFO di, PSP_DEVINFO_DATA dd, const DEVPROPKEY* k, GUID& v) {
    try {
        DEVPROPTYPE t;
        return SetupDiGetDevicePropertyW(di, dd, k, &t,
            reinterpret_cast<PBYTE>(&v), sizeof(v), nullptr, 0)
            && t == DEVPROP_TYPE_GUID;
    }
    catch (...) { return false; }
}

bool dma_pads_scan::CheckInstanceFF(const std::wstring& id) {
    try {
        auto pos = id.rfind(L'\\');
        if (pos == std::wstring::npos) return false;

        std::wstring tail = WideUpper(id.substr(pos + 1));
        int hexTotal = 0, fCount = 0;
        for (wchar_t c : tail) {
            bool isHex = (c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F');
            if (isHex) {
                hexTotal++;
                if (c == L'F') fCount++;
            }
        }
        return hexTotal >= 4 && (static_cast<float>(fCount) / hexTotal) > 0.5f;
    }
    catch (...) { return false; }
}

bool dma_pads_scan::CheckSubsysFF(const std::wstring& hwId) {
    try {
        std::wstring u = WideUpper(hwId);
        auto p = u.find(xorstr_(L"SUBSYS_"));
        if (p == std::wstring::npos || p + 15 > u.size()) return false;

        std::wstring sub = u.substr(p + 7, 8);
        if (sub == xorstr_(L"FFFFFFFF")) return true;
        if (sub.substr(0, 4) == xorstr_(L"FFFF") || sub.substr(4, 4) == xorstr_(L"FFFF")) return true;
        return false;
    }
    catch (...) { return false; }
}

bool dma_pads_scan::CheckRevFF(const std::wstring& hwId) {
    try {
        return WideUpper(hwId).find(xorstr_(L"REV_FF")) != std::wstring::npos;
    }
    catch (...) { return false; }
}

void dma_pads_scan::start_dma_pads() {
    SetConsoleOutputCP(CP_UTF8);

    HDEVINFO di = SetupDiGetClassDevsW(
        nullptr, xorstr_(L"PCI"), nullptr, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (di == INVALID_HANDLE_VALUE) return;

    int found = 0;

    try {
        SP_DEVINFO_DATA dd{};
        dd.cbSize = sizeof(dd);

        for (DWORD idx = 0; SetupDiEnumDeviceInfo(di, idx, &dd); idx++) {
            try {
                std::wstring instanceId = ReadStr(di, &dd, &DEVPKEY_Device_InstanceId);
                std::wstring hwId = ReadStr(di, &dd, &DEVPKEY_Device_HardwareIds);

                bool flagged = false;

                if (CheckInstanceFF(instanceId))  flagged = true;
                if (CheckSubsysFF(hwId))          flagged = true;
                if (CheckRevFF(hwId))             flagged = true;

                GUID containerId{};
                if (ReadGuid(di, &dd, &DEVPKEY_Device_ContainerId, containerId))
                    if (IsGuidAllFF(containerId)) flagged = true;

                if (flagged) {
                    std::wstring name = ReadStr(di, &dd, &DEVPKEY_NAME);
                    if (name.empty()) name = ReadStr(di, &dd, &DEVPKEY_Device_DeviceDesc);

                    std::string vendorId = ParseHexField(hwId, xorstr_(L"VEN_"));
                    std::string deviceId = ParseHexField(hwId, xorstr_(L"DEV_"));

                    LOG ( WARNING , xorstr_("N/A")) << xorstr_("Possible Spoofed DMA Found:")
                        << Narrow(name) << xorstr_(" - Vendor ID: ") << vendorId << xorstr_(" - Device ID: ") << deviceId;
                    found++;
                }
            }
            catch (...) { continue; }
        }
    }
    catch (...) {}

    SetupDiDestroyDeviceInfoList(di);
}