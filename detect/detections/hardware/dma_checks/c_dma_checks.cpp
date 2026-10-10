#include "c_dma_checks.h"

bool PCIDeviceScanner::IsDMARelated(const std::string& text) {
    try{
    std::string lowerText = text;
    std::transform(lowerText.begin(), lowerText.end(), lowerText.begin(), ::tolower);

    return (lowerText.find(xorstr_("direct memory access")) != std::string::npos) ||
        (lowerText.find(xorstr_("kmbox")) != std::string::npos) ||
        (lowerText.find(xorstr_("fuser")) != std::string::npos);
    }
    catch (...) { return false; }
}

bool PCIDeviceScanner::CheckForDMAKeywords(const std::string& vendorName, const std::string& deviceName) {
    try{
    return IsDMARelated(vendorName) || IsDMARelated(deviceName);
    }
    catch (...) { return false; }
}

std::vector<PCIDevice> PCIDeviceScanner::ExtractPCIDevicesFromRegistry() {
    try{
    std::vector<PCIDevice> devices;
    const wchar_t* registryPaths[] = {
        xorstr_(L"SYSTEM\\CurrentControlSet\\Enum\\PCI"),
        xorstr_(L"SYSTEM\\CurrentControlSet\\Enum\\PCIIDE")
    };

    for (const wchar_t* rootPath : registryPaths) {
        HKEY hRootKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, rootPath, 0, KEY_READ, &hRootKey) != ERROR_SUCCESS) {
            continue;
        }

        wchar_t vendorKeyName[256];
        for (DWORD vendorIndex = 0; ; vendorIndex++) {
            DWORD vendorNameSize = 256;
            if (RegEnumKeyExW(hRootKey, vendorIndex, vendorKeyName, &vendorNameSize,
                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                break;
            }

            std::wstring vendorKeyPath = std::wstring(rootPath) + xorstr_(L"\\") + vendorKeyName;
            HKEY hVendorKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, vendorKeyPath.c_str(), 0, KEY_READ, &hVendorKey) != ERROR_SUCCESS) {
                continue;
            }

            wchar_t deviceKeyName[256];
            for (DWORD deviceIndex = 0; ; deviceIndex++) {
                DWORD deviceNameSize = 256;
                if (RegEnumKeyExW(hVendorKey, deviceIndex, deviceKeyName, &deviceNameSize,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    break;
                }

                PCIDevice dev;
                dev.detectionSource = xorstr_("registry");
                std::wstring vendorID(vendorKeyName);
                std::wstring deviceID(deviceKeyName);

                size_t venPos = vendorID.find(xorstr_(L"VEN_"));
                size_t devPos = vendorID.find(xorstr_(L"DEV_"));

                if (venPos != std::wstring::npos && devPos != std::wstring::npos) {
                    dev.vendorID = ascii_wstring_to_string(std::wstring(vendorID, venPos + 4, 4));
                    dev.deviceID = ascii_wstring_to_string(std::wstring(vendorID, devPos + 4, 4));
                    dev.detectionSource = xorstr_("registry");

                    std::transform(dev.vendorID.begin(), dev.vendorID.end(), dev.vendorID.begin(), ::toupper);
                    std::transform(dev.deviceID.begin(), dev.deviceID.end(), dev.deviceID.begin(), ::toupper);

                    if (!dev.vendorID.empty() && !dev.deviceID.empty()) {
                        if (deviceCache.find(dev.vendorID) == deviceCache.end() ||
                            deviceCache[dev.vendorID].find(dev.deviceID) == deviceCache[dev.vendorID].end()) {
                            devices.push_back(dev);
                        }
                    }
                }
            }
            RegCloseKey(hVendorKey);
        }
        RegCloseKey(hRootKey);
    }
    return devices;
    }
    catch (...) { return {}; }
}

bool PCIDeviceScanner::DownloadPCIDatabaseToMemory() {
    try{
    HINTERNET hSession = WinHttpOpen(xorstr_(L"PCI ID Fetcher/1.0"),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 10000);

    HINTERNET hConnect = WinHttpConnect(hSession, xorstr_(L"pci-ids.ucw.cz"),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, xorstr_(L"GET"), xorstr_(L"/v2.2/pci.ids"),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    std::string responseData;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

        pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer) break;

        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            delete[] pszOutBuffer;
            break;
        }

        responseData.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    std::istringstream onlineData(responseData);
    std::string line;
    std::string currentVendor;

    while (std::getline(onlineData, line)) {
        if (line.empty() || line[0] == '#') continue;

        if (line[0] != '\t') {
            std::istringstream iss(line);
            std::string vid, vname;
            iss >> vid;
            std::getline(iss, vname);
            pciDB[vid][xorstr_("vendor")] = vname;
            currentVendor = vid;
        }
        else if (line[0] == '\t' && line[1] != '\t') {
            std::istringstream iss(line.substr(1));
            std::string pid, pname;
            iss >> pid;
            std::getline(iss, pname);
            pciDB[currentVendor][pid] = pname;
        }
    }

    return true;
    }
    catch (...) { return false; }
}

bool PCIDeviceScanner::CheckDeviceHunt(const std::string& vendorID, const std::string& deviceID, std::string& responseData) {
    try{
    HINTERNET hSession = WinHttpOpen(xorstr_(L"DeviceHunt Checker/1.0"),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 10000);

    std::string searchPath = xorstr_("/search/type/pci/vendor/") + vendorID + xorstr_("/device/") + deviceID;
    std::wstring widePath(searchPath.begin(), searchPath.end());

    HINTERNET hConnect = WinHttpConnect(hSession, xorstr_(L"devicehunt.com"),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, xorstr_(L"GET"), widePath.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

        pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer) break;

        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            delete[] pszOutBuffer;
            break;
        }

        responseData.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return (responseData.find(xorstr_("Sorry your search turned up no results.")) == std::string::npos);
    }
    catch (...) { return false; }
}

bool PCIDeviceScanner::CheckLinuxHardware(const std::string& vendorID, const std::string& deviceID, std::string& responseData) {
    try{
    HINTERNET hSession = WinHttpOpen(xorstr_(L"LinuxHardware Checker/1.0"),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;
    WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 10000);

    std::string searchPath = xorstr_("/?id=pci:") + vendorID + xorstr_("-") + deviceID;
    std::wstring widePath(searchPath.begin(), searchPath.end());

    HINTERNET hConnect = WinHttpConnect(hSession, xorstr_(L"linux-hardware.org"),
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, xorstr_(L"GET"), widePath.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;

        pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer) break;

        ZeroMemory(pszOutBuffer, dwSize + 1);
        if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            delete[] pszOutBuffer;
            break;
        }

        responseData.append(pszOutBuffer, dwDownloaded);
        delete[] pszOutBuffer;
    } while (dwSize > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return (responseData.find(xorstr_("images/404.png")) == std::string::npos);
    }
    catch (...) { return false; }
}

std::vector<PCIDevice> PCIDeviceScanner::ExtractPCIDevicesFromLogs() {
    try{
    std::vector<PCIDevice> devices;

    const std::wstring channelNames[] = {
        xorstr_(L"Microsoft-Windows-Kernel-PnP/Configuration")
    };

    EVT_HANDLE hResults = NULL;

    for (const std::wstring& channel : channelNames) {
        std::wstring query = xorstr_(
            L"<QueryList>"
            L"  <Query Id='0'>"
            L"    <Select Path='%s'>"
            L"      *[System[Provider[@Name='Microsoft-Windows-Kernel-PnP']]]"
            L"    </Select>"
            L"  </Query>"
            L"</QueryList>");

        wchar_t formattedQuery[2048];
        swprintf_s(formattedQuery, query.c_str(), channel.c_str());

        hResults = EvtQuery(NULL, NULL, formattedQuery, EvtQueryChannelPath | EvtQueryReverseDirection);
        if (hResults) break;
    }

    if (!hResults) {
        return devices;
    }

    EVT_HANDLE hEvent;
    DWORD returned = 0;

    while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &returned) && returned) {
        DWORD bufferSize = 0;
        DWORD propertyCount = 0;

        if (!EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, NULL, &bufferSize, &propertyCount)) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) continue;

            std::vector<wchar_t> buffer(bufferSize / sizeof(wchar_t));
            if (EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer.data(), &bufferSize, &propertyCount)) {
                std::wstring xml(buffer.begin(), buffer.end());

                size_t venPos = xml.find(xorstr_(L"PCI\\VEN_"));
                while (venPos != std::wstring::npos) {
                    PCIDevice dev;
                    dev.detectionSource = xorstr_("logs");
                    dev.vendorID = ascii_wstring_to_string(std::wstring(xml, venPos + 8, 4));
                    std::transform(dev.vendorID.begin(), dev.vendorID.end(), dev.vendorID.begin(), ::toupper);

                    size_t devPos = xml.find(xorstr_(L"DEV_"), venPos);
                    if (devPos != std::wstring::npos) {
                        dev.deviceID = ascii_wstring_to_string(std::wstring(xml, devPos + 4, 4));
                        std::transform(dev.deviceID.begin(), dev.deviceID.end(), dev.deviceID.begin(), ::toupper);
                    }

                    size_t timePos = xml.find(xorstr_(L"<TimeCreated SystemTime='"));
                    if (timePos != std::wstring::npos) {
                        dev.timestamp = ascii_wstring_to_string(std::wstring(xml, timePos + 24, 19));
                    }

                    if (!dev.vendorID.empty() && !dev.deviceID.empty()) {
                        if (deviceCache.find(dev.vendorID) == deviceCache.end() ||
                            deviceCache[dev.vendorID].find(dev.deviceID) == deviceCache[dev.vendorID].end()) {
                            devices.push_back(dev);
                        }
                    }

                    venPos = xml.find(xorstr_(L"PCI\\VEN_"), venPos + 1);
                }
            }
        }
        EvtClose(hEvent);
    }

    EvtClose(hResults);
    return devices;
    }
    catch (...) { return {}; }
}

struct HardcodedHit {
    const char* label;
    bool isDmaRelated;
};

static const std::unordered_map<std::string, HardcodedHit> kHardcodedIds = {
    { xorstr_("25A7:5864"), { xorstr_("Arduino Mouse Emulator Found"), true  } },
};

static std::string MakeKeyUpper(std::string vid, std::string pid) {
    try{
    std::transform(vid.begin(), vid.end(), vid.begin(), ::toupper);
    std::transform(pid.begin(), pid.end(), pid.begin(), ::toupper);
    return vid + xorstr_(":") + pid;
    }
    catch (...) { return {}; }
}

bool PCIDeviceScanner::IsWhitelisted(const std::string& vendorID, const std::string& deviceID) {
    try{
    static const std::vector<std::pair<std::string, std::string>> whitelist = {
        {xorstr_("0000"), xorstr_("0000")},
    };

    for (const auto& item : whitelist) {
        if (vendorID == item.first && deviceID == item.second) {
            return true;
        }
    }
    return false;
    }
    catch (...) { return false; }
}

void PCIDeviceScanner::VerifyDevice(PCIDevice& dev) {
    try {
        if (IsWhitelisted(dev.vendorID, dev.deviceID)) {
            dev.isKnown = true;
            dev.verificationSource = xorstr_("whitelist");
            deviceCache[dev.vendorID][dev.deviceID] = dev;
            return;
        }

        {
            const std::string key = MakeKeyUpper(dev.vendorID, dev.deviceID);
            auto it = kHardcodedIds.find(key);
            if (it != kHardcodedIds.end()) {
                dev.isKnown = true;
                dev.verificationSource = xorstr_("hardcoded");
                dev.vendorName = it->second.label;
                dev.deviceName.clear();

                deviceCache[dev.vendorID][dev.deviceID] = dev;

                if (it->second.isDmaRelated) {
                    LOG(DETECTION, xorstr_("N/A"))
                        << dev.vendorName << xorstr_(":Vendor ID: ")
                        << dev.vendorID
                        << xorstr_(" Device ID: ")
                        << dev.deviceID;
                }
                return;
            }
        }

        if (deviceCache[dev.vendorID].count(dev.deviceID) > 0) {
            dev = deviceCache[dev.vendorID][dev.deviceID];

            if (dev.isKnown && IsDMARelated(dev.vendorName + dev.deviceName)) {
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("DMA Found [BETA]: Vendor ID: ") << dev.vendorID << xorstr_(" Device ID: ") << dev.deviceID
                    << xorstr_(" - ") << dev.vendorName << xorstr_(" ") << dev.deviceName;
            }
            return;
        }

        auto vendorIt = pciDB.find(dev.vendorID);
        if (vendorIt != pciDB.end()) {
            dev.vendorName = vendorIt->second[xorstr_("vendor")];

            auto deviceIt = vendorIt->second.find(dev.deviceID);
            if (deviceIt != vendorIt->second.end()) {
                dev.deviceName = deviceIt->second;
                dev.isKnown = true;
                dev.verificationSource = xorstr_("pci-ids.ucw.cz");

                if (CheckForDMAKeywords(dev.vendorName, dev.deviceName)) {
                    LOG(DETECTION, xorstr_("N/A")) << xorstr_("DMA Found [BETA]: Vendor ID: ") << dev.vendorID << xorstr_(" Device ID: ") << dev.deviceID
                        << xorstr_(" - ") << dev.vendorName << xorstr_(" ") << dev.deviceName;
                }

                deviceCache[dev.vendorID][dev.deviceID] = dev;
                return;
            }
        }

        std::string linuxResponse;
        if (CheckLinuxHardware(dev.vendorID, dev.deviceID, linuxResponse)) {
            dev.isKnown = true;
            dev.verificationSource = xorstr_("linux-hardware.org");

            if (IsDMARelated(linuxResponse)) {
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("DMA Found [BETA]: Vendor ID: ") << dev.vendorID
                    << xorstr_(" Device ID: ") << dev.deviceID;
            }

            deviceCache[dev.vendorID][dev.deviceID] = dev;
            return;
        }

        std::string deviceHuntResponse;
        if (CheckDeviceHunt(dev.vendorID, dev.deviceID, deviceHuntResponse)) {
            dev.isKnown = true;
            dev.verificationSource = xorstr_("devicehunt.com");

            if (IsDMARelated(deviceHuntResponse)) {
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("DMA Found [BETA]: Vendor ID: ") << dev.vendorID
                    << xorstr_(" Device ID: ") << dev.deviceID;
            }

            deviceCache[dev.vendorID][dev.deviceID] = dev;
            return;
        }

        dev.verificationSource = xorstr_("none");
        deviceCache[dev.vendorID][dev.deviceID] = dev;
        LOG(WARNING, xorstr_("N/A")) << xorstr_("Possible Spoofed DMA Found [BETA]: Vendor ID: ") << dev.vendorID << xorstr_(" Device ID: ") << dev.deviceID;
    }
    catch (...) {}
}

void PCIDeviceScanner::start_pci_scanning() {
    try{
    auto start_time = std::chrono::steady_clock::now();
    const auto timeout = std::chrono::minutes(3);

    if (!DownloadPCIDatabaseToMemory()) {
        return;
    }

    if (std::chrono::steady_clock::now() - start_time > timeout) {
        return;
    }

    std::vector<PCIDevice> logDevices = ExtractPCIDevicesFromLogs();

    if (std::chrono::steady_clock::now() - start_time > timeout) {
        return;
    }

    std::vector<PCIDevice> regDevices = ExtractPCIDevicesFromRegistry();

    if (std::chrono::steady_clock::now() - start_time > timeout) {
        return;
    }

    std::set<std::pair<std::string, std::string>> processedDevices;
    std::vector<PCIDevice> allDevices;

    auto addUniqueDevice = [&](const PCIDevice& dev) {
        auto key = std::make_pair(dev.vendorID, dev.deviceID);
        if (processedDevices.find(key) == processedDevices.end()) {
            allDevices.push_back(dev);
            processedDevices.insert(key);
        }
        };

    for (auto& dev : logDevices) addUniqueDevice(dev);
    for (auto& dev : regDevices) addUniqueDevice(dev);

    for (auto& dev : allDevices) {
        VerifyDevice(dev);

        if (std::chrono::steady_clock::now() - start_time > timeout) {
            return;
        }

        if (dev.verificationSource != xorstr_("pci-ids.ucw.cz")) {
            Sleep(200);

            if (std::chrono::steady_clock::now() - start_time > timeout) {
                return;
            }
        }
    }
    }
    catch (...) {}
}