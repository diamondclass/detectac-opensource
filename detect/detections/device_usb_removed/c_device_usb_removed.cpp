#include "c_device_usb_removed.h"

namespace fs = std::filesystem;

std::set<std::string> UsbEventLogger::seen_events;
std::map<UsbEventLogger::VidPidKey, std::set<std::string>> UsbEventLogger::g_index;

std::wstring UsbEventLogger::ToUpperW(std::wstring s)
{
    try {
        std::transform(s.begin(), s.end(), s.begin(),
            [](wchar_t c) { return static_cast<wchar_t>(std::towupper(c)); });
        return s;
    }
    catch (...) { return xorstr_(L""); }
}

std::wstring UsbEventLogger::TrimW(std::wstring s)
{
    try {
        auto notSpace = [](wchar_t c) { return !std::iswspace(c); };
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), notSpace));
        s.erase(std::find_if(s.rbegin(), s.rend(), notSpace).base(), s.end());
        return s;
    }
    catch (...) { return xorstr_(L""); }
}

std::string UsbEventLogger::Narrow(const std::wstring& w)
{
    try {
        if (w.empty()) return {};
        int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
            nullptr, 0, nullptr, nullptr);
        std::string s(static_cast<size_t>(n), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()),
            s.data(), n, nullptr, nullptr);
        return s;
    }
    catch (...) { return xorstr_(""); }
}

std::wstring UsbEventLogger::Widen(const std::string& s)
{
    try {
        if (s.empty()) return {};
        int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
            nullptr, 0);
        std::wstring w(static_cast<size_t>(n), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
            w.data(), n);
        return w;
    }
    catch (...) { return xorstr_(L""); }
}

std::wstring UsbEventLogger::StripInfPrefix(std::wstring v)
{
    try {
        auto sc = v.rfind(L';');
        if (sc != std::wstring::npos) v = v.substr(sc + 1);
        return TrimW(std::move(v));
    }
    catch (...) { return xorstr_(L""); }
}

std::wstring UsbEventLogger::ReadRegString(HKEY hKey, const wchar_t* valueName)
{
    try {
        DWORD type = 0;
        DWORD bytes = 0;
        LONG rc = RegQueryValueExW(hKey, valueName, nullptr, &type, nullptr, &bytes);
        if (rc != ERROR_SUCCESS || bytes == 0) return xorstr_(L"");
        if (type != REG_SZ && type != REG_EXPAND_SZ && type != REG_MULTI_SZ) return xorstr_(L"");

        std::wstring buf;
        buf.resize(bytes / sizeof(wchar_t) + 1, L'\0');
        rc = RegQueryValueExW(hKey, valueName, nullptr, &type,
            reinterpret_cast<LPBYTE>(buf.data()), &bytes);
        if (rc != ERROR_SUCCESS) return xorstr_(L"");
        while (!buf.empty() && buf.back() == L'\0') buf.pop_back();

        if (type == REG_MULTI_SZ) {
            std::wstring out, cur;
            for (wchar_t c : buf) {
                if (c == L'\0') {
                    if (!cur.empty()) {
                        if (!out.empty()) out += xorstr_(L" | ");
                        out += cur;
                        cur.clear();
                    }
                }
                else {
                    cur.push_back(c);
                }
            }
            if (!cur.empty()) {
                if (!out.empty()) out += xorstr_(L" | ");
                out += cur;
            }
            return out;
        }
        return buf;
    }
    catch (...) { return xorstr_(L""); }
}

std::vector<std::wstring> UsbEventLogger::EnumSubKeys(HKEY hKey)
{
    try {
        std::vector<std::wstring> out;
        DWORD i = 0;
        wchar_t name[512];
        DWORD nameLen = _countof(name);
        while (RegEnumKeyExW(hKey, i, name, &nameLen,
            nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            out.emplace_back(name, nameLen);
            ++i;
            nameLen = _countof(name);
        }
        return out;
    }
    catch (...) { return {}; }
}

const std::wregex& UsbEventLogger::VidRe()
{
    try { static const std::wregex r(xorstr_(L"VID[_&]([0-9A-Fa-f]{4})")); return r; }
    catch (...) { static const std::wregex e; return e; }
}
const std::wregex& UsbEventLogger::PidRe()
{
    try { static const std::wregex r(xorstr_(L"PID[_&]([0-9A-Fa-f]{4})")); return r; }
    catch (...) { static const std::wregex e; return e; }
}
const std::wregex& UsbEventLogger::RevRe()
{
    try { static const std::wregex r(xorstr_(L"REV[_&]([0-9A-Za-z.]+)")); return r; }
    catch (...) { static const std::wregex e; return e; }
}
const std::wregex& UsbEventLogger::VenRe()
{
    try { static const std::wregex r(xorstr_(L"VEN[_&]([A-Za-z0-9 ._-]+?)(?=[\\\\&]|$)")); return r; }
    catch (...) { static const std::wregex e; return e; }
}
const std::wregex& UsbEventLogger::DevRe()
{
    try { static const std::wregex r(xorstr_(L"DEV[_&]([0-9A-Fa-f]{4})")); return r; }
    catch (...) { static const std::wregex e; return e; }
}
const std::wregex& UsbEventLogger::ProdRe()
{
    try { static const std::wregex r(xorstr_(L"PROD[_&]([A-Za-z0-9 ._-]+?)(?=[\\\\&]|$)")); return r; }
    catch (...) { static const std::wregex e; return e; }
}
const std::wregex& UsbEventLogger::SubsysRe()
{
    try { static const std::wregex r(xorstr_(L"SUBSYS[_&]([0-9A-Fa-f]{8})")); return r; }
    catch (...) { static const std::wregex e; return e; }
}

std::wstring UsbEventLogger::ExtractToken(const std::wstring& s, const std::wregex& re)
{
    try {
        std::wsmatch m;
        if (std::regex_search(s, m, re) && m.size() >= 2) return m[1].str();
        return xorstr_(L"");
    }
    catch (...) { return xorstr_(L""); }
}

std::wstring UsbEventLogger::MakeKey(const std::wstring& bus,
    const std::wstring& vid,
    const std::wstring& pid)
{
    try {
        return bus + xorstr_(L"\\") + (vid.empty() ? xorstr_(L"?") : vid) +
            xorstr_(L":") + (pid.empty() ? xorstr_(L"?") : pid);
    }
    catch (...) { return xorstr_(L""); }
}

UsbEventLogger::DeviceRecord& UsbEventLogger::GetOrCreate(DeviceMap& m,
    const std::wstring& bus,
    const std::wstring& vid,
    const std::wstring& pid)
{
    try {
        auto k = MakeKey(bus, vid, pid);
        auto it = m.find(k);
        if (it == m.end()) {
            DeviceRecord r;
            r.bus = bus;
            r.vid = vid;
            r.pid = pid;
            it = m.emplace(std::move(k), std::move(r)).first;
        }
        return it->second;
    }
    catch (...) {
        static DeviceRecord fallback;
        return fallback;
    }
}

void UsbEventLogger::ExtractIds(const std::wstring& path,
    std::wstring& vid,
    std::wstring& pid,
    std::wstring& rev,
    std::wstring& subsys)
{
    try {
        const std::wstring upper = ToUpperW(path);
        vid = ExtractToken(upper, VidRe());
        pid = ExtractToken(upper, PidRe());
        if (vid.empty()) vid = ExtractToken(upper, VenRe());
        if (pid.empty()) {
            std::wstring d = ExtractToken(upper, DevRe());
            if (!d.empty()) pid = d;
            else            pid = ExtractToken(upper, ProdRe());
        }
        rev = ExtractToken(upper, RevRe());
        subsys = ExtractToken(upper, SubsysRe());
    }
    catch (...) {}
}

void UsbEventLogger::SplitMulti(const std::wstring& blob, std::set<std::wstring>& out)
{
    try {
        size_t pos = 0;
        while (pos <= blob.size()) {
            size_t next = blob.find(xorstr_(L" | "), pos);
            std::wstring tok = (next == std::wstring::npos)
                ? blob.substr(pos)
                : blob.substr(pos, next - pos);
            tok = TrimW(std::move(tok));
            if (!tok.empty()) out.insert(tok);
            if (next == std::wstring::npos) break;
            pos = next + 3;
        }
    }
    catch (...) {}
}

std::wstring UsbEventLogger::BusFromPath(const std::wstring& upper)
{
    try {
        if (upper.find(xorstr_(L"USBSTOR")) != std::wstring::npos) return xorstr_(L"USBSTOR");
        if (upper.find(xorstr_(L"USB")) != std::wstring::npos) return xorstr_(L"USB");
        if (upper.find(xorstr_(L"NVME")) != std::wstring::npos) return xorstr_(L"NVME");
        if (upper.find(xorstr_(L"SCSI")) != std::wstring::npos) return xorstr_(L"SCSI");
        if (upper.find(xorstr_(L"IDE")) != std::wstring::npos) return xorstr_(L"IDE");
        if (upper.find(xorstr_(L"PCI")) != std::wstring::npos) return xorstr_(L"PCI");
        if (upper.find(xorstr_(L"SD")) != std::wstring::npos) return xorstr_(L"SD");
        if (upper.find(xorstr_(L"MMC")) != std::wstring::npos) return xorstr_(L"MMC");
        return xorstr_(L"");
    }
    catch (...) { return xorstr_(L""); }
}

void UsbEventLogger::ScanEnumKey(DeviceMap& devices, size_t& deviceCount)
{
    try {
        HKEY hEnum = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\CurrentControlSet\\Enum"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hEnum);
        if (rc != ERROR_SUCCESS) return;

        auto buses = EnumSubKeys(hEnum);
        for (const auto& bus : buses) {
            HKEY hBus = nullptr;
            if (RegOpenKeyExW(hEnum, bus.c_str(), 0,
                KEY_READ | KEY_WOW64_64KEY, &hBus) != ERROR_SUCCESS) {
                continue;
            }

            auto hwIds = EnumSubKeys(hBus);
            for (const auto& hw : hwIds) {
                HKEY hHw = nullptr;
                if (RegOpenKeyExW(hBus, hw.c_str(), 0,
                    KEY_READ | KEY_WOW64_64KEY, &hHw) != ERROR_SUCCESS) {
                    continue;
                }

                auto instances = EnumSubKeys(hHw);
                for (const auto& inst : instances) {
                    HKEY hInst = nullptr;
                    if (RegOpenKeyExW(hHw, inst.c_str(), 0,
                        KEY_READ | KEY_WOW64_64KEY, &hInst) != ERROR_SUCCESS) {
                        continue;
                    }

                    std::wstring fullPath = bus + xorstr_(L"\\") + hw + xorstr_(L"\\") + inst;
                    std::wstring vid, pid, rev, subsys;
                    ExtractIds(fullPath, vid, pid, rev, subsys);

                    auto& rec = GetOrCreate(devices,
                        ToUpperW(bus),
                        ToUpperW(vid),
                        ToUpperW(pid));
                    if (!rev.empty())    rec.revisions.insert(ToUpperW(rev));
                    if (!subsys.empty()) rec.subsystems.insert(ToUpperW(subsys));
                    rec.instancePaths.insert(fullPath);
                    rec.hardwareIds.insert(hw);
                    rec.sources.insert(xorstr_(L"Registry: HKLM\\SYSTEM\\CurrentControlSet\\Enum"));

                    std::wstring fn = ReadRegString(hInst, xorstr_(L"FriendlyName"));
                    std::wstring dd = ReadRegString(hInst, xorstr_(L"DeviceDesc"));
                    std::wstring mfg = ReadRegString(hInst, xorstr_(L"Mfg"));
                    std::wstring svc = ReadRegString(hInst, xorstr_(L"Service"));
                    std::wstring cls = ReadRegString(hInst, xorstr_(L"Class"));
                    std::wstring hids = ReadRegString(hInst, xorstr_(L"HardwareID"));
                    std::wstring cids = ReadRegString(hInst, xorstr_(L"CompatibleIDs"));
                    std::wstring loc = ReadRegString(hInst, xorstr_(L"LocationInformation"));

                    if (!fn.empty())  rec.friendlyNames.insert(StripInfPrefix(fn));
                    if (!dd.empty())  rec.deviceDescs.insert(StripInfPrefix(dd));
                    if (!mfg.empty()) rec.manufacturers.insert(StripInfPrefix(mfg));
                    if (!svc.empty()) rec.services.insert(svc);
                    if (!cls.empty()) rec.classNames.insert(cls);
                    if (!hids.empty()) SplitMulti(hids, rec.hardwareIds);
                    if (!cids.empty()) SplitMulti(cids, rec.compatibleIds);
                    (void)loc;

                    ++deviceCount;
                    RegCloseKey(hInst);
                }
                RegCloseKey(hHw);
            }
            RegCloseKey(hBus);
        }
        RegCloseKey(hEnum);
    }
    catch (...) {}
}

void UsbEventLogger::ScanMountedDevices(DeviceMap& devices)
{
    try {
        HKEY hMD = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\MountedDevices"), 0,
            KEY_READ | KEY_WOW64_64KEY, &hMD) != ERROR_SUCCESS) {
            return;
        }

        DWORD i = 0;
        std::vector<wchar_t> nameBuf(32768);
        std::vector<BYTE>    dataBuf(64 * 1024);

        for (;; ++i) {
            DWORD nameLen = static_cast<DWORD>(nameBuf.size());
            DWORD dataLen = static_cast<DWORD>(dataBuf.size());
            DWORD type = 0;
            LONG rc = RegEnumValueW(hMD, i, nameBuf.data(), &nameLen, nullptr,
                &type, dataBuf.data(), &dataLen);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;

            std::wstring vname(nameBuf.data(), nameLen);
            std::wstring devPath;
            if (type == REG_BINARY && dataLen >= 2 && (dataLen % 2) == 0) {
                devPath.assign(reinterpret_cast<const wchar_t*>(dataBuf.data()),
                    dataLen / 2);
                while (!devPath.empty() && devPath.back() == L'\0') devPath.pop_back();
            }

            std::wstring upper = ToUpperW(devPath);
            std::wstring vid, pid, rev, subsys;
            ExtractIds(devPath, vid, pid, rev, subsys);

            std::wstring bus = BusFromPath(upper);
            if (bus.empty() && vid.empty() && pid.empty()) continue;

            auto& rec = GetOrCreate(devices,
                bus.empty() ? xorstr_(L"MOUNT") : bus,
                ToUpperW(vid), ToUpperW(pid));
            rec.sources.insert(xorstr_(L"Registry: HKLM\\SYSTEM\\MountedDevices"));
            if (!devPath.empty()) rec.instancePaths.insert(devPath);
            if (!rev.empty())     rec.revisions.insert(ToUpperW(rev));

            const wchar_t* dosPrefix = xorstr_(L"\\DosDevices\\");
            const wchar_t* volumePrefix = xorstr_(L"\\??\\Volume");
            if (vname.rfind(dosPrefix, 0) == 0) {
                rec.driveLetters.insert(vname.substr(wcslen(dosPrefix)));
            }
            else if (vname.rfind(volumePrefix, 0) == 0) {
                rec.volumeIds.insert(vname);
            }
        }
        RegCloseKey(hMD);
    }
    catch (...) {}
}

void UsbEventLogger::ScanWpdDevices(DeviceMap& devices)
{
    try {
        HKEY hWpd = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hWpd) != ERROR_SUCCESS) {
            return;
        }

        auto keys = EnumSubKeys(hWpd);
        for (const auto& k : keys) {
            HKEY hDev = nullptr;
            if (RegOpenKeyExW(hWpd, k.c_str(), 0,
                KEY_READ | KEY_WOW64_64KEY, &hDev) != ERROR_SUCCESS) {
                continue;
            }
            std::wstring friendly = ReadRegString(hDev, xorstr_(L"FriendlyName"));

            std::wstring vid, pid, rev, subsys;
            ExtractIds(k, vid, pid, rev, subsys);
            std::wstring bus = BusFromPath(ToUpperW(k));

            if (!vid.empty() || !pid.empty() || !bus.empty()) {
                auto& rec = GetOrCreate(devices,
                    bus.empty() ? xorstr_(L"WPD") : bus,
                    ToUpperW(vid), ToUpperW(pid));
                if (!rev.empty()) rec.revisions.insert(ToUpperW(rev));
                if (!friendly.empty()) rec.friendlyNames.insert(friendly);
                rec.instancePaths.insert(k);
                rec.sources.insert(xorstr_(L"Registry: Windows Portable Devices"));
            }
            RegCloseKey(hDev);
        }
        RegCloseKey(hWpd);
    }
    catch (...) {}
}

void UsbEventLogger::ScanDeviceClasses(DeviceMap& devices)
{
    try {
        HKEY hRoot = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\DeviceClasses"),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &hRoot) != ERROR_SUCCESS) {
            return;
        }

        auto guids = EnumSubKeys(hRoot);
        for (const auto& g : guids) {
            HKEY hGuid = nullptr;
            if (RegOpenKeyExW(hRoot, g.c_str(), 0,
                KEY_READ | KEY_WOW64_64KEY, &hGuid) != ERROR_SUCCESS) {
                continue;
            }
            auto symlinks = EnumSubKeys(hGuid);
            for (const auto& sym : symlinks) {
                HKEY hSym = nullptr;
                if (RegOpenKeyExW(hGuid, sym.c_str(), 0,
                    KEY_READ | KEY_WOW64_64KEY, &hSym) != ERROR_SUCCESS) {
                    continue;
                }
                std::wstring devInst = ReadRegString(hSym, xorstr_(L"DeviceInstance"));

                std::wstring vid, pid, rev, subsys;
                ExtractIds(sym, vid, pid, rev, subsys);
                if (vid.empty() && pid.empty() && !devInst.empty()) {
                    ExtractIds(devInst, vid, pid, rev, subsys);
                }
                std::wstring bus = BusFromPath(ToUpperW(devInst.empty() ? sym : devInst));

                if (!vid.empty() || !pid.empty() || !bus.empty()) {
                    auto& rec = GetOrCreate(devices,
                        bus.empty() ? xorstr_(L"IFACE") : bus,
                        ToUpperW(vid), ToUpperW(pid));
                    if (!devInst.empty()) rec.instancePaths.insert(devInst);
                    if (!rev.empty())     rec.revisions.insert(ToUpperW(rev));
                    rec.sources.insert(xorstr_(L"Registry: Control\\DeviceClasses"));
                }
                RegCloseKey(hSym);
            }
            RegCloseKey(hGuid);
        }
        RegCloseKey(hRoot);
    }
    catch (...) {}
}

void UsbEventLogger::ScanSetupApiLog(DeviceMap& devices)
{
    try {
        fs::path logPath;
        wchar_t windir[MAX_PATH];
        if (GetWindowsDirectoryW(windir, MAX_PATH) > 0) {
            logPath = fs::path(windir) / xorstr_(L"INF") / xorstr_(L"setupapi.dev.log");
        }
        else {
            logPath = xorstr_(L"C:\\Windows\\INF\\setupapi.dev.log");
        }

        std::ifstream file(logPath, std::ios::binary);
        if (!file.is_open()) return;

        std::wregex sectionRe(
            xorstr_(LR"(\[Device Install \(([^)]+)\) - ([^\]]+)\])"),
            std::regex_constants::icase);

        std::string raw;
        while (std::getline(file, raw)) {
            if (!raw.empty() && raw.back() == '\r') raw.pop_back();
            if (raw.empty()) continue;
            if (raw.find(xorstr_("Device Install")) == std::string::npos) continue;

            std::wstring wline = Widen(raw);
            std::wsmatch m;
            if (!std::regex_search(wline, m, sectionRe) || m.size() < 3) continue;

            std::wstring path = m[2].str();
            std::wstring vid, pid, rev, subsys;
            ExtractIds(path, vid, pid, rev, subsys);

            std::wstring bus;
            auto bs = path.find(L'\\');
            if (bs != std::wstring::npos) bus = ToUpperW(path.substr(0, bs));
            if (bus.empty()) bus = BusFromPath(ToUpperW(path));
            if (bus.empty() && vid.empty() && pid.empty()) continue;

            auto& rec = GetOrCreate(devices, bus, ToUpperW(vid), ToUpperW(pid));
            rec.instancePaths.insert(path);
            if (!rev.empty()) rec.revisions.insert(ToUpperW(rev));
            rec.sources.insert(xorstr_(L"Log: setupapi.dev.log"));
        }
    }
    catch (...) {}
}

std::string UsbEventLogger::AsciiUpper(std::string s)
{
    try {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) {
                return static_cast<char>(std::toupper(c));
            });
        return s;
    }
    catch (...) { return xorstr_(""); }
}

void UsbEventLogger::BuildLookup()
{
    try {
        DeviceMap devices;
        size_t enumDeviceCount = 0;
        ScanEnumKey(devices, enumDeviceCount);
        ScanMountedDevices(devices);
        ScanWpdDevices(devices);
        ScanDeviceClasses(devices);
        ScanSetupApiLog(devices);

        g_index.clear();
        for (const auto& [_, r] : devices) {
            if (r.vid.empty() && r.pid.empty()) continue;
            VidPidKey key{ AsciiUpper(Narrow(r.vid)),
                           AsciiUpper(Narrow(r.pid)) };
            auto& names = g_index[key];
            for (const auto& fn : r.friendlyNames) {
                std::string s = Narrow(fn);
                if (!s.empty()) names.insert(s);
            }
            for (const auto& dd : r.deviceDescs) {
                std::string s = Narrow(dd);
                if (!s.empty()) names.insert(s);
            }
        }
    }
    catch (...) {}
}

std::vector<std::string> UsbEventLogger::LookupDeviceNames(const std::string& vid,
    const std::string& pid)
{
    try {
        VidPidKey key{ AsciiUpper(vid), AsciiUpper(pid) };
        auto it = g_index.find(key);
        if (it == g_index.end()) return {};
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }
    catch (...) { return {}; }
}

bool UsbEventLogger::is_duplicate_event(const std::string& vid, const std::string& pid, const std::string& local_time)
{
    try {
        std::string key = vid + xorstr_("|") + pid + xorstr_("|") + local_time;
        if (seen_events.find(key) != seen_events.end())
            return true;
        seen_events.insert(key);
        return false;
    }
    catch (...) { return false; }
}

std::string UsbEventLogger::wide_to_mb(const std::wstring& w)
{
    try {
        int size = WideCharToMultiByte(CP_THREAD_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size == 0) return std::string();
        std::string s(size, 0);
        WideCharToMultiByte(CP_THREAD_ACP, 0, w.c_str(), -1, &s[0], size, nullptr, nullptr);
        if (!s.empty() && s.back() == '\0') s.pop_back();
        return s;
    }
    catch (...) { return xorstr_(""); }
}

bool UsbEventLogger::extract_utc_timestring_from_xml(const std::wstring& xml, std::wstring& utc_time_out)
{
    try {
        size_t pos = xml.find(xorstr_(L"SystemTime="));
        if (pos == std::wstring::npos) return false;
        pos += wcslen(xorstr_(L"SystemTime="));
        size_t quote_pos = xml.find_first_of(xorstr_(L"\'\""), pos);
        if (quote_pos == std::wstring::npos) return false;
        wchar_t quote = xml[quote_pos];
        size_t start = quote_pos + 1;
        size_t end = xml.find(quote, start);
        if (end == std::wstring::npos) return false;
        utc_time_out = xml.substr(start, end - start);
        return true;
    }
    catch (...) { return false; }
}

bool UsbEventLogger::parse_iso8601_utc_to_systemtime(const std::wstring& s, SYSTEMTIME& st_utc)
{
    try {
        if (s.empty()) return false;
        size_t tpos = s.find(L'T');
        if (tpos == std::wstring::npos) return false;
        size_t tzpos = s.find_first_of(xorstr_(L"Z+-"), tpos);
        if (tzpos == std::wstring::npos) tzpos = s.size();
        std::wstring date_part = s.substr(0, tpos);
        int year = 0, month = 0, day = 0;
        if (swscanf_s(date_part.c_str(), xorstr_(L"%4d-%2d-%2d"), &year, &month, &day) != 3) return false;
        std::wstring time_part = s.substr(tpos + 1, tzpos - (tpos + 1));
        size_t dot = time_part.find(L'.');
        int hour = 0, minute = 0, second = 0;
        int millisecond = 0;
        if (dot == std::wstring::npos) {
            if (swscanf_s(time_part.c_str(), xorstr_(L"%2d:%2d:%2d"), &hour, &minute, &second) != 3) return false;
        }
        else {
            std::wstring time_no_frac = time_part.substr(0, dot);
            if (swscanf_s(time_no_frac.c_str(), xorstr_(L"%2d:%2d:%2d"), &hour, &minute, &second) != 3) return false;
            std::wstring frac = time_part.substr(dot + 1);
            if (frac.length() >= 3) millisecond = std::stoi(frac.substr(0, 3));
            else {
                std::wstring tmp = frac;
                while (tmp.length() < 3) tmp.push_back(L'0');
                millisecond = std::stoi(tmp);
            }
        }
        st_utc.wYear = (WORD)year;
        st_utc.wMonth = (WORD)month;
        st_utc.wDay = (WORD)day;
        st_utc.wHour = (WORD)hour;
        st_utc.wMinute = (WORD)minute;
        st_utc.wSecond = (WORD)second;
        st_utc.wMilliseconds = (WORD)millisecond;
        return true;
    }
    catch (...) { return false; }
}

std::string UsbEventLogger::format_systemtime_local(const SYSTEMTIME& st_local)
{
    try {
        char buf[64];
        sprintf_s(buf, sizeof(buf), xorstr_("%04u/%02u/%02u %02u:%02u:%02u"),
            st_local.wYear, st_local.wMonth, st_local.wDay,
            st_local.wHour, st_local.wMinute, st_local.wSecond);
        return std::string(buf);
    }
    catch (...) { return xorstr_(""); }
}

std::string UsbEventLogger::extract_code(const std::wstring& xml, const std::wstring& key)
{
    try {
        size_t pos = xml.find(key);
        if (pos == std::wstring::npos) return xorstr_("");
        pos += key.size();
        if (pos + 4 > xml.size()) return xorstr_("");
        std::wstring code = xml.substr(pos, 4);
        return wide_to_mb(code);
    }
    catch (...) { return xorstr_(""); }
}

bool UsbEventLogger::get_user_logon_time_local(FILETIME& ft_local_out, std::string& logon_time_str)
{
    try {
        HANDLE token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;

        TOKEN_STATISTICS stats;
        DWORD len;
        if (!GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &len)) {
            CloseHandle(token);
            return false;
        }
        CloseHandle(token);

        PLUID luid = &stats.AuthenticationId;
        PSECURITY_LOGON_SESSION_DATA pSessionData = nullptr;
        NTSTATUS status = LsaGetLogonSessionData(luid, &pSessionData);
        if (status != 0 || !pSessionData) return false;

        LARGE_INTEGER li = pSessionData->LogonTime;
        LsaFreeReturnBuffer(pSessionData);

        FILETIME ft_utc;
        ft_utc.dwLowDateTime = li.LowPart;
        ft_utc.dwHighDateTime = li.HighPart;

        if (!FileTimeToLocalFileTime(&ft_utc, &ft_local_out)) return false;

        SYSTEMTIME st_local;
        if (!FileTimeToSystemTime(&ft_local_out, &st_local)) return false;

        char buf[64];
        sprintf_s(buf, sizeof(buf), xorstr_("%04u/%02u/%02u %02u:%02u:%02u"),
            st_local.wYear, st_local.wMonth, st_local.wDay,
            st_local.wHour, st_local.wMinute, st_local.wSecond);

        logon_time_str = buf;
        return true;
    }
    catch (...) { return false; }
}

void UsbEventLogger::dev_checks()
{
    try {
        FILETIME ft_logon_local;
        std::string logon_time_str;
        if (!get_user_logon_time_local(ft_logon_local, logon_time_str))
            return;

        SYSTEMTIME st_now;
        GetLocalTime(&st_now);
        FILETIME ft_now;
        SystemTimeToFileTime(&st_now, &ft_now);

        ULARGE_INTEGER uli_now, uli_event;
        uli_now.LowPart = ft_now.dwLowDateTime;
        uli_now.HighPart = ft_now.dwHighDateTime;

        ULONGLONG one_month_100ns = 30ULL * 24ULL * 60ULL * 60ULL * 10000000ULL;

        EVT_HANDLE query = EvtQuery(nullptr, xorstr_(L"Microsoft-Windows-Kernel-PnP/Device Management"), nullptr, EvtQueryChannelPath | EvtQueryReverseDirection);
        if (!query) return;

        EVT_HANDLE results[16];
        DWORD returned = 0;
        while (EvtNext(query, 16, results, INFINITE, 0, &returned)) {
            for (DWORD i = 0; i < returned; ++i) {
                EVT_HANDLE h = results[i];
                DWORD needed = 0, size = 0;
                if (!EvtRender(nullptr, h, EvtRenderEventXml, 0, nullptr, &needed, &size) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    EvtClose(h);
                    continue;
                }

                std::unique_ptr<wchar_t[]> buffer(new wchar_t[(needed / sizeof(wchar_t)) + 1]);
                if (!EvtRender(nullptr, h, EvtRenderEventXml, needed, buffer.get(), &needed, &size)) {
                    EvtClose(h);
                    continue;
                }

                std::wstring xml(buffer.get());
                if (xml.find(xorstr_(L"USB\\VID")) == std::wstring::npos) {
                    EvtClose(h);
                    continue;
                }

                std::wstring utc_ts;
                std::string local_ts_str = xorstr_("unknown");
                FILETIME ft_event_local = { 0 };
                bool have_event_time = false;

                if (extract_utc_timestring_from_xml(xml, utc_ts)) {
                    SYSTEMTIME st_utc = { 0 };
                    if (parse_iso8601_utc_to_systemtime(utc_ts, st_utc)) {
                        FILETIME ft_utc, ft_local;
                        if (SystemTimeToFileTime(&st_utc, &ft_utc) && FileTimeToLocalFileTime(&ft_utc, &ft_local)) {
                            SYSTEMTIME st_local;
                            if (FileTimeToSystemTime(&ft_local, &st_local)) {
                                local_ts_str = format_systemtime_local(st_local);
                                ft_event_local = ft_local;
                                have_event_time = true;
                            }
                        }
                    }
                }

                if (have_event_time) {
                    uli_event.LowPart = ft_event_local.dwLowDateTime;
                    uli_event.HighPart = ft_event_local.dwHighDateTime;
                    if (uli_now.QuadPart > uli_event.QuadPart + one_month_100ns) {
                        EvtClose(h);
                        continue;
                    }
                }

                std::string vid = extract_code(xml, xorstr_(L"VID_"));
                std::string pid = extract_code(xml, xorstr_(L"PID_"));

                if (is_duplicate_event(vid, pid, local_ts_str)) {
                    EvtClose(h);
                    continue;
                }

                std::string timestamp_str = local_ts_str;

                std::vector<std::string> matched_names = LookupDeviceNames(vid, pid);

                {
                    auto contains_ci = [](const std::string& s, const char* needle, size_t nlen) {
                        if (s.size() < nlen) return false;
                        for (size_t i = 0; i + nlen <= s.size(); ++i) {
                            bool match = true;
                            for (size_t j = 0; j < nlen; ++j) {
                                char a = s[i + j], b = needle[j];
                                if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                                if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                                if (a != b) { match = false; break; }
                            }
                            if (match) return true;
                        }
                        return false;
                        };

                    auto drop_generic = [&](const char* needle, size_t nlen) {
                        bool has_other = false;
                        for (const auto& n : matched_names) {
                            if (!contains_ci(n, needle, nlen)) {
                                has_other = true;
                                break;
                            }
                        }
                        if (has_other) {
                            matched_names.erase(
                                std::remove_if(matched_names.begin(),
                                    matched_names.end(),
                                    [&](const std::string& s) {
                                        return contains_ci(s, needle, nlen);
                                    }),
                                matched_names.end());
                        }
                        };

                    drop_generic(xorstr_("HID"), 3);
                    drop_generic(xorstr_("USB"), 3);
                }

                std::ostringstream body;
                body << xorstr_("Device Removed ")
                    << (have_event_time && CompareFileTime(&ft_event_local, &ft_logon_local) >= 0 ? xorstr_("After Logon:") : xorstr_("Before Logon:"))
                    << xorstr_("Vendor ID: ") << (vid.empty() ? xorstr_("N/A") : vid)
                    << xorstr_(" Product ID: ") << (pid.empty() ? xorstr_("N/A") : pid);

                if (!matched_names.empty()) {
                    body << xorstr_(" Device: ");
                    for (size_t k = 0; k < matched_names.size(); ++k) {
                        if (k) body << xorstr_(" | ");
                        body << matched_names[k];
                    }
                }

                LOG ( INFO , timestamp_str ) << body.str();

                EvtClose(h);
            }
        }
        EvtClose(query);
    }
    catch (...) {}
}

void UsbEventLogger::start_dev_rm_checks()
{
    try {
        SetConsoleOutputCP(CP_UTF8);
        BuildLookup();
        dev_checks();
    }
    catch (...) {}
}