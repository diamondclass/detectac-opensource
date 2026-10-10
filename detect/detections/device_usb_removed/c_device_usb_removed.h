#pragma once

#include "../../pch.h"

class UsbEventLogger
{
public:
    static void start_dev_rm_checks();

    static void dev_checks();

    static std::set<std::string> seen_events;

    static bool is_duplicate_event(const std::string& vid, const std::string& pid, const std::string& local_time);
    static std::string wide_to_mb(const std::wstring& w);
    static bool extract_utc_timestring_from_xml(const std::wstring& xml, std::wstring& utc_time_out);
    static bool parse_iso8601_utc_to_systemtime(const std::wstring& s, SYSTEMTIME& st_utc);
    static std::string format_systemtime_local(const SYSTEMTIME& st_local);
    static std::string extract_code(const std::wstring& xml, const std::wstring& key);
    static bool get_user_logon_time_local(FILETIME& ft_local_out, std::string& logon_time_str);

private:
    struct DeviceRecord
    {
        std::wstring bus;
        std::wstring vid;
        std::wstring pid;
        std::set<std::wstring> revisions;
        std::set<std::wstring> subsystems;
        std::set<std::wstring> friendlyNames;
        std::set<std::wstring> deviceDescs;
        std::set<std::wstring> manufacturers;
        std::set<std::wstring> services;
        std::set<std::wstring> classNames;
        std::set<std::wstring> hardwareIds;
        std::set<std::wstring> compatibleIds;
        std::set<std::wstring> instancePaths;
        std::set<std::wstring> driveLetters;
        std::set<std::wstring> volumeIds;
        std::set<std::wstring> sources;
    };

    using DeviceMap = std::map<std::wstring, DeviceRecord>;
    using VidPidKey = std::pair<std::string, std::string>;

    static std::map<VidPidKey, std::set<std::string>> g_index;

    static std::wstring ToUpperW(std::wstring s);
    static std::wstring TrimW(std::wstring s);
    static std::string  Narrow(const std::wstring& w);
    static std::wstring Widen(const std::string& s);
    static std::wstring StripInfPrefix(std::wstring v);
    static std::wstring ReadRegString(HKEY hKey, const wchar_t* valueName);
    static std::vector<std::wstring> EnumSubKeys(HKEY hKey);

    static const std::wregex& VidRe();
    static const std::wregex& PidRe();
    static const std::wregex& RevRe();
    static const std::wregex& VenRe();
    static const std::wregex& DevRe();
    static const std::wregex& ProdRe();
    static const std::wregex& SubsysRe();

    static std::wstring   ExtractToken(const std::wstring& s, const std::wregex& re);
    static std::wstring   MakeKey(const std::wstring& bus, const std::wstring& vid, const std::wstring& pid);
    static DeviceRecord& GetOrCreate(DeviceMap& m, const std::wstring& bus, const std::wstring& vid, const std::wstring& pid);
    static void           ExtractIds(const std::wstring& path, std::wstring& vid, std::wstring& pid, std::wstring& rev, std::wstring& subsys);
    static void           SplitMulti(const std::wstring& blob, std::set<std::wstring>& out);

    static std::wstring   BusFromPath(const std::wstring& upper);
    static void           ScanEnumKey(DeviceMap& devices, size_t& deviceCount);
    static void           ScanMountedDevices(DeviceMap& devices);
    static void           ScanWpdDevices(DeviceMap& devices);
    static void           ScanDeviceClasses(DeviceMap& devices);
    static void           ScanSetupApiLog(DeviceMap& devices);

    static std::string                AsciiUpper(std::string s);
    static void                       BuildLookup();
    static std::vector<std::string>   LookupDeviceNames(const std::string& vid, const std::string& pid);
};


inline auto c_device_rm = std::make_unique<UsbEventLogger> ( );