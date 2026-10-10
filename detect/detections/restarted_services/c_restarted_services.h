#pragma once

#include "../../pch.h"

class ServiceRestartChecker final
{
public:
    struct ServiceEvent {
        std::string name;
        ULONGLONG time;
    };
     
    static std::vector<ServiceEvent> CheckServicesRestartedSinceWininit(
        const std::vector<std::pair<std::wstring, std::string>>& services
    );
    static std::vector<ServiceEvent> CheckProcessesRestartedSinceWininit(
        const std::vector<std::pair<std::wstring, std::string>>& processes
    );

    static std::vector<ServiceEvent> CheckDefaultServices();
    static void start_restarted_services_check();

    static constexpr ULONGLONG ONE_MINUTE_UNITS = 600000000ULL;
    static constexpr ULONGLONG LOGON_GRACE_UNITS = 10000000ULL;

    static std::string FormatTime(ULONGLONG timeUnits);
    static DWORD GetPidByName(const std::wstring& processName);
    static ULONGLONG GetProcessCreationTime(DWORD pid);
    static DWORD GetServicePid(const std::wstring& serviceName);
    static ULONGLONG GetInteractiveLogonTime();
    static bool StartedWithLogon(ULONGLONG procTime, ULONGLONG logonTime);
};

inline auto c_res_ser = std::make_unique<ServiceRestartChecker>();