#include "c_restarted_services.h"

std::string ServiceRestartChecker::FormatTime(ULONGLONG timeUnits)
{
    try {
        ULARGE_INTEGER uli;
        uli.QuadPart = timeUnits;

        FILETIME ft;
        ft.dwLowDateTime = uli.LowPart;
        ft.dwHighDateTime = uli.HighPart;

        SYSTEMTIME stUTC{}, stLocal{};

        if (!FileTimeToSystemTime(&ft, &stUTC))
            return xorstr_("<0000-00-00 00:00:00>");

        if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal))
            return xorstr_("<0000-00-00 00:00:00>");

        std::stringstream ss;
        ss << stLocal.wYear << xorstr_("-")
            << std::setfill('0') << std::setw(2) << stLocal.wMonth << xorstr_("-")
            << std::setfill('0') << std::setw(2) << stLocal.wDay << xorstr_(" ")
            << std::setfill('0') << std::setw(2) << stLocal.wHour << xorstr_(":")
            << std::setfill('0') << std::setw(2) << stLocal.wMinute << xorstr_(":")
            << std::setfill('0') << std::setw(2) << stLocal.wSecond;

        return ss.str();
    }
    catch (...) { return xorstr_(""); }
}

DWORD ServiceRestartChecker::GetPidByName(const std::wstring& processName)
{
    try{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
    }
    catch (...) {}
}

ULONGLONG ServiceRestartChecker::GetProcessCreationTime(DWORD pid)
{
    try{
    if (pid == 0) return 0;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return 0;

    FILETIME ftCreate{}, ftExit{}, ftKernel{}, ftUser{};
    ULONGLONG result = 0;
    if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser)) {
        ULARGE_INTEGER uli{};
        uli.LowPart = ftCreate.dwLowDateTime;
        uli.HighPart = ftCreate.dwHighDateTime;
        result = uli.QuadPart;
    }
    CloseHandle(hProcess);
    return result;
    }
    catch (...) {}
}

DWORD ServiceRestartChecker::GetServicePid(const std::wstring& serviceName)
{
    try{
    DWORD pid = 0;
    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) return 0;

    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(), SERVICE_QUERY_STATUS);
    if (hService) {
        SERVICE_STATUS_PROCESS ssp{};
        DWORD bytes = 0;
        if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytes)) {
            pid = ssp.dwProcessId;
        }
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
    return pid;
    }
    catch (...) {}
}

ULONGLONG ServiceRestartChecker::GetInteractiveLogonTime()
{
    try {
        const FILETIME localLogon = c_utils::get_logon_time();

        if (localLogon.dwLowDateTime == 0 && localLogon.dwHighDateTime == 0)
            return 0;

        FILETIME utcLogon{};
        if (!LocalFileTimeToFileTime(&localLogon, &utcLogon))
            return 0;

        ULARGE_INTEGER uli{};
        uli.LowPart = utcLogon.dwLowDateTime;
        uli.HighPart = utcLogon.dwHighDateTime;
        return uli.QuadPart;
    }
    catch (...) { return 0; }
}

bool ServiceRestartChecker::StartedWithLogon(ULONGLONG procTime, ULONGLONG logonTime)
{
    if (procTime == 0 || logonTime == 0) return false;

    const ULONGLONG diff = (procTime > logonTime) ? (procTime - logonTime) : (logonTime - procTime);
    return diff <= LOGON_GRACE_UNITS;
}

std::vector<ServiceRestartChecker::ServiceEvent> ServiceRestartChecker::CheckServicesRestartedSinceWininit(
    const std::vector<std::pair<std::wstring, std::string>>& services)
{
    try{
    std::vector<ServiceEvent> results;
    const DWORD wininitPid = GetPidByName(xorstr_(L"wininit.exe"));
    const ULONGLONG wininitTime = GetProcessCreationTime(wininitPid);

    if (wininitTime == 0) return results;

    for (const auto& service : services) {
        const DWORD svcPid = GetServicePid(service.first);
        const ULONGLONG svcTime = GetProcessCreationTime(svcPid);

        if (svcTime == 0) continue;

        const ULONGLONG diff = (svcTime > wininitTime) ? (svcTime - wininitTime) : (wininitTime - svcTime);

        if (diff > ONE_MINUTE_UNITS) {
            results.push_back({ service.second, svcTime });
        }
    }
    return results;
    }
    catch (...) {}
    return {};
}

std::vector<ServiceRestartChecker::ServiceEvent> ServiceRestartChecker::CheckProcessesRestartedSinceWininit(
    const std::vector<std::pair<std::wstring, std::string>>& processes)
{
    try {
        std::vector<ServiceEvent> results;
        const DWORD wininitPid = GetPidByName(xorstr_(L"wininit.exe"));
        const ULONGLONG wininitTime = GetProcessCreationTime(wininitPid);

        if (wininitTime == 0) return results;

        const ULONGLONG logonTime = GetInteractiveLogonTime();

        for (const auto& proc : processes) {
            const DWORD pid = GetPidByName(proc.first);
            const ULONGLONG procTime = GetProcessCreationTime(pid);

            if (procTime == 0) continue;

            const ULONGLONG diff = (procTime > wininitTime) ? (procTime - wininitTime) : (wininitTime - procTime);

            if (diff > ONE_MINUTE_UNITS && !StartedWithLogon(procTime, logonTime)) {
                results.push_back({ proc.second, procTime });
            }
        }
        return results;
    }
    catch (...) { return {}; }
}

std::vector<ServiceRestartChecker::ServiceEvent> ServiceRestartChecker::CheckDefaultServices()
{
    try{
    const std::vector<std::pair<std::wstring, std::string>> services = {
        {xorstr_(L"DusmSvc"), xorstr_("DusmSvc")},
        {xorstr_(L"SysMain"), xorstr_("SysMain")},
        {xorstr_(L"DPS"), xorstr_("DPS")},
        {xorstr_(L"Eventlog"), xorstr_("Eventlog")},
        {xorstr_(L"Dnscache"), xorstr_("Dnscache")}
    };

    const std::vector<std::pair<std::wstring, std::string>> processes = {
        {xorstr_(L"explorer.exe"), xorstr_("Explorer.exe")}, //explorer.exe restarts too much and can be done legitimately
        {xorstr_(L"lsass.exe"), xorstr_("Lsass.exe")}
    };

    auto results = CheckServicesRestartedSinceWininit(services);
    auto procResults = CheckProcessesRestartedSinceWininit(processes);
    results.insert(results.end(), procResults.begin(), procResults.end());

    return results;
    }
    catch (...) { return {}; }
}

void ServiceRestartChecker::start_restarted_services_check()
{
    try {
        auto events = ServiceRestartChecker::CheckDefaultServices();

        for (const auto& ev : events) {
            LOG(WARNING, FormatTime(ev.time)) << ev.name << xorstr_(" Has Been Restarted");
        }
    }
    catch (...) {}
}