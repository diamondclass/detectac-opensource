#include "c_eventlog_bypass.h"

namespace
{
    static const std::vector<std::string>& MonitoredEvtxFiles()
    {
        static const std::vector<std::string> files = {
            xorstr_("System.evtx"),
            xorstr_("Application.evtx"),
            xorstr_("Windows PowerShell.evtx"),
            xorstr_("Microsoft-Windows-PowerShell%4Operational.evtx"),
            xorstr_("Microsoft-Windows-Windows Defender%4Operational.evtx"),
            xorstr_("Microsoft-Windows-Kernel-PnP%4Configuration.evtx"),
            xorstr_("Microsoft-Windows-Kernel-PnP%4Device Management.evtx"),
            xorstr_("Microsoft-Windows-VolumeSnapshot-Driver%4Operational.evtx"),
            xorstr_("Microsoft-Windows-Storage-ClassPnP%4Operational.evtx"),
            xorstr_("Microsoft-Windows-Ntfs%4Operational.evtx"),
            xorstr_("Microsoft-Windows-VHDMP%4Operational.evtx"),
        };
        return files;
    }

    static std::string AsciiLower(const std::string& s)
    {
        std::string out;
        out.reserve(s.size());
        for (char c : s)
            out.push_back(static_cast<char>(::tolower(static_cast<unsigned char>(c))));
        return out;
    }

    static bool IsMonitoredEvtx(const std::string& fileName)
    {
        try
        {
            const std::string lower = AsciiLower(fileName);
            for (const auto& allowed : MonitoredEvtxFiles())
            {
                if (AsciiLower(allowed) == lower) return true;
            }
            return false;
        }
        catch (...) { return false; }
    }
}

void ReadOnlyEvtxScanner::event_bypass(const std::string& directory)
{
    try {
        std::vector<std::string> results;
        FindReadOnlyEvtx(directory, results);

        for (const auto& filePath : results)
        {
            LOG(WARNING, xorstr_("N/A"))
                << xorstr_("Eventlog Bypass: Evtx File Set To Read Only -> ")
                << filePath;
        }
    }
    catch (...) {}
}

void ReadOnlyEvtxScanner::FindReadOnlyEvtx(const std::string& directory,
    std::vector<std::string>& results)
{
    try {
        std::string searchPath = directory + xorstr_("\\*");

        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE)
            return;

        do
        {
            const std::string name = findData.cFileName;

            if (name == xorstr_(".") || name == xorstr_(".."))
                continue;

            std::string fullPath = directory + xorstr_("\\") + name;

            if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            {
                FindReadOnlyEvtx(fullPath, results);
            }
            else
            {
                if (!IsMonitoredEvtx(name))
                    continue;

                if (findData.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
                {
                    results.push_back(fullPath);
                }
            }

        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
    }
    catch (...) {}
}

void ReadOnlyEvtxScanner::start_eventlog_bypass()
{
    try {
        ReadOnlyEvtxScanner::event_bypass(xorstr_("C:\\Windows\\System32\\winevt\\Logs"));
        return;
    }
    catch (...) {}
}
