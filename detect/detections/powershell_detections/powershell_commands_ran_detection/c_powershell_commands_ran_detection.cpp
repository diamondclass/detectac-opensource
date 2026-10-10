#include "c_powershell_commands_ran_detection.h"
#include "../powershell_whitelist.h"

std::string c_powershell_commands_ran_detection::ExtractEventTime(const std::string& xml)
{
    try{
    size_t pos = xml.find(xorstr_("SystemTime="));
    if (pos == std::string::npos)
        return xorstr_("");

    pos += strlen(xorstr_("SystemTime="));

    if (pos >= xml.size())
        return xorstr_("");

    char quote = xml[pos];
    if (quote != '"' && quote != '\'')
        return xorstr_("");

    pos++;

    size_t end = xml.find(quote, pos);
    if (end == std::string::npos)
        return xorstr_("");

    return xml.substr(pos, end - pos);
    }
    catch (...) {};
    return {};
}

std::string c_powershell_commands_ran_detection::FormatEventTime(const std::string& isoTime)
{
    try{
    if (isoTime.length() < 19)
        return xorstr_("");

    std::string formatted = isoTime.substr(0, 19);
    formatted[10] = ' ';

    return formatted;
    }
    catch (...) {};
    return {};
}

std::string c_powershell_commands_ran_detection::ToLower(std::string s)
{
    try{
    std::transform(
        s.begin(),
        s.end(),
        s.begin(),
        [](unsigned char c) { return (char)tolower(c); }
    );

    return s;
    }
    catch (...) {};
}

bool c_powershell_commands_ran_detection::ContainsSuspiciousCommand(const std::string& hostApp)
{
    try{
    static const std::vector<std::string> keywords =
    {
        xorstr_("invoke-ex"),
        xorstr_("invoke-rest"),
        xorstr_("invoke-webrequest"),
        xorstr_("install-module -name psreadline -allowclobber -force"),
        xorstr_("invoke-commandindesktoppackage"),
        xorstr_("iex "),
        xorstr_("irm "),
        xorstr_("$env:TEMP"),
        xorstr_("sEvErance LOaDer"),
        xorstr_("asplaintext"),
        xorstr_("token"),
        xorstr_("apikey"),
        xorstr_("secret"),
        xorstr_("password")
    };

    std::string lowerHost = ToLower(hostApp);

    for (const auto& k : keywords)
    {
        if (lowerHost.find(k) != std::string::npos)
            return true;
    }

    return false;
    }
    catch (...) {};
    return false;
}

std::string c_powershell_commands_ran_detection::ExtractHostApplication(const std::string& xml)
{
    try{
    const std::string key = xorstr_("HostApplication=");
    size_t pos = xml.find(key);
    if (pos == std::string::npos)
        return xorstr_("");

    pos += key.length();

    size_t end = xml.find_first_of(xorstr_("<\r\n"), pos);
    if (end == std::string::npos)
        end = xml.length();

    return xml.substr(pos, end - pos);
    }
    catch (...) {};
    return {};
}

void c_powershell_commands_ran_detection::Scan(const wchar_t* evtxPath)
{
    try{
    EVT_HANDLE hQuery = EvtQuery(
        NULL,
        evtxPath,
        xorstr_(L"*"),
        EvtQueryFilePath
    );

    if (!hQuery)
    {
        return;
    }

    EVT_HANDLE hEvent = NULL;
    DWORD returned = 0;

    while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, &returned))
    {
        DWORD bufferUsed = 0;
        DWORD propertyCount = 0;

        EvtRender(
            NULL,
            hEvent,
            EvtRenderEventXml,
            0,
            NULL,
            &bufferUsed,
            &propertyCount
        );

        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            EvtClose(hEvent);
            continue;
        }

        WCHAR* wideBuffer = (WCHAR*)malloc(bufferUsed);

        if (!EvtRender(
            NULL,
            hEvent,
            EvtRenderEventXml,
            bufferUsed,
            wideBuffer,
            &bufferUsed,
            &propertyCount))
        {
            free(wideBuffer);
            EvtClose(hEvent);
            continue;
        }

        int len = WideCharToMultiByte(
            CP_ACP,
            0,
            wideBuffer,
            -1,
            NULL,
            0,
            NULL,
            NULL
        );

        std::string xml(len, '\0');

        WideCharToMultiByte(
            CP_ACP,
            0,
            wideBuffer,
            -1,
            &xml[0],
            len,
            NULL,
            NULL
        );

        std::string hostApp = ExtractHostApplication(xml);

        if (!hostApp.empty() && ContainsSuspiciousCommand(hostApp) && !ps_whitelist::IsWhitelisted(hostApp)
            && hostApp.find(xorstr_("Chrome/128.0.0.0")) == std::string::npos)
        {
            std::string rawTime = ExtractEventTime(xml);
            std::string formattedTime = FormatEventTime(rawTime);

            LOG(WARNING, formattedTime) << xorstr_("Possible Suspicious Powershell Command:") << hostApp;

        }

        free(wideBuffer);
        EvtClose(hEvent);
    }

    EvtClose(hQuery);
    }
    catch (...) {};
}

void c_powershell_commands_ran_detection::start_powershell_evtx_commands()
{
    try{
    c_powershell_commands_ran_detection::Scan(
        xorstr_(L"C:\\Windows\\System32\\winevt\\Logs\\Windows PowerShell.evtx")
    );

    return;
    }
    catch (...) {};
}