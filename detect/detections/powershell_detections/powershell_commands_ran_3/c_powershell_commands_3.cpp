#include "c_powershell_commands_3.h"
#include "../powershell_whitelist.h"

const std::vector<std::wstring> PowerShellEventParser::s_keywords = {
    xorstr_(L"invoke-ex"),
    xorstr_(L"invoke-webrequest"),
    xorstr_(L"Install-Module -Name PSReadLine -AllowClobber -Force"),
    xorstr_(L"Invoke-CommandInDesktopPackage"),
    xorstr_(L"iex "),
    xorstr_(L"irm "),
    xorstr_(L"$env:TEMP"),
    xorstr_(L"sEvErance LOaDer"),
    xorstr_(L"asplaintext"),
    xorstr_(L"token"),
    xorstr_(L"apikey"),
    xorstr_(L"secret"),
    xorstr_(L"password")
};

std::wstring PowerShellEventParser::ToLower(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

std::wstring PowerShellEventParser::Flatten(std::wstring s)
{
    std::replace(s.begin(), s.end(), L'\r', L' ');
    std::replace(s.begin(), s.end(), L'\n', L' ');
    return s;
}

bool PowerShellEventParser::MatchesKeyword(const std::wstring& scriptBlock)
{
    std::wstring lower = ToLower(scriptBlock);
    for (const auto& kw : s_keywords) {
        if (lower.find(ToLower(kw)) != std::wstring::npos)
            return true;
    }
    return false;
}

std::string PowerShellEventParser::WideToUtf8(const std::wstring& ws)
{
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
        static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(),
        static_cast<int>(ws.size()), out.data(), len, nullptr, nullptr);
    return out;
}

std::wstring PowerShellEventParser::FileTimeToLocalString(ULONGLONG ft)
{
    FILETIME filetime;
    filetime.dwLowDateTime = static_cast<DWORD>(ft);
    filetime.dwHighDateTime = static_cast<DWORD>(ft >> 32);

    FILETIME localFt;
    if (!FileTimeToLocalFileTime(&filetime, &localFt))
        return xorstr_(L"N/A");

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&localFt, &st))
        return xorstr_(L"N/A");

    wchar_t buf[64];
    swprintf_s(buf, xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    return buf;
}

void PowerShellEventParser::ProcessEvents(EVT_HANDLE hQuery, EVT_HANDLE hCtx)
{
    EVT_HANDLE hEvent = nullptr;
    DWORD returned = 0;

    while (EvtNext(hQuery, 1, &hEvent, INFINITE, 0, &returned)) {
        try {
            DWORD used = 0, props = 0;
            EvtRender(hCtx, hEvent, EvtRenderEventValues, 0, nullptr, &used, &props);

            std::vector<BYTE> buf(used);
            if (EvtRender(hCtx, hEvent, EvtRenderEventValues, used,
                buf.data(), &used, &props)) {

                auto* v = reinterpret_cast<PEVT_VARIANT>(buf.data());

                std::wstring script;
                if (v[1].Type == EvtVarTypeString && v[1].StringVal)
                    script = v[1].StringVal;

                if (MatchesKeyword(script)) {
                    std::string cmd = WideToUtf8(Flatten(script));
                    if (!ps_whitelist::IsWhitelisted(cmd)
                        && cmd.find(xorstr_("Chrome/128.0.0.0")) == std::string::npos) {
                        std::wstring timeStr = xorstr_(L"N/A");
                        if (v[0].Type == EvtVarTypeFileTime)
                            timeStr = FileTimeToLocalString(v[0].FileTimeVal);

                        LOG(WARNING, WideToUtf8(timeStr)) << xorstr_("Possible Suspicious Powershell Command:") << cmd;
                    }
                }
            }
        }
        catch (...) {
        }

        EvtClose(hEvent);
        hEvent = nullptr;
    }
}

void PowerShellEventParser::start_commands_3()
{
    SetConsoleOutputCP(CP_UTF8);

    const wchar_t* channel = xorstr_(L"Microsoft-Windows-PowerShell/Operational");
    const wchar_t* xpath = xorstr_(L"*[System[EventID=4104]]");

    EVT_HANDLE hQuery = EvtQuery(nullptr, channel, xpath,
        EvtQueryChannelPath | EvtQueryReverseDirection);
    if (!hQuery)
        return;

    LPCWSTR valuePaths[] = {
        xorstr_(L"Event/System/TimeCreated/@SystemTime"),
        xorstr_(L"Event/EventData/Data[@Name='ScriptBlockText']")
    };
    EVT_HANDLE hCtx = EvtCreateRenderContext(2, valuePaths, EvtRenderContextValues);
    if (!hCtx) {
        EvtClose(hQuery);
        return;
    }

    try {
        ProcessEvents(hQuery, hCtx);
    }
    catch (...) {
    }

    EvtClose(hCtx);
    EvtClose(hQuery);
}