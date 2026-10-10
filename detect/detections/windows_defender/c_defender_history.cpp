#include "c_defender_history.h"

std::wstring DefenderHistory::SanitizeString(const std::wstring& input) {
    try{
    std::wstring sanitized;
    for (wchar_t ch : input) {
        if (ch >= 32 && ch <= 126) {
            sanitized += ch;
        }
        else {
            sanitized += xorstr_(L"?");
        }
    }
    return sanitized;
    }
    catch (...) { return L""; }
}

std::wstring DefenderHistory::FormatTimestamp(const std::wstring& timestamp) {
    try{
    std::wregex timeRegex(xorstr_(L"(\\d{4})-(\\d{2})-(\\d{2})T(\\d{2}):(\\d{2}):(\\d{2})"));
    std::wsmatch match;
    if (std::regex_search(timestamp, match, timeRegex)) {
        std::wstringstream formattedTime;
        formattedTime << match[1].str() << xorstr_(L"-") << match[2].str() << xorstr_(L"-") << match[3].str() << xorstr_(L" ")
            << match[4].str() << xorstr_(L":") << match[5].str() << xorstr_(L":") << match[6].str();
        return formattedTime.str();
    }
    return xorstr_(L"Invalid Timestamp");
    }
    catch (...) { return L""; }
}

void DefenderHistory::QueryDefenderHistory() {
    try{
    EVT_HANDLE hResults = EvtQuery(NULL, xorstr_(L"Microsoft-Windows-Windows Defender/Operational"),
        xorstr_(L"*"), EvtQueryChannelPath);
    if (!hResults) return;

    EVT_HANDLE hEvents[10];
    DWORD dwReturned = 0;
    std::unordered_set<std::wstring> seenPaths;

    while (EvtNext(hResults, 10, hEvents, INFINITE, 0, &dwReturned)) {
        for (DWORD i = 0; i < dwReturned; i++) {
            DWORD dwBufferSize = 0, dwBufferUsed = 0;
            EvtRender(NULL, hEvents[i], EvtRenderEventXml, 0, NULL, &dwBufferUsed, &dwBufferSize);

            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                std::vector<wchar_t> buffer(dwBufferUsed / sizeof(wchar_t));
                if (EvtRender(NULL, hEvents[i], EvtRenderEventXml, dwBufferUsed, buffer.data(), &dwBufferUsed, &dwBufferSize)) {
                    std::wstring xmlData(buffer.data());
                    if (xmlData.find(xorstr_(L"<EventID>1116</EventID>")) != std::wstring::npos) {
                        std::wsmatch match;
                        std::wregex timeRegex(xorstr_(L"<TimeCreated SystemTime='([^']+)'\\s*/>"));
                        std::wregex pathRegex(xorstr_(L"<Data Name='Path'>(.*?)</Data>"));

                        std::wstring timeCreated = xorstr_(L"N/A");
                        std::wstring filePath = xorstr_(L"N/A");

                        if (std::regex_search(xmlData, match, timeRegex)) {
                            timeCreated = FormatTimestamp(match[1].str());
                        }
                        if (std::regex_search(xmlData, match, pathRegex)) {
                            filePath = match[1].str();
                        }

                        std::wstringstream ss(filePath);
                        std::wstring singlePath;
                        while (std::getline(ss, singlePath, L';')) {
                            singlePath.erase(0, singlePath.find_first_not_of(xorstr_(L" ")));

                            if (singlePath.find(xorstr_(L"file:_")) == 0) {
                                singlePath = singlePath.substr(6);
                            }
                            else if (singlePath.find(xorstr_(L"containerfile:_")) == 0) {
                                singlePath = singlePath.substr(15);
                            }

                            if (singlePath.find(xorstr_(L"regkeyvalue")) == 0 || singlePath.find(xorstr_(L"webfile")) == 0 || singlePath.find(xorstr_(L"regkey")) == 0 || singlePath.find(xorstr_(L"runkey")) == 0 || singlePath.find(xorstr_(L"runonce")) == 0 || singlePath.find(xorstr_(L"-&gt")) != std::wstring::npos || (singlePath.find(xorstr_(L"/")) == std::wstring::npos && singlePath.find(xorstr_(L"\\")) == std::wstring::npos)) {
                                continue;
                            }

                            singlePath = SanitizeString(singlePath);

                            if (seenPaths.insert(singlePath).second) {
                                LOG(INFO , utils->convert_wstring_to_string(timeCreated) ) << xorstr_("Malicious File:") << singlePath;
                            }
                        }
                    }
                }
            }
            EvtClose(hEvents[i]);
        }
    }
    EvtClose(hResults);
    }
    catch (...) {}
}