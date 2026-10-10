#include "c_custom_amcache.h"
#include "../../client_checks/client_checks_amcache/c_amcache.h"

#pragma comment(lib, "winhttp.lib")

namespace {

    std::unordered_map<std::string, std::string> sha1_filters;

    inline std::string ToUpperAscii(std::string s)
    {
        for (auto& c : s) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 32);
        }
        return s;
    }

}

std::string AmcacheReader2::fetch_json(const std::wstring& url)
{
    try {
        std::string result;
        HINTERNET hSession = WinHttpOpen(xorstr_(L"AmcacheReader/1.0"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) {
            return result;
        }

        URL_COMPONENTS urlComp = { 0 };
        wchar_t hostName[256];
        wchar_t urlPath[1024];
        urlComp.dwStructSize = sizeof(urlComp);
        urlComp.lpszHostName = hostName;
        urlComp.dwHostNameLength = _countof(hostName);
        urlComp.lpszUrlPath = urlPath;
        urlComp.dwUrlPathLength = _countof(urlPath);

        if (!WinHttpCrackUrl(url.c_str(), 0, 0, &urlComp)) {
            WinHttpCloseHandle(hSession);
            return result;
        }

        HINTERNET hConnect = WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return result;
        }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, xorstr_(L"GET"),
            urlComp.lpszUrlPath,
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            (urlComp.nPort == INTERNET_DEFAULT_HTTPS_PORT ? WINHTTP_FLAG_SECURE : 0));

        if (hRequest && WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0,
            0, 0) &&
            WinHttpReceiveResponse(hRequest, NULL))
        {
            DWORD dwSize = 0;
            do {
                if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;
                std::string buffer(dwSize, 0);
                DWORD dwDownloaded = 0;
                if (!WinHttpReadData(hRequest, &buffer[0], dwSize, &dwDownloaded)) break;
                buffer.resize(dwDownloaded);
                result.append(buffer);
            } while (dwSize > 0);
        }

        if (hRequest) WinHttpCloseHandle(hRequest);
        if (hConnect) WinHttpCloseHandle(hConnect);
        if (hSession) WinHttpCloseHandle(hSession);

        return result;
    }
    catch (...) {}
    return "";
}

std::wstring AmcacheReader2::s2ws(const std::string& str)
{
    try {
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &wstr[0], size_needed);
        return wstr;
    }
    catch (...) {}
    return L"";
}

void AmcacheReader2::load_sha1_filters_from_endpoint()
{
    try {
        static bool initialized = false;
        if (initialized) return;

        sha1_filters.clear();

        std::wstring url = s2ws(xorstr_("https://detect.ac/auth/user/strings/getstrings/")) + s2ws(detect.pin);
        std::string json_data = fetch_json(url);
        if (json_data.empty()) return;

        nlohmann::json parsed = nlohmann::json::parse(json_data);
        if (!parsed.contains(xorstr_("customStrings"))) return;

        for (auto& entry : parsed[xorstr_("customStrings")]) {
            if (!entry.contains(xorstr_("processName")) || !entry.contains(xorstr_("strings"))) continue;

            std::string process_name = entry[xorstr_("processName")].get<std::string>();
            if (process_name != xorstr_("Amcache")) continue;

            std::string raw_strings = entry[xorstr_("strings")].get<std::string>();
            size_t pos = 0;
            while (pos < raw_strings.size()) {
                size_t next = raw_strings.find(xorstr_("\r\n"), pos);
                std::string line;
                if (next == std::string::npos) {
                    line = raw_strings.substr(pos);
                    pos = raw_strings.size();
                }
                else {
                    line = raw_strings.substr(pos, next - pos);
                    pos = next + 2;
                }
                if (line.empty()) continue;

                size_t delim = line.find(xorstr_(":::"));
                if (delim == std::string::npos) continue;

                std::string name = line.substr(0, delim);
                std::string hash = ToUpperAscii(line.substr(delim + 3));

                if (!name.empty() && !hash.empty()) {
                    sha1_filters[hash] = name;
                }
            }
        }

        initialized = true;
    }
    catch (...) {}
}

void AmcacheReader2::ProcessAmcache()
{
    try {
        load_sha1_filters_from_endpoint();

        std::vector<AmcacheEntry> entries;
        if (!AmcacheFilters::GetAmcacheEntries(entries)) return;

        for (const auto& e : entries) {
            if (e.sha1.empty()) continue;

            auto it = sha1_filters.find(e.sha1);
            if (it == sha1_filters.end()) continue;

            const bool onDisk = !e.pathIsKeyName && std::filesystem::exists(e.path);

            LOG(DETECTION, xorstr_("N/A"))
                << xorstr_("Custom Amcache Hash ")
                << it->second
                << (onDisk
                    ? xorstr_(" Found On PC:")
                    : xorstr_(" Not Found On PC:"))
                << e.path;
        }
    }
    catch (...) {}
}
