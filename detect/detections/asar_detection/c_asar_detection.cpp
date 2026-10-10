#include "c_asar_detection.h"

std::string DiscordAsarScanner::GetUsername()
{
    try{
    char buf[256];
    DWORD len = sizeof(buf);
    if (GetUserNameA(buf, &len))
        return std::string(buf);
    return xorstr_("");
    }
    catch (...) { return ""; }
}

bool DiscordAsarScanner::ReadFileAll(const std::string& path, std::vector<char>& data)
{
    try {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, path.data(),
                                       static_cast<int>(path.size()), nullptr, 0);
        std::wstring wpath;
        if (wlen > 0) {
            wpath.resize(static_cast<size_t>(wlen));
            MultiByteToWideChar(CP_UTF8, 0, path.data(),
                                static_cast<int>(path.size()),
                                wpath.data(), wlen);
        }

        HANDLE h = CreateFileW(
            wpath.empty() ? nullptr : wpath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER li{};
        if (!GetFileSizeEx(h, &li) || li.QuadPart < 0) {
            CloseHandle(h);
            return false;
        }
        // core.asar can legitimately be ~150 MB; cap at 512 MB.
        if (li.QuadPart > (512ll << 20)) {
            CloseHandle(h);
            return false;
        }

        try {
            data.resize(static_cast<size_t>(li.QuadPart));
        } catch (...) {
            CloseHandle(h);
            return false;
        }

        size_t off = 0;
        while (off < data.size()) {
            DWORD want = static_cast<DWORD>(
                (std::min<size_t>)(data.size() - off, 1u << 20));
            DWORD got = 0;
            if (!ReadFile(h, data.data() + off, want, &got, nullptr)) {
                CloseHandle(h);
                return false;
            }
            if (got == 0) break;
            off += got;
        }
        CloseHandle(h);
        data.resize(off);
        return true;
    }
    catch (...) { return false; }
}

bool DiscordAsarScanner::ExtractMainScreenJS(const std::vector<char>& asar, std::string& outJs)
{
    try{
    if (asar.size() < 16)
        return false;

    uint32_t headerSize = *reinterpret_cast<const uint32_t*>(&asar[4]);
    uint32_t headerOffset = 8;
    uint32_t dataOffset = headerOffset + headerSize;

    std::string headerJson(asar.begin() + headerOffset, asar.begin() + dataOffset);

    size_t pos = headerJson.find(xorstr_("\"mainScreen.js\""));
    if (pos == std::string::npos)
        return false;

    size_t offPos = headerJson.find(xorstr_("\"offset\":\""), pos);
    size_t sizePos = headerJson.find(xorstr_("\"size\":"), pos);
    if (offPos == std::string::npos || sizePos == std::string::npos)
        return false;

    offPos += 10;
    sizePos += 7;

    size_t offEnd = headerJson.find(xorstr_("\""), offPos);
    size_t sizeEnd = headerJson.find(xorstr_(","), sizePos);

    uint64_t fileOffset = std::stoull(headerJson.substr(offPos, offEnd - offPos));
    uint64_t fileSize = std::stoull(headerJson.substr(sizePos, sizeEnd - sizePos));

    uint64_t absoluteOffset = dataOffset + fileOffset;
    if (absoluteOffset + fileSize > asar.size())
        return false;

    outJs.assign(
        asar.begin() + absoluteOffset,
        asar.begin() + absoluteOffset + fileSize
    );

    return true;
    }
    catch (...) { return false; }
}

bool DiscordAsarScanner::DetectInjectedRequire(const std::string& js, std::string& outModuleName)
{
    try{
    std::istringstream stream(js);
    std::string line;
    bool inInit = false;
    int linesChecked = 0;

    while (std::getline(stream, line))
    {
        std::string t = line;
        t.erase(std::remove_if(t.begin(), t.end(), isspace), t.end());

        if (!inInit)
        {
            if (t.find(xorstr_("functioninit()")) != std::string::npos)
                inInit = true;
            continue;
        }

        linesChecked++;
        if (linesChecked <= 10)
        {
            size_t reqPos = t.find(xorstr_("require(\"./"));
            if (reqPos != std::string::npos)
            {
                size_t start = reqPos + 11;
                size_t end = t.find(xorstr_("\""), start);
                if (end != std::string::npos && t.find(xorstr_(")()"), end) != std::string::npos)
                {
                    outModuleName = t.substr(start, end - start);
                    return true;
                }
            }
        }

        if (t == xorstr_("}"))
            break;
    }

    return false;
    }
    catch (...) { return false; }
}

bool DiscordAsarScanner::ScanForInjectedRequire(std::string& outInjectedModule)
{
    try{
    std::string user = GetUsername();
    if (user.empty())
        return false;

    std::string asarPath =
        xorstr_("C:\\Users\\") + user +
        xorstr_("\\AppData\\Local\\Discord\\app-1.0.9220\\modules\\discord_desktop_core-1\\discord_desktop_core\\core.asar");

    std::vector<char> asarData;
    if (!ReadFileAll(asarPath, asarData))
        return false;

    std::string mainJs;
    if (!ExtractMainScreenJS(asarData, mainJs))
        return false;

    return DetectInjectedRequire(mainJs, outInjectedModule);
    }
    catch (...) { return false; }
}

void DiscordAsarScanner::asar_checks()
{
    try{
    std::string module;
    if (DiscordAsarScanner::ScanForInjectedRequire(module))
    {
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Discord ASAR Vulnerability Bypass:User has Modified Discord To Exploit A Vulnerability Which Allows Malicious .js Files To Be Launched, User Bypassing - Bypass File Name Embedded In: C:\\Users\\%username%\\AppData\\Local\\Discord\\app-1.0.9220\\modules\\discord_desktop_core-1\\discord_desktop_core\\core.asar - File Name:") << module << xorstr_(".js");
    }
    return;
    }
    catch (...) {}
}