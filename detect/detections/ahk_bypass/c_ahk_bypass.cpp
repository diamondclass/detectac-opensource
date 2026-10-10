#include "c_ahk_bypass.h"

const std::vector<std::string> AhkPrefetchScanner::ahk_keywords =
{
    xorstr_("send,"),
    xorstr_("sendinput,"),
    xorstr_("sendplay,"),
    xorstr_("sendraw,"),
    xorstr_("hotkey"),
    xorstr_("inputbox"),
    xorstr_("msgbox"),
    xorstr_("#noenv"),
    xorstr_("#singleinstance"),
    xorstr_("#persistent"),
    xorstr_("#installkeybdhook"),
    xorstr_("#installmousehook"),
    xorstr_("#usehook"),
    xorstr_("#maxhotkeysperinterval"),
    xorstr_("#hotkeyinterval"),
    xorstr_("#winactivateforce"),
    xorstr_("winwait"),
    xorstr_("winexist"),
    xorstr_("winget"),
    xorstr_("winmove"),
    xorstr_("^c::"),
    xorstr_("!f4::"),
    xorstr_("#x::"),
    xorstr_("+tab::"),
    xorstr_("loop, files"),
    xorstr_("loop, parse"),
    xorstr_("; autohotkey"),
    xorstr_("; ahk")
};

bool AhkPrefetchScanner::is_pe_file(const std::string& path)
{
    try
    {
        std::ifstream file(path, std::ios::binary);
        if (!file)
            return false;

        unsigned char mz[2];
        file.read(reinterpret_cast<char*>(mz), 2);

        return file.gcount() == 2 && mz[0] == 'M' && mz[1] == 'Z';
    }
    catch (...)
    {
        return false;
    }
}

void AhkPrefetchScanner::normalize_to_single_line(std::string& s)
{
    try{
    for (char& c : s)
    {
        if (c == '\r' || c == '\n' || c == '\t')
            c = ' ';
    }

    s.erase(
        std::unique(
            s.begin(),
            s.end(),
            [](char a, char b) { return a == ' ' && b == ' '; }
        ),
        s.end()
    );
    }
    catch (...) {}
}

std::string AhkPrefetchScanner::get_username()
{
    try{
    char buffer[256];
    DWORD size = sizeof(buffer);

    if (GetUserNameA(buffer, &size))
        return std::string(buffer);

    return {};
    }
    catch (...) { return ""; }
}

bool AhkPrefetchScanner::is_cmd_prefetch(const std::filesystem::path& p)
{
    try{
    if (p.extension() != xorstr_(".pf"))
        return false;

    std::string name = c_utils::path_to_utf8(p.filename());
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    return name.rfind(xorstr_("autohotkey64.exe-"), 0) == 0;
    }
    catch (...) { return false; }
}

std::string AhkPrefetchScanner::replace_volume_guid(const std::string& path)
{
    try {
        size_t volumePos = path.find(xorstr_("VOLUME{"));
        if (volumePos == std::string::npos) {
            volumePos = path.find(xorstr_("Volume{"));
        }
        if (volumePos == std::string::npos) {
            return path;
        }

        size_t closeBrace = path.find(xorstr_("}"), volumePos);
        if (closeBrace == std::string::npos) {
            return path;
        }

        std::string remainingPath;
        if (closeBrace + 1 < path.length()) {
            remainingPath = path.substr(closeBrace + 1);
        }
        else {
            return path;
        }

        DWORD drives = GetLogicalDrives();

        char driveLetter[4] = { 0 };
        for (char letter = 'A'; letter <= 'Z'; letter++) {
            if (drives & (1 << (letter - 'A'))) {
                sprintf_s(driveLetter, xorstr_("%c:"), letter);
                std::string testPath = std::string(driveLetter) + remainingPath;

                DWORD attrib = GetFileAttributesA(testPath.c_str());
                if (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY)) {
                    return testPath;
                }
            }
        }

        return xorstr_("C:") + remainingPath;
    }
    catch (...) {
        return path;
    }
}

bool AhkPrefetchScanner::is_whitelisted(const std::string& path, const std::string& username)
{
    try{
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::string whitelist =
        xorstr_("c:\\users\\") + username + xorstr_("\\appdata\\local\\temp\\msbuildtemp\\");

    std::transform(whitelist.begin(), whitelist.end(), whitelist.begin(), ::tolower);
    return lower.rfind(whitelist, 0) == 0;
    }
    catch (...) { return false; }
}

bool AhkPrefetchScanner::is_file_too_large(const std::string& path, uintmax_t max_size)
{
    try
    {
        if (!std::filesystem::exists(path))
            return true;

        uintmax_t size = std::filesystem::file_size(path);
        return size > max_size;
    }
    catch (...)
    {
        return true;
    }
}

bool AhkPrefetchScanner::read_file(const std::string& path, std::string& out)
{
    try{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;

    out.assign(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );

    return true;
    }
    catch (...) { return false; }
}

void AhkPrefetchScanner::start_ahk_bypass_detections()
{
    try{
    const std::filesystem::path prefetch_dir = xorstr_("C:\\Windows\\Prefetch");
    const std::string username = get_username();

    if (username.empty())
        return;

    std::error_code _ahk_ec;
    if (!std::filesystem::exists(prefetch_dir, _ahk_ec) || _ahk_ec) return;
    if (!std::filesystem::is_directory(prefetch_dir, _ahk_ec) || _ahk_ec) return;

    for (auto it = std::filesystem::directory_iterator(prefetch_dir,
            std::filesystem::directory_options::skip_permission_denied, _ahk_ec);
         !_ahk_ec && it != std::filesystem::directory_iterator();
         it.increment(_ahk_ec))
    {
        if (_ahk_ec) { _ahk_ec.clear(); continue; }
        const auto& entry = *it;
        if (!is_cmd_prefetch(entry.path()))
            continue;

        prefetch_parser parser(c_utils::path_to_utf8(entry.path()));
        if (!parser.success())
            continue;

        auto filenames = parser.get_filenames_strings();
        std::unordered_set<std::string> seen_paths;

        for (const auto& wname : filenames)
        {
            std::string path = ascii_wstring_to_string(wname);
            path = replace_volume_guid(path);

            if (is_whitelisted(path, username))
                continue;

            if (is_pe_file(path))
                continue;

            if (is_file_too_large(path, MAX_SCRIPT_SIZE))
                continue;

            if (!seen_paths.insert(path).second)
                continue;

            std::string content;
            if (!read_file(path, content))
                continue;

            std::string lower_content = content;
            std::transform(
                lower_content.begin(),
                lower_content.end(),
                lower_content.begin(),
                ::tolower
            );

            bool matched = false;

            for (const auto& kw : ahk_keywords)
            {
                if (lower_content.find(kw) != std::string::npos)
                {
                    matched = true;
                    break;
                }
            }

            if (!matched)
                continue;

            normalize_to_single_line(content);

            LOG ( WARNING , xorstr_("N/A")) << xorstr_("Possible AHK Bypass Script Found:File ->   ") << path << xorstr_("  Script ->   ") << content;

        }
    }
    }
    catch (...) {}
}