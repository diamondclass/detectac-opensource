#include "c_cmd_and_bat.h"

std::string CmdPrefetchScanner::GetUsername()
{
    try{
    char buffer[256];
    DWORD size = sizeof(buffer);

    if (GetUserNameA(buffer, &size))
        return std::string(buffer);

    return {};
    }
    catch (...) {}
}

bool CmdPrefetchScanner::IsCmdPrefetch(const std::filesystem::path& p)
{
    try{
    if (p.extension() != xorstr_(".pf"))
        return false;

    std::string name = c_utils::path_to_utf8(p.filename());
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);

    return name.rfind(xorstr_("cmd.exe-"), 0) == 0;
    }
    catch (...) {}
}

std::string CmdPrefetchScanner::ReplaceVolumeGuid(const std::string& path)
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

bool CmdPrefetchScanner::EndsWithBatOrCmd(const std::string& s)
{
    try{
    std::string lower = s;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    return lower.size() > 4 &&
        (lower.ends_with(xorstr_(".bat")) || lower.ends_with(xorstr_(".cmd")));
    }
    catch (...) {}
}

bool CmdPrefetchScanner::EndsWithTpm(const std::string& s)
{
    try {
        std::string lower = s;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        return lower.size() > 4 && lower.ends_with(xorstr_(".tpm"));
    }
    catch (...) { return false; }
}

bool CmdPrefetchScanner::IsInUserTemp(const std::string& path, const std::string& username)
{
    try {
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        std::string temp_prefix =
            xorstr_("c:\\users\\") + username + xorstr_("\\appdata\\local\\temp\\");
        std::transform(temp_prefix.begin(), temp_prefix.end(), temp_prefix.begin(), ::tolower);

        return lower.rfind(temp_prefix, 0) == 0;
    }
    catch (...) { return false; }
}

bool CmdPrefetchScanner::IsWhitelisted(const std::string& path, const std::string& username)
{
    try{
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::string whitelist =
        xorstr_("c:\\users\\") + username + xorstr_("\\appdata\\local\\temp\\msbuildtemp\\");

    std::transform(whitelist.begin(), whitelist.end(), whitelist.begin(), ::tolower);

    if (lower.rfind(whitelist, 0) == 0)
        return true;

    if (lower.find(xorstr_("microsoft visual c++")) != std::string::npos)
        return true;

    if (lower.find(xorstr_("microsoft visual studio")) != std::string::npos)
        return true;

    if (lower.find(xorstr_("ghidra")) != std::string::npos)
        return true;

    return false;
    }
    catch (...) { return false; }
}

void CmdPrefetchScanner::start_cmd_and_bat_detection()
{
    try{
    const std::filesystem::path prefetch_dir = xorstr_("C:\\Windows\\Prefetch");
    const std::string username = GetUsername();

    if (username.empty())
        return;

    std::error_code _fs_ec;
    if (!std::filesystem::exists(prefetch_dir, _fs_ec) || _fs_ec) return;
    if (!std::filesystem::is_directory(prefetch_dir, _fs_ec) || _fs_ec) return;

    for (auto it = std::filesystem::directory_iterator(prefetch_dir, std::filesystem::directory_options::skip_permission_denied, _fs_ec);
         !_fs_ec && it != std::filesystem::directory_iterator();
         it.increment(_fs_ec))
    {
        if (_fs_ec) { _fs_ec.clear(); continue; }
        const auto& entry = *it;
        if (!IsCmdPrefetch(entry.path()))
            continue;

        prefetch_parser parser(c_utils::path_to_utf8(entry.path()));
        if (!parser.success())
            continue;

        auto filenames = parser.get_filenames_strings();
        std::unordered_set<std::string> seen_paths;

        for (const auto& wname : filenames)
        {
            std::string name = ascii_wstring_to_string(wname);
            name = ReplaceVolumeGuid(name);

            if (EndsWithTpm(name) && IsInUserTemp(name, username))
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("FLK Bypass Detected:") << name;

            if (IsWhitelisted(name, username))
                continue;

            if (!EndsWithBatOrCmd(name))
                continue;

            if (!seen_paths.insert(name).second)
                continue;

            LOG(WARNING, xorstr_("N/A")) << xorstr_("Executed .bat/.cmd File:") << name;
        }
    }
    return;
    }
    catch (...) {}
}