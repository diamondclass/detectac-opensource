#pragma once

#include "../prefetch_parser/prefetch_parser.h"
#include "../../pch.h"

class CmdPrefetchScanner
{
public:
    static void start_cmd_and_bat_detection();
    static std::string GetUsername();
    static bool IsCmdPrefetch(const std::filesystem::path& p);
    static std::string ReplaceVolumeGuid(const std::string& path);
    static bool EndsWithBatOrCmd(const std::string& s);
    static bool EndsWithTpm(const std::string& s);
    static bool IsInUserTemp(const std::string& path, const std::string& username);
    static bool IsWhitelisted(const std::string& path, const std::string& username);
};

inline auto c_cb = std::make_unique<CmdPrefetchScanner>();