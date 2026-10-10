#pragma once

#include "../prefetch_parser/prefetch_parser.h"
#include "../../pch.h"

class AhkPrefetchScanner
{
public:

    static constexpr uintmax_t MAX_SCRIPT_SIZE = 1024 * 1024;

    static void start_ahk_bypass_detections();

    static void normalize_to_single_line(std::string& s);
    static std::string get_username();
    static bool is_cmd_prefetch(const std::filesystem::path& p);
    static std::string replace_volume_guid(const std::string& path);
    static bool is_whitelisted(const std::string& path, const std::string& username);
    static bool read_file(const std::string& path, std::string& out);
    static const std::vector<std::string> ahk_keywords;
    static bool is_pe_file(const std::string& path);
    static bool is_file_too_large(const std::string& path, uintmax_t max_size);
};

inline auto c_ahk = std::make_unique<AhkPrefetchScanner>();