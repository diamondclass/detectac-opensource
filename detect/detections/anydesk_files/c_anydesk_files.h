#pragma once

#include "../../pch.h"

class file_transfer_parser
{
public:
    static std::string get_username();
    static bool is_wide_string(const std::string& str);
    static std::unordered_set<std::string> extract_unique_quoted_strings(const std::string& filepath);
    static std::string clean_string(const std::string& str);
    static void start_anydesk_scan();
};

inline auto c_anydesk = std::make_unique<file_transfer_parser>();