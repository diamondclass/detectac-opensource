#pragma once

#include "../../pch.h"


class ai_scanner
{
public:
    static void scan_ai();
    static std::string get_local_app_data_path();
    static std::string get_file_hash(const std::string& file_path);
    static bool is_hidden_or_system(const std::filesystem::directory_entry& entry);
};

inline auto c_ai = std::make_unique<ai_scanner>();