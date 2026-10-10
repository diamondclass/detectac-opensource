#pragma once

#include "../../pch.h"
#include "../prefetch_parser/prefetch_parser.h"

class vbs_scanner {
public:
    static std::string wstring_to_string(const std::wstring& wstr);
    static std::wstring string_to_wstring(const std::string& str);

    static std::string format_time(time_t time);

    static std::vector<std::string> get_drive_letters();
    static std::wstring get_relative_path(const std::wstring& path);

    static bool is_script_host_prefetch(const std::filesystem::path& p);
    static bool ends_with_vbs(const std::wstring& path);

    static std::wstring resolve_volume_to_drive(
        const std::wstring& path,
        const std::vector<std::string>& drives,
        bool& found
    );
    static void start_vbs_detection();
};

inline auto c_vbs = std::make_unique<vbs_scanner>();
