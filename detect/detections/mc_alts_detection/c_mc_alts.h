#pragma once

#include "../../pch.h"

#undef min
#undef max

class process_utilities {
public:
    static std::string get_username();
    static bool contains_pattern(const std::string& data, const std::vector<std::string>& patterns);
    static std::vector<std::string> extract_readable_strings(const std::string& data);
    static bool contains_numbers(const std::string& str);
    static bool find_process_by_name(const std::string& process_name, DWORD& pid, DWORD& parent_pid);
    static std::string get_process_name(DWORD pid);
    static std::string sanitize_string(const std::string& str, const std::regex& regex_pattern, std::unordered_set<std::string>& unique_outputs);
    static std::vector<std::string> read_and_sanitize_json(const std::string& username, std::unordered_set<std::string>& unique_outputs);
    static void search_strings_in_process(DWORD pid, const std::vector<std::string>& patterns,
        bool sanitize_for_feather_client, bool sanitize_for_badlion_client, bool sanitize_for_lunar_client,
        std::unordered_set<std::string>& unique_outputs);
    static bool doesFileExist(const std::wstring& filePath);
    static void checkfile();
    static bool is_drive_letter_path(const std::wstring& path);
    static std::string wide_to_utf8(const std::wstring& wide);
    static void list_volume_folder_mounts();

    static void start_mc_alts();
    static void start_mc_alts11();
};

inline auto c_mc_alts = std::make_unique<process_utilities>();