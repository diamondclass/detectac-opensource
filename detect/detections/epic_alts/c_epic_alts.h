#pragma once

#include "../../pch.h"

class epic_games {
public:
    static void start_epic_alt_scan();

private:
    using account_set = std::set<std::string>;

    static std::string to_lower_copy(const std::string& value);
    static std::string trim_copy(const std::string& value);
    static bool is_account_id(const std::string& value);
    static std::string wide_to_narrow(const std::wstring& value);

    static std::string get_local_appdata();
    static bool read_registry_string(HKEY root, const wchar_t* sub_key, const wchar_t* value_name, std::string& out);
    static std::string read_file_capped(const std::string& path, size_t max_bytes);

    static void add_account(account_set& accounts, const std::string& id);

    static void scan_registry_identifiers(account_set& accounts, std::string& machine_id);
    static void scan_launcher_configs(account_set& accounts, const std::string& local_appdata);
    static void scan_launcher_data(account_set& accounts, const std::string& local_appdata);
    static void scan_fortnite_cloud(account_set& accounts, const std::string& local_appdata);
    static void scan_crash_contexts(account_set& accounts, const std::string& crashes_root);

    static void parse_game_user_settings(const std::string& path, account_set& accounts);
};

inline auto c_epicalts = std::make_unique<epic_games>();
