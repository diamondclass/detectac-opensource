#pragma once

#include "../../pch.h"

class rainbow_six {
public:
    static bool is_valid_uuid(const std::string& s);
    static void start_r6alt_scan();

private:
    using account_set = std::set<std::string>;

    static std::string to_lower_copy(const std::string& value);
    static std::string trim_copy(const std::string& value);
    static std::string strip_quotes(const std::string& value);

    static std::string get_env(const char* name);
    static std::string get_ubisoft_launcher_root();
    static std::vector<std::string> get_documents_roots();

    static void add_account(account_set& accounts, const std::string& uuid);

    static void scan_siege_profiles(account_set& accounts);
    static void scan_uuid_named_entries(account_set& accounts, const std::string& directory);
    static void scan_avatar_cache(account_set& accounts, const std::string& launcher_root);
    static std::string read_remembered_username(const std::string& launcher_root);
};

inline auto c_r6alts = std::make_unique<rainbow_six>();
