#include "c_r6_alts.h"

bool rainbow_six::is_valid_uuid(const std::string& s) {
    try {
        if (s.length() != 36) return false;
        for (size_t i = 0; i < s.length(); ++i) {
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (s[i] != '-') return false;
            }
            else {
                if (!isxdigit(static_cast<unsigned char>(s[i]))) return false;
            }
        }
        return true;
    }
    catch (...) {}
    return false;
}

std::string rainbow_six::to_lower_copy(const std::string& value) {
    try {
        std::string result = value;
        for (char& c : result) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
        }
        return result;
    }
    catch (...) {}
    return {};
}

std::string rainbow_six::trim_copy(const std::string& value) {
    try {
        size_t first = 0;
        size_t last = value.size();

        while (first < last) {
            char c = value[first];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') ++first;
            else break;
        }
        while (last > first) {
            char c = value[last - 1];
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') --last;
            else break;
        }

        return value.substr(first, last - first);
    }
    catch (...) {}
    return {};
}

std::string rainbow_six::strip_quotes(const std::string& value) {
    try {
        std::string result = trim_copy(value);
        if (result.size() >= 2 &&
            ((result.front() == '"' && result.back() == '"') ||
             (result.front() == '\'' && result.back() == '\''))) {
            result = result.substr(1, result.size() - 2);
        }
        return result;
    }
    catch (...) {}
    return {};
}

std::string rainbow_six::get_env(const char* name) {
    try {
        char buffer[MAX_PATH]{};
        DWORD length = GetEnvironmentVariableA(name, buffer, MAX_PATH);
        if (length > 0 && length < MAX_PATH) return std::string(buffer, length);
    }
    catch (...) {}
    return {};
}

std::string rainbow_six::get_ubisoft_launcher_root() {
    try {
        std::string local_appdata = get_env(xorstr_("LOCALAPPDATA"));
        if (local_appdata.empty()) {
            std::string profile = get_env(xorstr_("USERPROFILE"));
            if (profile.empty()) return {};
            local_appdata = profile + xorstr_("\\AppData\\Local");
        }
        return local_appdata + xorstr_("\\Ubisoft Game Launcher");
    }
    catch (...) {}
    return {};
}

std::vector<std::string> rainbow_six::get_documents_roots() {
    try {
        std::vector<std::string> roots;

        std::string known = utils->get_known_folder_path(FOLDERID_Documents);
        if (!known.empty()) roots.push_back(known);

        std::string profile = get_env(xorstr_("USERPROFILE"));
        if (!profile.empty()) {
            std::string fallback = profile + xorstr_("\\Documents");

            bool duplicate = false;
            for (const auto& existing : roots) {
                if (to_lower_copy(existing) == to_lower_copy(fallback)) { duplicate = true; break; }
            }
            if (!duplicate) roots.push_back(fallback);
        }

        return roots;
    }
    catch (...) {}
    return {};
}

void rainbow_six::add_account(account_set& accounts, const std::string& uuid) {
    try {
        if (!is_valid_uuid(uuid)) return;
        accounts.insert(to_lower_copy(uuid));
    }
    catch (...) {}
}

void rainbow_six::scan_siege_profiles(account_set& accounts) {
    try {
        for (const auto& documents : get_documents_roots()) {
            std::string base = documents + xorstr_("\\My Games\\Rainbow Six - Siege");
            std::string pattern = base + xorstr_("\\*");

            WIN32_FIND_DATAA find_data{};
            HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
            if (find_handle == INVALID_HANDLE_VALUE) continue;

            do {
                if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

                std::string name = find_data.cFileName;
                if (name == xorstr_(".") || name == xorstr_("..")) continue;

                add_account(accounts, name);
            } while (FindNextFileA(find_handle, &find_data) != 0);

            FindClose(find_handle);
        }
    }
    catch (...) {}
}

void rainbow_six::scan_uuid_named_entries(account_set& accounts, const std::string& directory) {
    try {
        std::string pattern = directory + xorstr_("\\*");

        WIN32_FIND_DATAA find_data{};
        HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) return;

        do {
            std::string name = find_data.cFileName;
            if (name == xorstr_(".") || name == xorstr_("..")) continue;

            add_account(accounts, name);
        } while (FindNextFileA(find_handle, &find_data) != 0);

        FindClose(find_handle);
    }
    catch (...) {}
}

void rainbow_six::scan_avatar_cache(account_set& accounts, const std::string& launcher_root) {
    try {
        std::string directory = launcher_root + xorstr_("\\cache\\avatars");
        std::string pattern = directory + xorstr_("\\*");

        WIN32_FIND_DATAA find_data{};
        HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) return;

        do {
            std::string name = find_data.cFileName;
            if (name == xorstr_(".") || name == xorstr_("..")) continue;

            if (name.size() >= 36) {
                add_account(accounts, name.substr(0, 36));
            }
        } while (FindNextFileA(find_handle, &find_data) != 0);

        FindClose(find_handle);
    }
    catch (...) {}
}

std::string rainbow_six::read_remembered_username(const std::string& launcher_root) {
    try {
        std::string path = launcher_root + xorstr_("\\settings.yaml");

        std::ifstream file(path);
        if (!file.is_open()) return {};

        std::string line;
        bool in_masters = false;

        while (std::getline(file, line)) {
            std::string trimmed = trim_copy(line);
            if (trimmed.empty()) continue;

            bool indented = (!line.empty() && (line.front() == ' ' || line.front() == '\t'));

            if (!indented) {
                in_masters = (to_lower_copy(trimmed) == to_lower_copy(xorstr_("masters:")));
                continue;
            }

            if (!in_masters) continue;

            size_t colon = trimmed.find(':');
            if (colon == std::string::npos) continue;

            std::string key = to_lower_copy(trim_copy(trimmed.substr(0, colon)));
            if (key != to_lower_copy(xorstr_("username"))) continue;

            std::string value = strip_quotes(trimmed.substr(colon + 1));
            if (!value.empty()) return value;
        }
    }
    catch (...) {}
    return {};
}

void rainbow_six::start_r6alt_scan() {
    try {
        account_set accounts;

        scan_siege_profiles(accounts);

        std::string launcher_root = get_ubisoft_launcher_root();
        std::string remembered_username;

        if (!launcher_root.empty()) {
            scan_uuid_named_entries(accounts, launcher_root + xorstr_("\\cache\\club"));
            scan_uuid_named_entries(accounts, launcher_root + xorstr_("\\cache\\ownership"));
            scan_uuid_named_entries(accounts, launcher_root + xorstr_("\\cache\\settings"));
            scan_uuid_named_entries(accounts, launcher_root + xorstr_("\\savegames"));
            scan_avatar_cache(accounts, launcher_root);

            remembered_username = read_remembered_username(launcher_root);
        }

        if (accounts.empty()) {
            if (!remembered_username.empty()) {
                LOG(INFO, xorstr_("N/A")) << xorstr_("R6 Account Found:") << xorstr_("Username - ")
                    << remembered_username << xorstr_(" (Could not find ID)");
            }
            return;
        }

        bool attach_username = (accounts.size() == 1 && !remembered_username.empty());

        for (const auto& id : accounts) {
            if (attach_username) {
                LOG(INFO, xorstr_("N/A")) << xorstr_("R6 Account Found:") << xorstr_("Username - ")
                    << remembered_username << xorstr_(" | ID - ") << id;
            }
            else {
                LOG(INFO, xorstr_("N/A")) << xorstr_("R6 ID Found:") << xorstr_("ID - ") << id
                    << xorstr_(" (Could not find username)");
            }
        }
    }
    catch (...) {}
}
