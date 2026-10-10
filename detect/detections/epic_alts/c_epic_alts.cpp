#include "c_epic_alts.h"

std::string epic_games::to_lower_copy(const std::string& value) {
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

std::string epic_games::trim_copy(const std::string& value) {
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

bool epic_games::is_account_id(const std::string& value) {
    try {
        if (value.size() != 32) return false;
        for (char c : value) {
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (!hex) return false;
        }
        return true;
    }
    catch (...) {}
    return false;
}

std::string epic_games::wide_to_narrow(const std::wstring& value) {
    try {
        if (value.empty()) return {};

        int needed = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
            nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return {};

        std::string result(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()),
            &result[0], needed, nullptr, nullptr);
        return result;
    }
    catch (...) {}
    return {};
}

std::string epic_games::get_local_appdata() {
    try {
        char buffer[MAX_PATH]{};
        DWORD length = GetEnvironmentVariableA(xorstr_("LOCALAPPDATA"), buffer, MAX_PATH);
        if (length > 0 && length < MAX_PATH) return std::string(buffer, length);

        char profile[MAX_PATH]{};
        length = GetEnvironmentVariableA(xorstr_("USERPROFILE"), profile, MAX_PATH);
        if (length > 0 && length < MAX_PATH) {
            return std::string(profile, length) + xorstr_("\\AppData\\Local");
        }
    }
    catch (...) {}
    return {};
}

bool epic_games::read_registry_string(HKEY root, const wchar_t* sub_key, const wchar_t* value_name, std::string& out) {
    try {
        DWORD type = 0;
        DWORD size = 0;

        LONG status = RegGetValueW(root, sub_key, value_name,
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, &type, nullptr, &size);
        if (status != ERROR_SUCCESS || size < sizeof(wchar_t) || size > 64 * 1024) return false;

        std::wstring buffer(size / sizeof(wchar_t), L'\0');
        status = RegGetValueW(root, sub_key, value_name,
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, &type, &buffer[0], &size);
        if (status != ERROR_SUCCESS) return false;

        size_t terminator = buffer.find(L'\0');
        if (terminator != std::wstring::npos) buffer.resize(terminator);

        out = wide_to_narrow(buffer);
        return !out.empty();
    }
    catch (...) {}
    return false;
}

std::string epic_games::read_file_capped(const std::string& path, size_t max_bytes) {
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return {};

        std::string content;
        content.resize(max_bytes);
        file.read(&content[0], static_cast<std::streamsize>(max_bytes));

        std::streamsize read = file.gcount();
        if (read <= 0) return {};

        content.resize(static_cast<size_t>(read));
        return content;
    }
    catch (...) {}
    return {};
}

void epic_games::add_account(account_set& accounts, const std::string& id) {
    try {
        if (!is_account_id(id)) return;
        accounts.insert(to_lower_copy(id));
    }
    catch (...) {}
}

void epic_games::scan_registry_identifiers(account_set& accounts, std::string& machine_id) {
    try {
        std::string account_id;
        if (read_registry_string(HKEY_CURRENT_USER,
            xorstr_(L"Software\\Epic Games\\Unreal Engine\\Identifiers"),
            xorstr_(L"AccountId"), account_id)) {
            add_account(accounts, trim_copy(account_id));
        }

        std::string raw_machine_id;
        if (read_registry_string(HKEY_CURRENT_USER,
            xorstr_(L"Software\\Epic Games\\Unreal Engine\\Identifiers"),
            xorstr_(L"MachineId"), raw_machine_id)) {
            machine_id = to_lower_copy(trim_copy(raw_machine_id));
        }
    }
    catch (...) {}
}

void epic_games::parse_game_user_settings(const std::string& path, account_set& accounts) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) return;

        std::string line;

        while (std::getline(file, line)) {
            std::string trimmed = trim_copy(line);
            if (trimmed.size() < 3) continue;
            if (trimmed.front() != '[' || trimmed.back() != ']') continue;

            std::string section = trimmed.substr(1, trimmed.size() - 2);
            if (section.find('_') != 32) continue;

            add_account(accounts, section.substr(0, 32));
        }
    }
    catch (...) {}
}

void epic_games::scan_launcher_configs(account_set& accounts, const std::string& local_appdata) {
    try {
        std::string config_root = local_appdata + xorstr_("\\EpicGamesLauncher\\Saved\\Config");
        std::string pattern = config_root + xorstr_("\\*");

        WIN32_FIND_DATAA find_data{};
        HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) return;

        do {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

            std::string name = find_data.cFileName;
            if (name == xorstr_(".") || name == xorstr_("..")) continue;

            std::string ini_path = config_root + xorstr_("\\") + name + xorstr_("\\GameUserSettings.ini");
            parse_game_user_settings(ini_path, accounts);
        } while (FindNextFileA(find_handle, &find_data) != 0);

        FindClose(find_handle);
    }
    catch (...) {}
}

void epic_games::scan_launcher_data(account_set& accounts, const std::string& local_appdata) {
    try {
        std::string data_root = local_appdata + xorstr_("\\EpicGamesLauncher\\Saved\\Data");
        std::string pattern = data_root + xorstr_("\\*.dat");

        WIN32_FIND_DATAA find_data{};
        HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) return;

        do {
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            std::string name = find_data.cFileName;

            std::string prefix = xorstr_("OC_");
            if (name.size() > prefix.size() && name.compare(0, prefix.size(), prefix) == 0) {
                name = name.substr(prefix.size());
            }

            std::string suffix = xorstr_(".dat");
            if (name.size() > suffix.size() &&
                to_lower_copy(name.substr(name.size() - suffix.size())) == suffix) {
                name = name.substr(0, name.size() - suffix.size());
            }

            add_account(accounts, name);
        } while (FindNextFileA(find_handle, &find_data) != 0);

        FindClose(find_handle);
    }
    catch (...) {}
}

void epic_games::scan_fortnite_cloud(account_set& accounts, const std::string& local_appdata) {
    try {
        std::string cloud_root = local_appdata + xorstr_("\\FortniteGame\\Saved\\Cloud");
        std::string pattern = cloud_root + xorstr_("\\*");

        WIN32_FIND_DATAA find_data{};
        HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) return;

        do {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

            std::string name = find_data.cFileName;
            if (name == xorstr_(".") || name == xorstr_("..")) continue;

            add_account(accounts, name);
        } while (FindNextFileA(find_handle, &find_data) != 0);

        FindClose(find_handle);
    }
    catch (...) {}
}

void epic_games::scan_crash_contexts(account_set& accounts, const std::string& crashes_root) {
    try {
        std::string pattern = crashes_root + xorstr_("\\*");

        WIN32_FIND_DATAA find_data{};
        HANDLE find_handle = FindFirstFileA(pattern.c_str(), &find_data);
        if (find_handle == INVALID_HANDLE_VALUE) return;

        const std::string open_tag = xorstr_("<EpicAccountId>");
        const std::string close_tag = xorstr_("</EpicAccountId>");

        do {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

            std::string name = find_data.cFileName;
            if (name == xorstr_(".") || name == xorstr_("..")) continue;

            std::string xml_path = crashes_root + xorstr_("\\") + name + xorstr_("\\CrashContext.runtime-xml");
            std::string content = read_file_capped(xml_path, 512 * 1024);
            if (content.empty()) continue;

            size_t position = 0;
            while ((position = content.find(open_tag, position)) != std::string::npos) {
                size_t start = position + open_tag.size();
                size_t end = content.find(close_tag, start);
                if (end == std::string::npos) break;

                add_account(accounts, trim_copy(content.substr(start, end - start)));

                position = end + close_tag.size();
            }
        } while (FindNextFileA(find_handle, &find_data) != 0);

        FindClose(find_handle);
    }
    catch (...) {}
}

void epic_games::start_epic_alt_scan() {
    try {
        std::string local_appdata = get_local_appdata();
        if (local_appdata.empty()) return;

        account_set accounts;
        std::string machine_id;

        scan_registry_identifiers(accounts, machine_id);
        scan_launcher_configs(accounts, local_appdata);
        scan_launcher_data(accounts, local_appdata);
        scan_fortnite_cloud(accounts, local_appdata);
        scan_crash_contexts(accounts, local_appdata + xorstr_("\\EpicGamesLauncher\\Saved\\Crashes"));
        scan_crash_contexts(accounts, local_appdata + xorstr_("\\FortniteGame\\Saved\\Crashes"));

        if (!machine_id.empty()) accounts.erase(machine_id);

        for (const auto& id : accounts) {
            LOG(INFO, xorstr_("N/A")) << xorstr_("Epic ID Found:") << xorstr_("ID - ") << id
                << xorstr_(" (Could not find username)");
        }
    }
    catch (...) {}
}
