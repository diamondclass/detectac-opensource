#include "c_vbs.h"

std::string vbs_scanner::wstring_to_string(const std::wstring& wstr) {
    try {
        if (wstr.empty()) return std::string();

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
        return str;
    }
    catch (...) { return ""; }
}

std::wstring vbs_scanner::string_to_wstring(const std::string& str) {
    try {
        if (str.empty()) return std::wstring();

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], size_needed);
        return wstr;
    }
    catch (...) { return L""; }
}

std::string vbs_scanner::format_time(time_t time) {
    try {
        if (time <= 0 || time > 32535244799LL) {
            return xorstr_("N/A");
        }

        struct tm timeinfo;
        if (localtime_s(&timeinfo, &time) != 0) {
            return xorstr_("N/A");
        }

        char buffer[80];
        if (strftime(buffer, sizeof(buffer), xorstr_("%Y-%m-%d %H:%M:%S"), &timeinfo) == 0) {
            return xorstr_("N/A");
        }

        return std::string(buffer);
    }
    catch (...) { return ""; }
}

std::vector<std::string> vbs_scanner::get_drive_letters() {
    try {
        std::vector<std::string> drives;
        DWORD drive_mask = GetLogicalDrives();

        for (char letter = 'A'; letter <= 'Z'; ++letter) {
            if (drive_mask & 1) {
                std::string drive = std::string(1, letter) + xorstr_(":\\");
                drives.push_back(drive);
            }
            drive_mask >>= 1;
        }

        return drives;
    }
    catch (...) { return {}; }
}

std::wstring vbs_scanner::get_relative_path(const std::wstring& path) {
    try {
        if (path.length() > 0 && path[0] == L'\\') {
            if (path.find(xorstr_(L"\\VOLUME{")) == 0) {
                size_t brace_end = path.find(xorstr_(L"}"), 0);
                if (brace_end == std::wstring::npos) {
                    return path;
                }

                size_t path_start = path.find(xorstr_(L"\\"), brace_end);
                if (path_start == std::wstring::npos || path_start + 1 >= path.length()) {
                    return xorstr_(L"");
                }

                return path.substr(path_start + 1);
            }
            else if (path.find(xorstr_(L"\\DEVICE\\")) == 0) {
                size_t device_end = path.find(xorstr_(L"\\"), 8);
                if (device_end == std::wstring::npos) {
                    return path;
                }

                size_t path_start = path.find(xorstr_(L"\\"), device_end + 1);
                if (path_start == std::wstring::npos || path_start + 1 >= path.length()) {
                    return xorstr_(L"");
                }

                return path.substr(path_start + 1);
            }
            else {
                return path.substr(1);
            }
        }

        return path;
    }
    catch (...) { return L""; }
}

bool vbs_scanner::is_script_host_prefetch(const std::filesystem::path& p) {
    try {
        std::string name = c_utils::path_to_utf8(p.filename());
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);

        if (!name.ends_with(xorstr_(".pf")))
            return false;

        return name.rfind(xorstr_("wscript.exe-"), 0) == 0 ||
               name.rfind(xorstr_("cscript.exe-"), 0) == 0;
    }
    catch (...) { return false; }
}

bool vbs_scanner::ends_with_vbs(const std::wstring& path) {
    try {
        if (path.length() <= 4)
            return false;

        std::wstring ext = path.substr(path.length() - 4);
        for (size_t i = 0; i < ext.length(); i++) {
            ext[i] = std::towlower(ext[i]);
        }

        return ext == xorstr_(L".vbs");
    }
    catch (...) { return false; }
}

std::wstring vbs_scanner::resolve_volume_to_drive(const std::wstring& path, const std::vector<std::string>& drives, bool& found) {
    try {
        found = false;

        std::wstring relative_path = get_relative_path(path);
        if (relative_path.empty()) {
            found = false;
            return xorstr_(L"?:\\") + path;
        }

        std::vector<std::wstring> common_prefixes;
        common_prefixes.push_back(xorstr_(L""));
        common_prefixes.push_back(xorstr_(L"Windows\\"));
        common_prefixes.push_back(xorstr_(L"Windows\\System32\\"));
        common_prefixes.push_back(xorstr_(L"Program Files\\"));
        common_prefixes.push_back(xorstr_(L"Program Files (x86)\\"));
        common_prefixes.push_back(xorstr_(L"ProgramData\\"));
        common_prefixes.push_back(xorstr_(L"Users\\"));

        std::error_code _fs_ec;

        for (size_t d = 0; d < drives.size(); d++) {
            std::wstring drive_w = string_to_wstring(drives[d]);

            std::wstring test_path = drive_w + relative_path;
            if (std::filesystem::exists(test_path, _fs_ec) && !_fs_ec) {
                found = true;
                return test_path;
            }
            _fs_ec.clear();

            for (size_t p = 0; p < common_prefixes.size(); p++) {
                test_path = drive_w + common_prefixes[p] + relative_path;
                if (std::filesystem::exists(test_path, _fs_ec) && !_fs_ec) {
                    found = true;
                    return test_path;
                }
                _fs_ec.clear();
            }

            std::wstring upper_path = relative_path;
            for (size_t i = 0; i < upper_path.length(); i++) {
                upper_path[i] = std::towupper(upper_path[i]);
            }

            if (upper_path.find(xorstr_(L"SYSTEM32\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(9);
                test_path = drive_w + xorstr_(L"Windows\\System32\\") + without_prefix;
                if (std::filesystem::exists(test_path, _fs_ec) && !_fs_ec) {
                    found = true;
                    return test_path;
                }
                _fs_ec.clear();
            }
            else if (upper_path.find(xorstr_(L"WINDOWS\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(8);
                test_path = drive_w + xorstr_(L"Windows\\") + without_prefix;
                if (std::filesystem::exists(test_path, _fs_ec) && !_fs_ec) {
                    found = true;
                    return test_path;
                }
                _fs_ec.clear();
            }
            else if (upper_path.find(xorstr_(L"SYSWOW64\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(9);
                test_path = drive_w + xorstr_(L"Windows\\SysWOW64\\") + without_prefix;
                if (std::filesystem::exists(test_path, _fs_ec) && !_fs_ec) {
                    found = true;
                    return test_path;
                }
                _fs_ec.clear();
            }

            if (relative_path.length() > 0 && relative_path[0] == L'$') {
                test_path = drive_w + relative_path;
                if (drives[d] == xorstr_("C:\\")) {
                    found = true;
                    return test_path;
                }
            }
        }

        found = false;
        return xorstr_(L"?:\\") + relative_path;
    }
    catch (...) { return L""; }
}

void vbs_scanner::start_vbs_detection() {
    try {
        const std::filesystem::path prefetch_dir = xorstr_("C:\\Windows\\Prefetch");

        std::error_code _fs_ec;
        if (!std::filesystem::exists(prefetch_dir, _fs_ec) || _fs_ec) return;
        if (!std::filesystem::is_directory(prefetch_dir, _fs_ec) || _fs_ec) return;

        std::vector<std::string> drives = get_drive_letters();

        std::vector<std::filesystem::path> script_host_prefetch_files;

        for (auto it = std::filesystem::directory_iterator(prefetch_dir, std::filesystem::directory_options::skip_permission_denied, _fs_ec);
             !_fs_ec && it != std::filesystem::directory_iterator();
             it.increment(_fs_ec))
        {
            if (_fs_ec) { _fs_ec.clear(); continue; }
            const auto& entry = *it;
            if (!entry.is_regular_file(_fs_ec) || _fs_ec) { _fs_ec.clear(); continue; }

            if (!is_script_host_prefetch(entry.path()))
                continue;

            script_host_prefetch_files.push_back(entry.path());
        }

        for (size_t pf_idx = 0; pf_idx < script_host_prefetch_files.size(); pf_idx++) {
            prefetch_parser parser(c_utils::path_to_utf8(script_host_prefetch_files[pf_idx]));

            if (!parser.success()) {
                continue;
            }

            time_t last_exec_time = parser.executed_time();
            std::string timestamp = format_time(last_exec_time);

            std::vector<std::wstring> filenames = parser.get_filenames_strings();
            std::unordered_set<std::string> seen_paths;

            for (size_t f_idx = 0; f_idx < filenames.size(); f_idx++) {
                std::wstring file = filenames[f_idx];
                if (file.empty()) continue;

                if (!ends_with_vbs(file))
                    continue;

                bool found = false;
                std::wstring resolved_path = resolve_volume_to_drive(file, drives, found);
                std::string resolved_str = wstring_to_string(resolved_path);

                if (resolved_str.empty())
                    continue;

                if (!seen_paths.insert(resolved_str).second)
                    continue;

                if (!found) {
                    LOG(WARNING, timestamp) << xorstr_("Not Found Executed VBS Script:") << resolved_str;
                }
                else {
                    LOG(WARNING, timestamp) << xorstr_("Executed VBS Script:") << resolved_str;
                }
            }
        }

        return;
    }
    catch (...) {}
}
