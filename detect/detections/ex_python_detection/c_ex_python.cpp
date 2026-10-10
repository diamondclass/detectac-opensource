#include "c_ex_python.h"

std::string python_scanner::wstring_to_string(const std::wstring& wstr) {
    try {
        if (wstr.empty()) return std::string();

        int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), NULL, 0, NULL, NULL);
        std::string str(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), &str[0], size_needed, NULL, NULL);
        return str;
    }
    catch (...) { return ""; }
}

std::wstring python_scanner::string_to_wstring(const std::string& str) {
    try {
        if (str.empty()) return std::wstring();

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), NULL, 0);
        std::wstring wstr(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &wstr[0], size_needed);
        return wstr;
    }
    catch (...) { return L""; }
}

std::string python_scanner::format_time(time_t time) {
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


std::vector<std::string> python_scanner::get_drive_letters() {
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

std::wstring python_scanner::get_relative_path(const std::wstring& path) {
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

bool python_scanner::has_pe_extension(const std::wstring& path) {
    try {
        size_t dot_pos = path.find_last_of(L'.');
        if (dot_pos == std::wstring::npos)
            return false;

        std::wstring ext = path.substr(dot_pos);
        for (auto& c : ext)
            c = std::towlower(c);

        const wchar_t* pe_exts[] = {
            xorstr_(L".exe"), xorstr_(L".dll"), xorstr_(L".sys"),
            xorstr_(L".drv"), xorstr_(L".ocx"), xorstr_(L".cpl"),
            xorstr_(L".scr"), xorstr_(L".pyd"), xorstr_(L".com"),
            xorstr_(L".efi"), xorstr_(L".node")
        };

        for (const wchar_t* pe_ext : pe_exts) {
            if (ext == pe_ext)
                return true;
        }

        return false;
    }
    catch (...) { return false; }
}

bool python_scanner::is_pe_file(const std::wstring& filepath) {
    try {
        HANDLE hFile = CreateFileW(filepath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (hFile == INVALID_HANDLE_VALUE)
            return false;

        char header[2] = {};
        DWORD bytes_read = 0;
        BOOL result = ReadFile(hFile, header, 2, &bytes_read, nullptr);
        CloseHandle(hFile);

        if (!result || bytes_read < 2)
            return false;

        return (header[0] == 'M' && header[1] == 'Z');
    }
    catch (...) { return false; }
}

std::wstring python_scanner::resolve_volume_to_drive(const std::wstring& path, const std::vector<std::string>& drives, bool& found) {
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

        for (size_t d = 0; d < drives.size(); d++) {
            std::wstring drive_w = string_to_wstring(drives[d]);

            std::wstring test_path = drive_w + relative_path;
            if (std::filesystem::exists(test_path)) {
                found = true;
                return test_path;
            }

            for (size_t p = 0; p < common_prefixes.size(); p++) {
                test_path = drive_w + common_prefixes[p] + relative_path;
                if (std::filesystem::exists(test_path)) {
                    found = true;
                    return test_path;
                }
            }

            std::wstring upper_path = relative_path;
            for (size_t i = 0; i < upper_path.length(); i++) {
                upper_path[i] = std::towupper(upper_path[i]);
            }

            if (upper_path.find(xorstr_(L"SYSTEM32\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(9);
                test_path = drive_w + xorstr_(L"Windows\\System32\\") + without_prefix;
                if (std::filesystem::exists(test_path)) {
                    found = true;
                    return test_path;
                }
            }
            else if (upper_path.find(xorstr_(L"WINDOWS\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(8);
                test_path = drive_w + xorstr_(L"Windows\\") + without_prefix;
                if (std::filesystem::exists(test_path)) {
                    found = true;
                    return test_path;
                }
            }
            else if (upper_path.find(xorstr_(L"SYSWOW64\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(9);
                test_path = drive_w + xorstr_(L"Windows\\SysWOW64\\") + without_prefix;
                if (std::filesystem::exists(test_path)) {
                    found = true;
                    return test_path;
                }
            }
            else if (upper_path.find(xorstr_(L"APPPATCH\\")) == 0) {
                std::wstring without_prefix = relative_path.substr(9);
                test_path = drive_w + xorstr_(L"Windows\\AppPatch\\") + without_prefix;
                if (std::filesystem::exists(test_path)) {
                    found = true;
                    return test_path;
                }
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

void python_scanner::start_python_detection() {
    try {
        try {
            std::string prefetch_dir = xorstr_("C:\\Windows\\Prefetch");

            if (!std::filesystem::exists(prefetch_dir)) {
                return;
            }

            std::vector<std::string> drives = get_drive_letters();

            bool found_python_prefetch = false;
            int prefetch_count = 0;

            std::vector<std::filesystem::path> python_prefetch_files;

            std::error_code _py_ec;
            for (auto it = std::filesystem::directory_iterator(prefetch_dir,
                    std::filesystem::directory_options::skip_permission_denied, _py_ec);
                 !_py_ec && it != std::filesystem::directory_iterator();
                 it.increment(_py_ec))
            {
                if (_py_ec) { _py_ec.clear(); continue; }
                const auto& entry = *it;
                if (!entry.is_regular_file(_py_ec) || _py_ec) { _py_ec.clear(); continue; }

                std::string filename = c_utils::path_to_utf8(entry.path().filename());

                std::string filename_upper = filename;
                for (size_t i = 0; i < filename_upper.length(); i++) {
                    filename_upper[i] = std::toupper(static_cast<unsigned char>(filename_upper[i]));
                }

                if (filename_upper.find(xorstr_("PYTHON.EXE")) == 0 &&
                    filename_upper.find(xorstr_(".PF")) != std::string::npos) {
                    python_prefetch_files.push_back(entry.path());
                }
            }

            for (size_t pf_idx = 0; pf_idx < python_prefetch_files.size(); pf_idx++) {
                found_python_prefetch = true;
                prefetch_count++;

                prefetch_parser parser(c_utils::path_to_utf8(python_prefetch_files[pf_idx]));

                if (!parser.success()) {
                    continue;
                }

                time_t last_exec_time = parser.executed_time();
                std::string timestamp = format_time(last_exec_time);

                std::vector<std::wstring> filenames = parser.get_filenames_strings();

                for (size_t f_idx = 0; f_idx < filenames.size(); f_idx++) {
                    std::wstring file = filenames[f_idx];
                    if (file.empty()) continue;

                    std::wstring file_upper = file;
                    for (size_t i = 0; i < file_upper.length(); i++) {
                        file_upper[i] = std::towupper(file_upper[i]);
                    }

                    if (file_upper.length() < 3 ||
                        file_upper.substr(file_upper.length() - 3) != xorstr_(L".PY")) {
                        continue;
                    }

                    if (file_upper.find(xorstr_(L"\\COMMON\\")) != std::wstring::npos ||
                        file_upper.find(xorstr_(L"\\LIB\\")) != std::wstring::npos) {
                        continue;
                    }

                    bool found = false;
                    std::wstring resolved_path = resolve_volume_to_drive(file, drives, found);
                    std::string resolved_str = wstring_to_string(resolved_path);

                    if (!found) {
                        LOG ( WARNING , timestamp) << xorstr_("Not Found Executed Python File:") << resolved_str;
                    }
                    else {
                        LOG(WARNING, timestamp) << xorstr_("Executed Python File:") << resolved_str;
                    }
                }
            }

            if (!found_python_prefetch) {
                return;
            }

        }
        catch (const std::exception& e) {
            return;
        }

        return;
    }
    catch (...) {}
}