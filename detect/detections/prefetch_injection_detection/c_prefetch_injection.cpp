#include "c_prefetch_injection.h"

std::string PrefetchScanner::format_last_runtime(time_t t) {
    try {
        if (t <= 0 || t > 32535244799LL) return xorstr_("N/A");
        struct tm tm_buf;
        if (localtime_s(&tm_buf, &t) != 0) return xorstr_("N/A");
        char buf[64];
        if (strftime(buf, sizeof(buf), xorstr_("%Y-%m-%d %H:%M:%S"), &tm_buf) == 0) return xorstr_("N/A");
        return buf;
    }
    catch (...) { return xorstr_("N/A"); }
}

bool PrefetchScanner::contains_blocked_name(const std::wstring& path) {
    try {
        std::wstring upper = path;
        std::transform(upper.begin(), upper.end(), upper.begin(), ::towupper);

        static const std::vector<std::wstring> blocked = {
            xorstr_(L"FIVEM"),
            xorstr_(L"REDM"),
            xorstr_(L"NOTEPAD.EXE"),
            xorstr_(L"CODE.EXE"),
            xorstr_(L"NOTEPAD++.EXE"),
            xorstr_(L"LASTACTIVITYVIEW.EXE")
        };

        for (const auto& b : blocked) {
            if (upper.find(b) != std::wstring::npos)
                return true;
        }

        return false;
    }
    catch (...) { return false; }
}

std::string PrefetchScanner::wstring_to_string(const std::wstring& wstr) {
    try {
        if (wstr.empty()) return xorstr_("");
        int size = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (size <= 0) return xorstr_("");
        std::string result(size - 1, 0);
        WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, result.data(), size, nullptr, nullptr);
        return result;
    }
    catch (...) { return xorstr_(""); }
}

bool PrefetchScanner::contains_citizenfx_ini(const std::wstring& wpath) {
    try {
        const wchar_t* needle = xorstr_(L"CITIZENFX.INI");
        std::wstring path = wpath;
        std::transform(path.begin(), path.end(), path.begin(), ::towupper);
        return path.find(needle) != std::wstring::npos;
    }
    catch (...) { return false; }
}

std::wstring PrefetchScanner::get_executable_name_from_data(const std::vector<char>& data) {
    try {
        std::wstring result;
        constexpr size_t offset = 0x10;
        constexpr size_t max_chars = 30;
        if (data.size() < offset + 60) return result;
        const wchar_t* ptr = reinterpret_cast<const wchar_t*>(data.data() + offset);
        for (size_t i = 0; i < max_chars && ptr[i] != L'\0'; ++i)
            result.push_back(ptr[i]);
        return result;
    }
    catch (...) { return L""; }
}

std::wstring PrefetchScanner::get_executable_path(const std::vector<std::wstring>& associated_files, const std::wstring& exe_name) {
    try {
        if (exe_name.empty()) return {};
        std::wstring exe_upper = exe_name;
        std::transform(exe_upper.begin(), exe_upper.end(), exe_upper.begin(), ::towupper);
        std::wstring suffix = xorstr_(L"\\");
        suffix += exe_upper;
        for (const auto& path : associated_files) {
            if (path.length() < suffix.length()) continue;
            std::wstring path_upper = path;
            std::transform(path_upper.begin(), path_upper.end(), path_upper.begin(), ::towupper);
            if (path_upper.back() != L'\\' && path_upper.length() >= suffix.length() &&
                path_upper.compare(path_upper.length() - suffix.length(), suffix.length(), suffix) == 0)
                return path;
        }
        return {};
    }
    catch (...) { return {}; }
}

std::vector<char> PrefetchScanner::get_prefetch_data(const std::string& file_path) {
    try {
        std::vector<char> content;
        if (!read_file(file_path, content) || content.size() < 0x100) return {};
        if (content.at(0) == 'M' && content.at(1) == 'A' && content.at(2) == 'M') {
            using RtlDecompressBufferEx = NTSTATUS(__stdcall*)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG, PVOID);
            using RtlGetCompressionWorkSpaceSize = NTSTATUS(__stdcall*)(USHORT, PULONG, PULONG);
            auto compression_workspace_size = reinterpret_cast<RtlGetCompressionWorkSpaceSize>(GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("RtlGetCompressionWorkSpaceSize")));
            auto decompress_buffer_ex = reinterpret_cast<RtlDecompressBufferEx>(GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("RtlDecompressBufferEx")));
            if (!compression_workspace_size || !decompress_buffer_ex) return {};
            std::span data_span(content.data(), 0x8);
            const auto signature = *reinterpret_cast<std::uint32_t*>(data_span.data());
            const auto decompressed_size = *reinterpret_cast<std::uint32_t*>(data_span.data() + 0x4);
            if ((signature & 0x00FFFFFF) != 0x004d414d) return {};
            const auto compression_format = (signature & 0x0F000000) >> 24;
            ULONG compressed_buffer_workspace_size = 0, compress_fragment_workspace_size = 0;
            if (compression_workspace_size(compression_format, reinterpret_cast<PULONG>(&compressed_buffer_workspace_size), reinterpret_cast<PULONG>(&compress_fragment_workspace_size)) != 0) return {};
            content.erase(content.begin(), content.begin() + 8);
            std::vector<char> decompressed_data(decompressed_size);
            ULONG final_uncompressed_size;
            auto* workspace = malloc(static_cast<size_t>(compressed_buffer_workspace_size));
            if (!workspace) return {};
            if (decompress_buffer_ex(compression_format, reinterpret_cast<PUCHAR>(decompressed_data.data()), static_cast<ULONG>(decompressed_size), reinterpret_cast<PUCHAR>(content.data()), static_cast<ULONG>(content.size()), &final_uncompressed_size, workspace) != 0) {
                free(workspace);
                return {};
            }
            free(workspace);
            return decompressed_data;
        }
        if (content.at(4) == 'S' && content.at(5) == 'C' && content.at(6) == 'C' && content.at(7) == 'A') return content;
        return {};
    }
    catch (...) { return {}; }
}

std::wstring PrefetchScanner::extract_path_from_volume(const std::wstring& volume_path) {
    try {
        size_t vol_start = volume_path.find(xorstr_(L"VOLUME{"));
        if (vol_start == std::wstring::npos) return volume_path;
        size_t vol_end = volume_path.find(xorstr_(L"}"), vol_start);
        if (vol_end == std::wstring::npos) return volume_path;
        if (vol_end + 1 < volume_path.length() && volume_path[vol_end + 1] == L'\\')
            return volume_path.substr(vol_end + 2);
        return volume_path.substr(vol_end + 1);
    }
    catch (...) { return volume_path; }
}

std::wstring PrefetchScanner::resolve_volume_to_drive(const std::wstring& volume_path) {
    try {
        std::wstring path = extract_path_from_volume(volume_path);
        if (path.empty()) return {};
        for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
            std::wstring test_path = std::wstring(1, drive) + xorstr_(L":\\") + path;
            DWORD attrs = GetFileAttributesW(test_path.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && !(attrs & FILE_ATTRIBUTE_DIRECTORY))
                return test_path;
        }
        return {};
    }
    catch (...) { return {}; }
}

void PrefetchScanner::start_prefetch_injections() {
    try {
        const char* prefetch_dir = xorstr_("C:\\Windows\\Prefetch");
        WIN32_FIND_DATAA find_data{};
        std::string search_path = std::string(prefetch_dir) + xorstr_("\\*");
        std::set<std::wstring> seen_paths;
        std::vector<std::pair<std::wstring, std::string>> not_found_paths;
        HANDLE hFind = FindFirstFileA(search_path.c_str(), &find_data);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;

            const std::string filename(find_data.cFileName);
            if (filename.size() < 4) continue;

            const std::string ext = filename.substr(filename.size() - 3);
            if (_stricmp(ext.c_str(), xorstr_(".pf")) != 0) continue;

            std::string full_path = std::string(prefetch_dir) + xorstr_("\\") + filename;

            prefetch_parser parser(full_path);
            if (!parser.success()) continue;

            auto associated_files = parser.get_filenames_strings();

            bool has_citizenfx = false;
            for (const auto& wpath : associated_files) {
                if (contains_citizenfx_ini(wpath)) {
                    has_citizenfx = true;
                    break;
                }
            }
            if (!has_citizenfx) continue;

            std::vector<char> data = get_prefetch_data(full_path);
            std::wstring exe_name = data.empty() ? L"" : get_executable_name_from_data(data);
            std::wstring exe_path = get_executable_path(associated_files, exe_name);
            if (exe_path.empty()) continue;

            time_t last_run = parser.executed_time();
            std::string runtime_str = format_last_runtime(last_run);

            if (seen_paths.count(exe_path)) continue;
            seen_paths.insert(exe_path);

            std::wstring resolved = resolve_volume_to_drive(exe_path);

            if (!resolved.empty()) {
                if (!contains_blocked_name(resolved)) {
                    LOG(DETECTION, runtime_str) << xorstr_("FiveM Injector Found On Pc:") << wstring_to_string(resolved);
                }
            }
            else {
                std::wstring path_only = extract_path_from_volume(exe_path);
                std::wstring candidate = xorstr_(L"?:\\") + path_only;

                if (!contains_blocked_name(candidate)) {
                    not_found_paths.push_back({ candidate, runtime_str });
                }
            }

        } while (FindNextFileA(hFind, &find_data));

        FindClose(hFind);

        if (!not_found_paths.empty()) {
            for (const auto& nf : not_found_paths) {
                if (!contains_blocked_name(nf.first)) {
                    LOG(DETECTION, nf.second) << xorstr_("FiveM Injector Found Deleted Off Pc:") << nf.first;
                }
            }
        }
    }
    catch (...) {}
}