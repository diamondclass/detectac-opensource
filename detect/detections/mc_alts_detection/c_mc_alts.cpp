#include "c_mc_alts.h"


std::string process_utilities::get_username() {
    try{
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;

    if (GetUserNameA(username, &username_len)) {
        return std::string(username);
    }
    else {
        return xorstr_("");
    }
    }
    catch (...) {}
    return {};
}

bool process_utilities::contains_pattern(const std::string& data, const std::vector<std::string>& patterns) {
    try{
    return std::any_of(patterns.begin(), patterns.end(), [&data](const std::string& pattern) {
        return data.find(pattern) != std::string::npos;
        });
    }
    catch (...) {}
}

std::vector<std::string> process_utilities::extract_readable_strings(const std::string& data) {
    try{
    std::vector<std::string> readable_strings;
    size_t start = 0;
    size_t len = 0;

    for (size_t i = 0; i < data.size(); ++i) {
        if (std::isprint(static_cast<unsigned char>(data[i])) || data[i] == '\t' || data[i] == '\n') {
            if (len == 0) start = i;
            ++len;
        }
        else {
            if (len >= 19) {
                readable_strings.emplace_back(data.substr(start, len));
            }
            len = 0;
        }
    }
    if (len >= 19) {
        readable_strings.emplace_back(data.substr(start, len));
    }

    return readable_strings;
    }
    catch (...) {}
    return {};
}

bool process_utilities::contains_numbers(const std::string& str) {
    try{
    return std::any_of(str.begin(), str.end(), ::isdigit);
    }
    catch (...) {}
    return false;
}

bool process_utilities::find_process_by_name(const std::string& process_name, DWORD& pid, DWORD& parent_pid) {
    try{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32 process_entry = {};
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process_entry)) {
        do {
            if (process_name == process_entry.szExeFile) {
                pid = process_entry.th32ProcessID;
                parent_pid = process_entry.th32ParentProcessID;
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    CloseHandle(snapshot);
    return false;
    }
    catch (...) {}
}

std::string process_utilities::get_process_name(DWORD pid) {
    try{
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return "";
    }

    PROCESSENTRY32 process_entry = {};
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process_entry)) {
        do {
            if (process_entry.th32ProcessID == pid) {
                CloseHandle(snapshot);
                return process_entry.szExeFile;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    CloseHandle(snapshot);
    return xorstr_("");
    }
    catch (...) {}
    return {};
}

std::string process_utilities::sanitize_string(const std::string& str, const std::regex& regex_pattern, std::unordered_set<std::string>& unique_outputs) {
    try{
    std::smatch match;
    if (std::regex_search(str, match, regex_pattern)) {
        std::string sanitized = match[1];
        if (unique_outputs.insert(sanitized).second) {
            return sanitized;
        }
    }
    return xorstr_("");
    }
    catch (...) {}
    return {};
}

std::vector<std::string> process_utilities::read_and_sanitize_json(const std::string& username, std::unordered_set<std::string>& unique_outputs) {
    try{
    std::string file_path = xorstr_( "C:\\Users\\" ) + username + xorstr_ ( "\\.lunarclient\\settings\\game\\accounts.json" );
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return {};
    }

    std::vector<std::string> names;
    std::string line;
    std::regex name_regex( xorstr_ ( "\"name\"\\s*:\\s*\"([^\"]+)\"" ) );

    while (std::getline(file, line)) {
        std::string sanitized_name = sanitize_string(line, name_regex, unique_outputs);
        if (!sanitized_name.empty()) {
            names.push_back(sanitized_name);
        }
    }

    return names;
    }
    catch (...) {}
    return {};
}

void process_utilities::search_strings_in_process(DWORD pid, const std::vector<std::string>& patterns,
    bool sanitize_for_feather_client, bool sanitize_for_badlion_client, bool sanitize_for_lunar_client,
    std::unordered_set<std::string>& unique_outputs) {
    try{
    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) {
        return;
    }

    SYSTEM_INFO sys_info;
    GetSystemInfo(&sys_info);

    MEMORY_BASIC_INFORMATION mem_info;
    char* address = (char*)sys_info.lpMinimumApplicationAddress;

    std::regex feather_regex( xorstr_ ( "\"mcUsername\":\"([^\"]+)\"" ) );
    std::regex badlion_regex( xorstr_ ( "Adding session: ([^\\s]+)" ) );
    std::regex lunar_regex( xorstr_ ( R"(\[LC Accounts\] Loaded content for \[([^\]]+)\])") );

    while (address < sys_info.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(process, address, &mem_info, sizeof(mem_info)) == sizeof(mem_info) &&
            (mem_info.State == MEM_COMMIT) &&
            (mem_info.RegionSize >= 1LL * 1024 * 1024 * 1024) &&
            ((mem_info.Protect & PAGE_READWRITE) ||
                (mem_info.Protect & PAGE_READONLY) ||
                (mem_info.Protect & PAGE_EXECUTE_READWRITE))) {

            const size_t chunk_size = 64 * 1024 * 1024;
            std::vector<char> buffer(chunk_size);
            SIZE_T bytes_read;

            for (size_t offset = 0; offset < mem_info.RegionSize; offset += chunk_size) {
                size_t current_chunk_size = std::min(chunk_size, static_cast<size_t>(mem_info.RegionSize - offset));

                if (ReadProcessMemory(process, address + offset, buffer.data(), current_chunk_size, &bytes_read) && bytes_read > 0) {
                    std::string region_data(buffer.data(), bytes_read);
                    auto readable_strings = extract_readable_strings(region_data);
                    for (const auto& str : readable_strings) {
                        if (contains_pattern(str, patterns)) {
                            std::string sanitized;
                            if (sanitize_for_feather_client) {
                                sanitized = sanitize_string(str, feather_regex, unique_outputs);
                            }
                            else if (sanitize_for_badlion_client) {
                                sanitized = sanitize_string(str, badlion_regex, unique_outputs);
                            }
                            else if (sanitize_for_lunar_client) {
                                sanitized = sanitize_string(str, lunar_regex, unique_outputs);
                            }

                            if (!sanitized.empty()) {
                                LOG ( INFO , xorstr_( "N/A" ) ) << xorstr_ ( "Minecraft Account:" ) << sanitized << xorstr_(" ");
                            }
                        }
                    }
                }
            }
        }
        address += mem_info.RegionSize;
    }

    CloseHandle(process);
    }
    catch (...) {}
}

bool process_utilities::is_drive_letter_path(const std::wstring& path)
{
    try{
    return path.length() == 3 && path[1] == L':' && path[2] == L'\\' &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
    }
    catch (...) {}
}

std::string process_utilities::wide_to_utf8(const std::wstring& wide)
{
    try{
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(size_needed - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &result[0], size_needed, nullptr, nullptr);
    return result;
    }
    catch (...) {}
    return {};
}

void process_utilities::list_volume_folder_mounts()
{
    try{
    wchar_t volume_name[MAX_PATH];
    HANDLE find_handle = FindFirstVolumeW(volume_name, MAX_PATH);
    if (find_handle == INVALID_HANDLE_VALUE)
        return;

    do {
        size_t len = wcslen(volume_name);
        if (volume_name[len - 1] != L'\\') {
            if (len + 1 < MAX_PATH)
                wcscat_s(volume_name, MAX_PATH, xorstr_(L"\\"));
            else
                continue;
        }

        std::vector<wchar_t> buffer(4096);
        DWORD return_length = 0;

        if (GetVolumePathNamesForVolumeNameW(volume_name, buffer.data(), (DWORD)buffer.size(), &return_length)) {
            size_t i = 0;
            while (i < return_length) {
                std::wstring path = &buffer[i];
                if (!path.empty() && !is_drive_letter_path(path)) {
                    LOG ( DETECTION , xorstr_("N/A")) << xorstr_("USN Journal Bypass Folder Found:") << wide_to_utf8(path);
                }
                i += path.length() + 1;
            }
        }

    } while (FindNextVolumeW(find_handle, volume_name, MAX_PATH));

    FindVolumeClose(find_handle);
    }
    catch (...) {}
}

bool process_utilities::doesFileExist(const std::wstring& filePath) {
    try{
    DWORD fileAttributes = GetFileAttributesW(filePath.c_str());
    return (fileAttributes != INVALID_FILE_ATTRIBUTES &&
        !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
    }
    catch (...) {}
}

void process_utilities::checkfile() {
    try{
    std::wstring filePath = xorstr_(L"C:\\Windows\\SysWOW64\\msadres.dll");

    if (doesFileExist(filePath)) {
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Bruzen Bypass Found:C:\\Windows\\SysWOW64\\msadres.dll");
    }
    }
    catch (...) {}
}

void process_utilities::start_mc_alts11() {
    try{
    std::string target_process = xorstr_ ( "javaw.exe" );
    std::vector<std::string> patterns;
    std::unordered_set<std::string> unique_outputs;

    DWORD pid = 0, parent_pid = 0;

    std::string username = process_utilities::get_username();
    std::vector<std::string> sanitized_names = process_utilities::read_and_sanitize_json(username, unique_outputs);

    for (const auto& name : sanitized_names) {
        LOG ( INFO , xorstr_("N/A") ) << xorstr_ ( "Minecraft Account:" ) << name << xorstr_( " " );
    }

    if (!process_utilities::find_process_by_name(target_process, pid, parent_pid)) {
    }

    std::string parent_process_name = process_utilities::get_process_name(parent_pid);

    bool sanitize_for_feather_client = false;
    bool sanitize_for_badlion_client = false;
    bool sanitize_for_lunar_client = false;

    if (parent_process_name == xorstr_ ( "Feather Launcher.exe" ) ) {
        patterns = { xorstr_ ( "\"mcUsername\"" ) };
        sanitize_for_feather_client = true;
    }
    else if (parent_process_name == xorstr_ ( "Lunar Client.exe" ) ) {
        patterns = { xorstr_ ( "[LC Accounts] Loaded content for " ) };
        sanitize_for_lunar_client = true;
    }
    else if (parent_process_name == xorstr_ ( "Badlion Client.exe" ) ) {
        patterns = { xorstr_ ( "Adding session: " ) };
        sanitize_for_badlion_client = true;
    }
    else {
    }

    process_utilities::search_strings_in_process(pid, patterns, sanitize_for_feather_client, sanitize_for_badlion_client, sanitize_for_lunar_client, unique_outputs);
    
    }
    catch (...) {}
}

void process_utilities::start_mc_alts()
{
    try{
        process_utilities::start_mc_alts11();

        process_utilities::checkfile();

        process_utilities::list_volume_folder_mounts();
    }
    catch (...) {}
}