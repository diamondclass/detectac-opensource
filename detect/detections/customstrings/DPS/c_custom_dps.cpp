#include "c_custom_dps.h"

#define MIN_STRING_LENGTH 4

bool cdpsscan::enable_debug_privilege() {
    try {
        HANDLE h_token;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) return false;

        LUID luid;
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(h_token); return false; }

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), NULL, NULL)) { CloseHandle(h_token); return false; }
        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { CloseHandle(h_token); return false; }

        CloseHandle(h_token);
        return true;
    }
    catch (...) {}
    return false;
}

DWORD cdpsscan::get_process_id_by_name(const std::string& service_name) {
    try {
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCManager) return 0;

        SC_HANDLE hService = OpenService(hSCManager, service_name.c_str(), SERVICE_QUERY_STATUS);
        if (!hService) { CloseServiceHandle(hSCManager); return 0; }

        SERVICE_STATUS_PROCESS ssp;
        DWORD bytes_needed = 0;
        if (!QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes_needed)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return 0;
        }

        DWORD pid = ssp.dwProcessId;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return pid;
    }
    catch (...) {}
    return 0;
}

static inline std::pair<std::string, std::string> split_custom_string(const std::string& s) { try{
    size_t pos = s.find(xorstr_(":::"));
    if (pos != std::string::npos) return { s.substr(0, pos), s.substr(pos + 3) };
    return { xorstr_(""), s }; } catch (...) { return { "", "" }; }
}

static inline std::string sanitize_ascii_printable(const std::string& s) { try{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) if (c >= 32 && c <= 126) out.push_back((char)c);
    return out; } catch (...) { return ""; }
}

static std::vector<std::pair<std::string, std::string>> hardcoded_filters = {

    //put filters here

};

std::vector<std::pair<std::string, std::string>> cdpsscan::get_custom_filters_only() {
    try {
        static std::vector<std::pair<std::string, std::string>> filters;
        static bool initialized = false;
        if (initialized) return filters;
        filters.clear();

        std::string json_data = custom_strings::fetch_json(xorstr_("https://detect.ac/auth/user/strings/getstrings/") + detect.pin);
        if (!json_data.empty()) {
            try {
                nlohmann::json parsed_json = nlohmann::json::parse(json_data);
                if (parsed_json.contains(xorstr_("customStrings")) && parsed_json[xorstr_("customStrings")].is_array()) {
                    for (auto& entry : parsed_json[xorstr_("customStrings")]) {
                        if (entry.contains(xorstr_("processName")) && entry.contains(xorstr_("strings"))) {
                            std::string process_name = entry[xorstr_("processName")].get<std::string>();
                            std::string raw_strings = entry[xorstr_("strings")].get<std::string>();
                            if (process_name == xorstr_("DPS")) {
                                size_t pos = 0;
                                while (pos < raw_strings.size()) {
                                    size_t next = raw_strings.find(xorstr_("\r\n"), pos);
                                    std::string line;
                                    if (next == std::string::npos) { line = raw_strings.substr(pos); pos = raw_strings.size(); }
                                    else { line = raw_strings.substr(pos, next - pos); pos = next + 2; }

                                    line = sanitize_ascii_printable(line);
                                    if (line.empty()) continue;

                                    auto parts = split_custom_string(line);
                                    std::string name = sanitize_ascii_printable(parts.first);
                                    std::string value = sanitize_ascii_printable(parts.second);
                                    if (!value.empty() && !name.empty()) filters.emplace_back(value, name);
                                }
                            }
                        }
                    }
                }
            }
            catch (...) {}
        }

        initialized = true;
        return filters;
    }
    catch (...) {}
    return {};
}

bool cdpsscan::apply_filter(const std::string& memory_string, const std::pair<std::string, std::string>& filter, bool is_custom) {
    try {
        if (filter.first.empty() || memory_string.empty()) return false;

        std::string mem_lower = memory_string;
        for (char& c : mem_lower) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }
        std::string value_lower = filter.first;
        for (char& c : value_lower) {
            const unsigned char uc = static_cast<unsigned char>(c);
            if (uc >= 'A' && uc <= 'Z') c = static_cast<char>(uc + ('a' - 'A'));
        }

        if (mem_lower.find(value_lower) == std::string::npos) return false;

        static std::unordered_set<std::string> detected_strings;
        std::string unique_key = memory_string + filter.second;
        if (detected_strings.insert(unique_key).second) {
            if (is_custom)
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("Custom String ") + filter.second + xorstr_(" Found:") + memory_string;
            else
                LOG(DETECTION, xorstr_("N/A")) << filter.second << xorstr_(" Found In DPS:") << memory_string;
        }
        return true;
    }
    catch (...) { return false; }
}

void cdpsscan::scan_process_memory(HANDLE h_process) {
    try {
        auto custom_filters             = get_custom_filters_only();
        auto hardcoded_filters_snapshot = hardcoded_filters;
        if (custom_filters.empty() && hardcoded_filters_snapshot.empty()) return;

        static custom_strings::fast_matcher matcher;
        static bool                         matcher_ready = false;
        if (!matcher_ready) {
            matcher.prepare(custom_filters, hardcoded_filters_snapshot);
            matcher_ready = true;
        }
        if (matcher.empty()) return;

        auto emit = [](const custom_strings::fast_matcher::entry& e,
                       const std::string& original)
        {
            if (e.is_custom)
                LOG(DETECTION, xorstr_("N/A")) << xorstr_("Custom String ") + e.name + xorstr_(" Found:") + original;
            else
                LOG(DETECTION, xorstr_("N/A")) << e.name << xorstr_(" Found In DPS:") << original;
        };

        MEMORY_BASIC_INFORMATION mbi;
        constexpr SIZE_T BUF_SIZE = 65536;
        unsigned char buffer[BUF_SIZE];
        SIZE_T bytes_read;

        std::string ascii_string;
        std::string utf16_ascii;
        ascii_string.reserve(1024);
        utf16_ascii.reserve(1024);

        for (PBYTE address = 0;
             VirtualQueryEx(h_process, address, &mbi, sizeof(mbi)) == sizeof(mbi);
             address += mbi.RegionSize)
        {
            if (mbi.State != MEM_COMMIT ||
                !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                continue;

            for (PBYTE addr = (PBYTE)mbi.BaseAddress;
                 addr < (PBYTE)mbi.BaseAddress + mbi.RegionSize;
                 addr += BUF_SIZE)
            {
                if (!ReadProcessMemory(h_process, addr, buffer, BUF_SIZE, &bytes_read)) continue;

                ascii_string.clear();
                for (SIZE_T i = 0; i < bytes_read; ++i) {
                    const unsigned char c = buffer[i];
                    if (c >= 0x20 && c <= 0x7E) {
                        ascii_string.push_back(static_cast<char>(c));
                    } else {
                        if (ascii_string.size() >= MIN_STRING_LENGTH) matcher.scan(ascii_string, emit);
                        ascii_string.clear();
                    }
                }
                if (ascii_string.size() >= MIN_STRING_LENGTH) matcher.scan(ascii_string, emit);

                utf16_ascii.clear();
                for (SIZE_T i = 0; i + 1 < bytes_read; i += 2) {
                    const unsigned char lo = buffer[i];
                    const unsigned char hi = buffer[i + 1];
                    if (hi == 0 && lo >= 0x20 && lo <= 0x7E) {
                        utf16_ascii.push_back(static_cast<char>(lo));
                    } else {
                        if (utf16_ascii.size() >= MIN_STRING_LENGTH) matcher.scan(utf16_ascii, emit);
                        utf16_ascii.clear();
                    }
                }
                if (utf16_ascii.size() >= MIN_STRING_LENGTH) matcher.scan(utf16_ascii, emit);
            }
        }
    }
    catch (...) {}
}

void cdpsscan::start_dps_scan() {
    try {
        if (!cdpsscan::enable_debug_privilege()) return;

        DWORD process_id = cdpsscan::get_process_id_by_name(xorstr_("DPS"));
        if (process_id == 0) return;

        HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
        if (!h_process) return;

        cdpsscan::scan_process_memory(h_process);

        CloseHandle(h_process);
    }
    catch (...) {}
}
