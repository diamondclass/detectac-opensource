#include "c_executed_diffdrive.h"

#define MIN_STRING_LENGTH 4

std::string DpsScanner::c_drive_volume;

std::vector<std::pair<std::string, std::string>> DpsScanner::hardcoded_filters = {
    { xorstr_("harddiskvolume1"), xorstr_("harddiskvolume1") }, { xorstr_("harddiskvolume2"), xorstr_("harddiskvolume2") },
    { xorstr_("harddiskvolume3"), xorstr_("harddiskvolume3") }, { xorstr_("harddiskvolume4"), xorstr_("harddiskvolume4") },
    { xorstr_("harddiskvolume5"), xorstr_("harddiskvolume5") }, { xorstr_("harddiskvolume6"), xorstr_("harddiskvolume6") },
    { xorstr_("harddiskvolume7"), xorstr_("harddiskvolume7") }, { xorstr_("harddiskvolume8"), xorstr_("harddiskvolume8") },
    { xorstr_("harddiskvolume9"), xorstr_("harddiskvolume9") }, { xorstr_("harddiskvolume10"),xorstr_("harddiskvolume10") },
    { xorstr_("harddiskvolume11"),xorstr_("harddiskvolume11") },{ xorstr_("harddiskvolume12"),xorstr_("harddiskvolume12") },
    { xorstr_("harddiskvolume13"),xorstr_("harddiskvolume13") },{ xorstr_("harddiskvolume14"),xorstr_("harddiskvolume14") },
    { xorstr_("harddiskvolume15"),xorstr_("harddiskvolume15") },{ xorstr_("harddiskvolume16"),xorstr_("harddiskvolume16") },
    { xorstr_("harddiskvolume17"),xorstr_("harddiskvolume17") },{ xorstr_("harddiskvolume18"),xorstr_("harddiskvolume18") },
    { xorstr_("harddiskvolume19"),xorstr_("harddiskvolume19") },{ xorstr_("harddiskvolume20"),xorstr_("harddiskvolume20") },
    { xorstr_("harddiskvolume21"),xorstr_("harddiskvolume21") },{ xorstr_("harddiskvolume22"),xorstr_("harddiskvolume22") },
    { xorstr_("harddiskvolume23"),xorstr_("harddiskvolume23") }
};

bool DpsScanner::enable_debug_privilege() {
    try{
    HANDLE h_token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token)) return false;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(h_token); return false; }
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(h_token, FALSE, &tp, sizeof(tp), NULL, NULL)) { CloseHandle(h_token); return false; }
    CloseHandle(h_token);
    return true;
    }
    catch (...) {}
}

DWORD DpsScanner::get_process_id_by_name(const std::string& service_name) {
    try{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    SC_HANDLE svc = OpenServiceA(scm, service_name.c_str(), SERVICE_QUERY_STATUS);
    if (!svc) { CloseServiceHandle(scm); return 0; }
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed = 0;
    DWORD pid = 0;
    if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &bytes_needed)) {
        pid = ssp.dwProcessId;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return pid;
    }
    catch (...) {}
}

void DpsScanner::remove_c_drive_volume_from_filters() {
    try{
    char target[MAX_PATH] = { 0 };
    if (QueryDosDeviceA(xorstr_("C:"), target, MAX_PATH)) {
        std::string device = target;
        std::transform(device.begin(), device.end(), device.begin(), ::tolower);
        c_drive_volume = device;

        for (auto it = hardcoded_filters.begin(); it != hardcoded_filters.end();) {
            std::string filter_lower = it->first;
            std::transform(filter_lower.begin(), filter_lower.end(), filter_lower.begin(), ::tolower);
            if (device.find(filter_lower) != std::string::npos) {
                it = hardcoded_filters.erase(it);
            }
            else {
                ++it;
            }
        }
    }
    }
    catch (...) {}
}

std::string DpsScanner::sanitize_for_output(const std::string& s) {
    try{
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c >= 32 && c <= 126) out.push_back((char)c);
        else out.push_back('?');
    }
    return out;
    }
    catch (...) {}
    return {};
}

std::string DpsScanner::truncate_at_extension(const std::string& s) {
    try{
    static const std::vector<std::string> exts = {
        xorstr_(".exe"), xorstr_(".dll"), xorstr_(".sys"), xorstr_(".txt"), xorstr_(".log"), xorstr_(".dat"),
        xorstr_(".ini"), xorstr_(".bat"), xorstr_(".cmd"), xorstr_(".vbs"), xorstr_(".ps1")
    };

    size_t earliest = std::string::npos;
    for (auto& ext : exts) {
        size_t pos = s.find(ext);
        if (pos != std::string::npos) {
            size_t end = pos + ext.size();
            if (earliest == std::string::npos || end < earliest) {
                earliest = end;
            }
        }
    }

    if (earliest != std::string::npos) {
        return s.substr(0, earliest);
    }
    return s;
    }
    catch (...) {}
    return {};
}

void DpsScanner::output_split_matches(const std::string& mem_str, const std::string& filter_name) {
    try{
    static std::unordered_set<std::string> seen;

    std::string clean = sanitize_for_output(mem_str);
    std::string pattern = xorstr_("\\Device\\HarddiskVolume");

    size_t pos = 0;
    while (true) {
        size_t found = clean.find(pattern, pos);
        if (found == std::string::npos) break;

        size_t next = clean.find(pattern, found + 1);
        std::string piece = clean.substr(found, (next == std::string::npos ? std::string::npos : next - found));

        std::string lower_piece = piece;
        std::transform(lower_piece.begin(), lower_piece.end(), lower_piece.begin(), ::tolower);
        if (!c_drive_volume.empty() && lower_piece.find(c_drive_volume) != std::string::npos) {
            pos = (next == std::string::npos ? clean.size() : next);
            continue;
        }

        piece = truncate_at_extension(piece);

        if (seen.find(piece) == seen.end()) {
            LOG ( INFO , xorstr_("N/A")) << xorstr_("File Executed From Different Drive:") << piece;
            seen.insert(piece);
        }

        pos = (next == std::string::npos ? clean.size() : next);
    }
    }
    catch (...) {}
}

bool DpsScanner::apply_filter(const std::string& mem_str, const std::pair<std::string, std::string>& filter) {
    try{
    std::string lower = mem_str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    std::string val = filter.first;
    std::transform(val.begin(), val.end(), val.begin(), ::tolower);

    if (lower.find(val) != std::string::npos) {
        output_split_matches(mem_str, filter.second);
        return true;
    }
    return false;
    }
    catch (...) {}
    return false;
}

inline bool DpsScanner::is_ascii_utf8_byte(unsigned char c) {
    try{
    return (c >= 0x20 && c <= 0x7E) || c == 0x09 || c == 0x0A || c == 0x0D || c >= 0x80;
    }
    catch (...) {}
}

inline bool DpsScanner::is_utf16le_printable(wchar_t wc) {
    try{
    return (wc >= 0x20 && wc <= 0x7E) || wc == L'\\' || wc == L'/' || wc == L':' || wc == L'.' || wc == L'-' || wc == L'_' || (wc >= 0x80 && wc < 0xD800);
    }
    catch (...) {}
}

void DpsScanner::scan_process_memory(HANDLE h_process) {
    try{
    MEMORY_BASIC_INFORMATION mbi;
    constexpr SIZE_T BUF_SIZE = 65536;
    unsigned char buffer[BUF_SIZE];

    for (PBYTE addr = 0; VirtualQueryEx(h_process, addr, &mbi, sizeof(mbi)) == sizeof(mbi); addr += mbi.RegionSize) {
        if (mbi.State != MEM_COMMIT) continue;
        if (!(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            continue;

        for (PBYTE chunk = (PBYTE)mbi.BaseAddress; chunk < (PBYTE)mbi.BaseAddress + mbi.RegionSize; chunk += BUF_SIZE) {
            SIZE_T bytes_read = 0;
            if (!ReadProcessMemory(h_process, chunk, buffer, BUF_SIZE, &bytes_read)) continue;

            std::string ascii_str;
            ascii_str.reserve(256);
            for (SIZE_T i = 0; i < bytes_read; ++i) {
                unsigned char c = buffer[i];
                if (is_ascii_utf8_byte(c)) ascii_str.push_back((char)c);
                else {
                    if (ascii_str.size() >= MIN_STRING_LENGTH) {
                        for (auto& f : hardcoded_filters) apply_filter(ascii_str, f);
                    }
                    ascii_str.clear();
                }
            }
            if (ascii_str.size() >= MIN_STRING_LENGTH) {
                for (auto& f : hardcoded_filters) apply_filter(ascii_str, f);
            }

            std::wstring wide_str;
            wide_str.reserve(256);
            for (SIZE_T i = 0; i + 1 < bytes_read; i += 2) {
                wchar_t wc = *(wchar_t*)&buffer[i];
                if (is_utf16le_printable(wc)) wide_str.push_back(wc);
                else {
                    if (wide_str.size() >= MIN_STRING_LENGTH) {
                        std::string utf8 = ascii_wstring_to_string(wide_str);
                        for (auto& f : hardcoded_filters) apply_filter(utf8, f);
                    }
                    wide_str.clear();
                }
            }
            if (wide_str.size() >= MIN_STRING_LENGTH) {
                std::string utf8 = ascii_wstring_to_string(wide_str);
                for (auto& f : hardcoded_filters) apply_filter(utf8, f);
            }
        }
    }
    }
    catch (...) {}
}

void DpsScanner::start_diff_drive_detection() {
    try{
    if (!enable_debug_privilege()) return;
    DWORD pid = get_process_id_by_name(xorstr_("DPS"));
    if (!pid) return;

    remove_c_drive_volume_from_filters();

    HANDLE h_process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!h_process) return;
    scan_process_memory(h_process);
    CloseHandle(h_process);
    }
    catch (...) {}
}