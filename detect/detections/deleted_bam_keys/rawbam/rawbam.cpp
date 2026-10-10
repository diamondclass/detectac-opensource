#include "rawbam.h"

uint16_t HiveParser::read_u16_le(const unsigned char* p) { try{ uint16_t v; memcpy(&v, p, 2); return v;
}
catch (...) { return 0; }
}
uint32_t HiveParser::read_u32_le(const unsigned char* p) { try{uint32_t v; memcpy(&v, p, 4); return v;
}
catch (...) { return 0; }
}

std::string HiveParser::utf16le_to_utf8(const std::u16string& input) {
    try{
    if (input.empty()) return std::string();
    std::wstring w; w.resize(input.size());
    for (size_t i = 0; i < input.size(); ++i) w[i] = (wchar_t)input[i];
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), NULL, 0, NULL, NULL);
    if (len <= 0) return std::string();
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], len, NULL, NULL);
    return out;
    }
    catch (...) { return ""; }
}

bool HiveParser::likely_utf16_le(const unsigned char* p, size_t bytes) {
    try{
    if (bytes < 2 || (bytes % 2) != 0) return false;
    size_t pairs = bytes / 2;
    for (size_t i = 0; i < pairs && i < 64; ++i) {
        uint16_t wc = (uint16_t)p[2 * i] | ((uint16_t)p[2 * i + 1] << 8);
        if (wc == 0) break;
        if ((wc >= 0x20 && wc < 0xD800) || (wc >= 0xE000 && wc <= 0xFFFD)) return true;
    }
    return false;
    }
    catch (...) { return false; }
}

std::string HiveParser::try_utf16_as_bytes(const unsigned char* p, size_t bytes) {
    try{
    if (bytes < 2) return std::string();
    if ((bytes % 2) != 0) bytes -= 1;
    std::u16string u16((char16_t*)p, (char16_t*)(p + bytes));
    size_t real_len = 0;
    for (size_t i = 0; i < u16.size(); i++) { if (u16[i] == 0) break; real_len++; }
    u16.resize(real_len);
    return utf16le_to_utf8(u16);
    }
    catch (...) { return ""; }
}

std::string HiveParser::try_ascii_preview(const unsigned char* p, size_t len) {
    try{
    std::string s;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = p[i];
        if (c >= 0x20 && c <= 0x7E) s.push_back((char)c);
        else s.push_back('.');
    }
    return s;
    }
    catch (...) { return ""; }
}

bool HiveParser::starts_with(const unsigned char* p, size_t remaining, const char* s, size_t n) {
    try{
    if (remaining < n) return false;
    for (size_t i = 0; i < n; i++) if (p[i] != (unsigned char)s[i]) return false;
    return true;
    }
    catch (...) { return false; }
}

std::string HiveParser::extract_nk_name(const unsigned char* p, size_t payload_size) {
    try{
    if (payload_size < 0x4C) return std::string();
    uint16_t flags = read_u16_le(p + 0x02);
    uint16_t name_len = read_u16_le(p + 0x48);
    const unsigned char* name_ptr = p + 0x4C;
    if (0x4C + (size_t)name_len > payload_size) return std::string();
    if (flags & 0x20) return std::string((const char*)name_ptr, name_len);
    if ((name_len % 2) != 0) return std::string();
    std::u16string u16((char16_t*)name_ptr, (char16_t*)(name_ptr + name_len));
    return utf16le_to_utf8(u16);
    }
    catch (...) { return ""; }
}

std::string HiveParser::extract_vk_name(const unsigned char* cell_ptr, size_t payload_size) {
    try{
    if (payload_size < 0x14 + 1) return std::string();
    uint16_t name_len = 0; memcpy(&name_len, cell_ptr + 0x02, sizeof(name_len));
    const unsigned char* name_ptr = cell_ptr + 0x14;
    size_t remaining = (payload_size > 0x14) ? (payload_size - 0x14) : 0;
    if (name_len && name_len <= remaining) return std::string((const char*)name_ptr, name_len);
    if (remaining >= 2 && likely_utf16_le(name_ptr, remaining)) return try_utf16_as_bytes(name_ptr, remaining);
    return try_ascii_preview(name_ptr, std::min<size_t>(remaining, 64));
    }
    catch (...) { return ""; }
}

std::vector<size_t> HiveParser::resolve_value_list_offsets(uint32_t vl_raw, uint32_t value_count,
    const unsigned char* data, size_t filesize, const std::vector<size_t>& vk_cell_offsets)
{
    try{
    std::vector<size_t> result;
    if (vl_raw == 0xFFFFFFFFu || value_count == 0 || value_count > 1024) return result;
    size_t vl_file_off = (size_t)vl_raw + 0x1000;
    if (vl_file_off + (size_t)value_count * 4 > filesize) return result;
    const unsigned char* vl_ptr = data + vl_file_off;
    for (uint32_t i = 0; i < value_count; i++) {
        uint32_t vk_rel = read_u32_le(vl_ptr + i * 4);
        if (vk_rel == 0xFFFFFFFFu) continue;
        size_t vk_file_off = (size_t)vk_rel + 0x1000;
        for (size_t known : vk_cell_offsets) if (vk_file_off == known) result.push_back(vk_file_off);
    }
    return result;
    }
    catch (...) { return {}; }
}

bool HiveParser::resolve_data_pointer(uint32_t data_raw, uint32_t want_size,
    const std::vector<size_t>& hbin_payload_starts,
    const unsigned char* data_base, size_t filesize,
    const std::vector<size_t>&, const unsigned char*& out_ptr, size_t& out_avail)
{
    try{
    out_ptr = nullptr; out_avail = 0;
    if (data_raw == 0xFFFFFFFFu) return false;
    std::vector<size_t> candidates;
    for (size_t hb : hbin_payload_starts) candidates.push_back(hb + (size_t)data_raw);
    candidates.push_back((size_t)data_raw + 0x1000);
    for (size_t cand : candidates) {
        if (cand + 4 > filesize) continue;
        int32_t cell_size = 0; memcpy(&cell_size, data_base + cand, 4);
        int32_t abs_size = cell_size < 0 ? -cell_size : cell_size;
        if (abs_size <= 4) continue;
        size_t payload = (size_t)abs_size - 4;
        if (want_size <= payload && cand + 4 + want_size <= filesize) {
            out_ptr = data_base + cand + 4;
            out_avail = want_size;
            return true;
        }
    }
    return false;
    }
    catch (...) {}
    return false;
}

std::string HiveParser::device_path_to_dos(const std::string& device_path) {
    try{
    wchar_t volume_name[MAX_PATH];
    wchar_t drive_letter[3];
    for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
        swprintf(drive_letter, 3, xorstr_(L"%c:"), drive);
        if (QueryDosDeviceW(drive_letter, volume_name, MAX_PATH)) {
            size_t volume_length = wcslen(volume_name);
            std::wstring w_device(device_path.begin(), device_path.end());
            if (_wcsnicmp(w_device.c_str(), volume_name, volume_length) == 0) {
                std::wstring result = drive_letter + w_device.substr(volume_length);
                int len = WideCharToMultiByte(CP_UTF8, 0, result.c_str(), -1, NULL, 0, NULL, NULL);
                std::string out(len - 1, 0);
                WideCharToMultiByte(CP_UTF8, 0, result.c_str(), -1, &out[0], len, NULL, NULL);
                return out;
            }
        }
    }
    return device_path;
    }
    catch (...) { return ""; }
}

bool HiveParser::is_drive_path(const std::string& path) {
    try{
    return path.size() > 2 &&
        std::isalpha((unsigned char)path[0]) &&
        path[1] == ':' &&
        (path[2] == '\\' || path[2] == '/');
    }
    catch (...) { return false; }
}

void HiveParser::print_values_recursive(
    int nk_index,
    const std::vector<nk_entry>& nks,
    const std::vector<vk_entry>& vks,
    const std::vector<size_t>& vk_offsets,
    const std::vector<size_t>& hbin_payload_starts,
    const unsigned char* data,
    size_t filesize,
    const std::vector<size_t>& all_cell_offsets,
    const std::unordered_map<size_t, int>& vk_offset_to_index,
    int depth,
    std::vector<std::string>& results)
{
    try{
    for (size_t vk_off : resolve_value_list_offsets(
        nks[nk_index].value_list_raw, nks[nk_index].value_count,
        data, filesize, vk_offsets))
    {
        int vk_idx = vk_offset_to_index.count(vk_off) ? vk_offset_to_index.at(vk_off) : -1;
        if (vk_idx < 0) continue;
        const vk_entry& vk = vks[vk_idx];
        std::string valname = vk.name;

        if (valname.find(xorstr_("\\Device\\HarddiskVolume")) == 0) {
            std::string translated = device_path_to_dos(valname);
            if (is_drive_path(translated)) {
                results.push_back(translated);
            }
        }
        else {
            if (is_drive_path(valname)) {
                results.push_back(valname);
            }
        }
    }

    for (size_t i = 0; i < nks.size(); ++i) {
        if (nks[i].parent_index == nk_index)
            print_values_recursive((int)i, nks, vks, vk_offsets,
                hbin_payload_starts, data, filesize,
                all_cell_offsets, vk_offset_to_index, depth + 1, results);
    }
    }
    catch (...) {}
}

int HiveParser::hive_list_values_recursive(const char* hive_path, const char* target_path, std::vector<std::string>& results) {
    try{
    HANDLE h = CreateFileA(hive_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 1;
    LARGE_INTEGER size_li; if (!GetFileSizeEx(h, &size_li)) { CloseHandle(h); return 2; }
    HANDLE fm = CreateFileMappingA(h, NULL, PAGE_READONLY, 0, 0, NULL); if (!fm) { CloseHandle(h); return 3; }
    void* base = MapViewOfFile(fm, FILE_MAP_READ, 0, 0, 0); if (!base) { CloseHandle(fm); CloseHandle(h); return 4; }
    const unsigned char* data = (const unsigned char*)base; size_t filesize = (size_t)size_li.QuadPart;

    std::vector<size_t> hbin_payload_starts, nk_offsets, vk_offsets, all_cell_offsets;
    std::vector<nk_entry> nks; std::vector<vk_entry> vks;

    size_t pos = 0x1000;
    while (pos + 8 < filesize) {
        if (starts_with(data + pos, filesize - pos, xorstr_("hbin"), 4)) {
            uint32_t hbin_size = 0; memcpy(&hbin_size, data + pos + 8, 4);
            size_t hbin_payload_start = pos + 32;
            hbin_payload_starts.push_back(hbin_payload_start);
            size_t hbin_payload_end = pos + hbin_size;
            size_t cell_pos = hbin_payload_start;
            while (cell_pos + 4 < hbin_payload_end) {
                int32_t cell_size = 0; memcpy(&cell_size, data + cell_pos, 4);
                int32_t abs_size = cell_size < 0 ? -cell_size : cell_size;
                if (abs_size <= 4) { cell_pos += 4; continue; }
                all_cell_offsets.push_back(cell_pos);
                const unsigned char* cell_ptr = data + cell_pos + 4;
                size_t payload_size = (size_t)abs_size - 4;
                if (starts_with(cell_ptr, payload_size, xorstr_("nk"), 2)) {
                    nk_entry e;
                    e.file_offset = cell_pos;
                    e.payload_size = payload_size;
                    e.name = extract_nk_name(cell_ptr, payload_size);
                    e.parent_raw = read_u32_le(cell_ptr + 0x10);
                    e.value_count = read_u32_le(cell_ptr + 0x24);
                    e.value_list_raw = read_u32_le(cell_ptr + 0x28);
                    e.parent_index = -1;
                    nks.push_back(e);
                    nk_offsets.push_back(e.file_offset);
                }
                else if (starts_with(cell_ptr, payload_size, xorstr_("vk"), 2)) {
                    vk_entry v;
                    v.file_offset = cell_pos;
                    v.payload_size = payload_size;
                    v.name = extract_vk_name(cell_ptr, payload_size);
                    v.data_size = read_u32_le(cell_ptr + 0x04);
                    v.data_offset = read_u32_le(cell_ptr + 0x08);
                    v.data_type = read_u32_le(cell_ptr + 0x0C);
                    vks.push_back(v);
                    vk_offsets.push_back(v.file_offset);
                }
                cell_pos += abs_size;
            }
            pos = hbin_payload_end;
        }
        else pos++;
    }

    std::unordered_map<size_t, int> nk_offset_to_index;
    for (size_t i = 0; i < nk_offsets.size(); ++i) nk_offset_to_index[nk_offsets[i]] = (int)i;
    for (size_t i = 0; i < nks.size(); ++i) {
        size_t off = (size_t)nks[i].parent_raw + 0x1000;
        if (nk_offset_to_index.count(off)) nks[i].parent_index = nk_offset_to_index[off];
    }

    if (!target_path) return 0;
    std::string s(target_path);
    if (s.rfind(xorstr_("Computer\\"), 0) == 0) s = s.substr(9);
    if (s.rfind(xorstr_("HKEY_LOCAL_MACHINE\\"), 0) == 0) s = s.substr(19);
    std::transform(s.begin(), s.end(), s.begin(), ::tolower);

    for (size_t i = 0; i < nks.size(); ++i) {
        std::string nm = nks[i].name;
        std::transform(nm.begin(), nm.end(), nm.begin(), ::tolower);
        if (nm == s.substr(s.find_last_of(xorstr_("\\")) + 1)) {
            std::unordered_map<size_t, int> vk_offset_to_index;
            for (size_t j = 0; j < vk_offsets.size(); ++j) vk_offset_to_index[vk_offsets[j]] = (int)j;
            print_values_recursive((int)i, nks, vks, vk_offsets,
                hbin_payload_starts, data, filesize,
                all_cell_offsets, vk_offset_to_index, 0, results);
        }
    }

    UnmapViewOfFile(base); CloseHandle(fm); CloseHandle(h);
    return 0;
    }
    catch (...) { return 0; }
}

std::vector<std::string> HiveParser::enumerate_target_keys() {
    try{
    std::vector<std::string> result;
    const char* base_subkey = xorstr_("SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings");
    HKEY h_base;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, base_subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h_base) == ERROR_SUCCESS) {
        DWORD index = 0;
        char subkey_name[512];
        DWORD subkey_name_size;
        while (true) {
            subkey_name_size = sizeof(subkey_name);
            FILETIME ft;
            LONG r = RegEnumKeyExA(h_base, index, subkey_name, &subkey_name_size, NULL, NULL, NULL, &ft);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r == ERROR_SUCCESS) {
                std::string sid(subkey_name);
                if (sid.size() >= 25) {
                    result.push_back(std::string(xorstr_("HKEY_LOCAL_MACHINE\\")) + base_subkey + xorstr_("\\") + sid);
                }
            }
            index++;
        }
        RegCloseKey(h_base);
    }
    return result;
    }
    catch (...) { return {}; }
}

std::vector<std::string> HiveParser::start_raw_bam() {
    try{
    std::vector<std::string> results;
    char tempPathBuffer[MAX_PATH];
    DWORD tempPathLength = GetEnvironmentVariableA(xorstr_("TEMP"), tempPathBuffer, MAX_PATH);
    if (tempPathLength == 0 || tempPathLength > MAX_PATH) {
        return results;
    }
    std::string hive_path = std::string(tempPathBuffer) + xorstr_("\\SYSTEM");
    std::vector<std::string> targets = HiveParser::enumerate_target_keys();
    if (targets.empty()) {
        return results;
    }
    for (const auto& key : targets) {
        HiveParser::hive_list_values_recursive(hive_path.c_str(), key.c_str(), results);
    }
    return results;
    }
    catch (...) { return {}; }
}