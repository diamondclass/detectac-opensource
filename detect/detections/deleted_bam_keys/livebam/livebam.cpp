#include "livebam.h"

std::string RegistryUtils::device_path_to_dos(const std::string& device_path) {
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

bool RegistryUtils::is_drive_path(const std::string& path) {
    try{
    return path.size() > 2 &&
        std::isalpha((unsigned char)path[0]) &&
        path[1] == ':' &&
        (path[2] == '\\' || path[2] == '/');
    }
    catch (...) { return false; }
}

void RegistryUtils::query_registry_values(HKEY root, const std::string& subkey, std::vector<std::string>& results) {
    try{
    HKEY h_key;
    if (RegOpenKeyExA(root, subkey.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &h_key) == ERROR_SUCCESS) {
        DWORD index = 0;
        char value_name[512];
        DWORD value_name_size;
        BYTE data[1024];
        DWORD data_size;
        DWORD type;
        while (true) {
            value_name_size = sizeof(value_name);
            data_size = sizeof(data);
            LONG result = RegEnumValueA(h_key, index, value_name, &value_name_size, NULL, &type, data, &data_size);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result == ERROR_SUCCESS) {
                std::string valname(value_name);

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
            index++;
        }
        RegCloseKey(h_key);
    }
    }
    catch (...) {}
}

std::vector<std::string> RegistryUtils::start_live_bam() {
    try{
    std::vector<std::string> results;
    const char* base_subkey = xorstr_("SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings");
    HKEY h_base;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, base_subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h_base) == ERROR_SUCCESS) {
        DWORD index = 0;
        char subkey_name[512];
        DWORD subkey_name_size;
        while (true) {
            subkey_name_size = sizeof(subkey_name);
            FILETIME ft;
            LONG result = RegEnumKeyExA(h_base, index, subkey_name, &subkey_name_size, NULL, NULL, NULL, &ft);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result == ERROR_SUCCESS) {
                std::string sid(subkey_name);
                if (sid.size() >= 25) {
                    std::string full_path = std::string(base_subkey) + xorstr_("\\") + sid;
                    query_registry_values(HKEY_LOCAL_MACHINE, full_path, results);
                }
            }
            index++;
        }
        RegCloseKey(h_base);
    }
    return results;
    }
    catch (...) { return {}; }
}