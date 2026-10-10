#include "c_prefetch_integrity.h"

std::string PrefetchIntegrity::ComputeSHA1(const std::string& filePath) {
    try{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        return xorstr_("");

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return xorstr_("");
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return xorstr_("");
    }

    char buffer[8192];
    while (file) {
        file.read(buffer, sizeof(buffer));
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (!CryptHashData(hHash, reinterpret_cast<const BYTE*>(buffer),
                static_cast<DWORD>(bytesRead), 0)) {
                CryptDestroyHash(hHash);
                CryptReleaseContext(hProv, 0);
                return xorstr_("");
            }
        }
    }

    DWORD hashLen = 20;
    BYTE hashBytes[20]{};
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
        std::ostringstream oss;
        for (DWORD i = 0; i < hashLen; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hashBytes[i]);
        result = oss.str();
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
    }
    catch (...) { return ""; }
}

bool PrefetchIntegrity::IsReadOnly(const std::string& filePath) {
    try{   DWORD attrs = GetFileAttributesA(filePath.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return false;
    return (attrs & FILE_ATTRIBUTE_READONLY) != 0;
    }
    catch (...) { return false; }
}

bool PrefetchIntegrity::HasMAMSignature(const std::string& filePath) {
    try{
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) return false;

    unsigned char header[3] = { 0 };
    file.read(reinterpret_cast<char*>(header), 3);
    if (file.gcount() < 3) return false;

    return (header[0] == 0x4D && header[1] == 0x41 && header[2] == 0x4D);
    }
    catch (...) { return false; }
}

void PrefetchIntegrity::check_prefetch_registry() {
    try {
        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(
            HKEY_LOCAL_MACHINE,
            xorstr_("SYSTEM\\ControlSet001\\Control\\Session Manager\\Memory Management\\PrefetchParameters"),
            0,
            KEY_READ,
            &hKey
        );

        if (result != ERROR_SUCCESS)
            return;

        DWORD value = 0;
        DWORD size = sizeof(DWORD);
        DWORD type = 0;
        result = RegQueryValueExA(
            hKey,
            xorstr_("EnablePrefetcher"),
            nullptr,
            &type,
            reinterpret_cast<LPBYTE>(&value),
            &size
        );

        if (result != ERROR_SUCCESS) {
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("Prefetch Bypass:EnablePrefetcher Key Not Present In Registry");
        }
        else if (type == REG_DWORD && value != 3) {
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("Prefetch Bypass:EnablePrefetcher Not Enabled In Registry");
        }

        RegCloseKey(hKey);
    }
    catch (...) {}
}

void PrefetchIntegrity::start_prefetch_integrity() {
    try{
    check_prefetch_registry();

    const std::string prefetchPath = xorstr_("C:\\Windows\\Prefetch");

    std::error_code ec;
    if (!std::filesystem::exists(prefetchPath, ec))
        return;

    std::vector<FileInfo> files;

    for (const auto& entry : std::filesystem::directory_iterator(prefetchPath, ec)) {
        if (ec) continue;
        if (!entry.is_regular_file(ec) || ec) continue;

        FileInfo info{};
        info.path = c_utils::path_to_utf8(entry.path());
        info.name = c_utils::path_to_utf8(entry.path().filename());
        info.readOnly = IsReadOnly(info.path);
        info.hasMAMSig = HasMAMSignature(info.path);
        info.sha1 = ComputeSHA1(info.path);

        files.push_back(std::move(info));
    }

    for (const auto& f : files) {
        if (f.readOnly)
            LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Prefetch Bypass:File Set To Ready Only -> ") << f.path;
    }

    for (const auto& f : files) {
        if (!f.hasMAMSig)
            //LOG(WARNING, xorstr_("N/A")) << xorstr_("Possible Prefetch Bypass:Unnusual File In Prefetch Folder -> ") << f.name
    ;}

    std::map<std::string, std::vector<const FileInfo*>> hashMap;
    for (const auto& f : files) {
        if (!f.sha1.empty())
            hashMap[f.sha1].push_back(&f);
    }

    for (const auto& [hash, group] : hashMap) {
        if (group.size() >= 2) {
            for (const auto* fi : group)
                LOG(WARNING, xorstr_("N/A")) << xorstr_("Possible Prefetch Bypass:Files With Duplicate Hash (Likely \"Type\" or \"Echo\" Modified) -> ") << fi->name;
        }
    }
    }
    catch (...) {}
}