#include "c_ai_detections.h"

const std::string BASE_PATH = ai_scanner::get_local_app_data_path();
const std::vector<std::string> DETECTED_HASHES = {
    xorstr_("cf4b8faf62db174df3babc4a1da7f10ff2b653faab44ff049fc563c61d5ae581"),
    xorstr_("2daacb79ed2d92f58b15825d6aadb9b83fb711643a7c233204b0addc09d453f4")
};
const std::vector<std::string> DETECTED_FILES = { xorstr_("pedaccuracy.meta") };

std::string ai_scanner::get_local_app_data_path()
{
    try {
        char* local_app_data = nullptr;
        size_t len = 0;
        if (_dupenv_s(&local_app_data, &len, xorstr_("LOCALAPPDATA")) != 0 || local_app_data == nullptr)
        {
            return xorstr_("");
        }
        std::string path(local_app_data);
        free(local_app_data);
        return path + xorstr_("\\FiveM\\FiveM.app\\citizen\\common\\data\\ai");
    } catch (...) { return ""; }
}

std::string ai_scanner::get_file_hash(const std::string& file_path)
{
    try{
    std::ifstream file(file_path, std::ios::binary);
    if (!file) return xorstr_("");

    HCRYPTPROV h_prov;
    HCRYPTHASH h_hash;
    BYTE hash[32];
    DWORD hash_size = sizeof(hash);
    CHAR hex_str[65];

    if (!CryptAcquireContext(&h_prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return xorstr_("");
    if (!CryptCreateHash(h_prov, CALG_SHA_256, 0, 0, &h_hash))
    {
        CryptReleaseContext(h_prov, 0);
        return xorstr_("");
    }

    char buffer[4096];
    while (file.read(buffer, sizeof(buffer)))
    {
        CryptHashData(h_hash, reinterpret_cast<BYTE*>(buffer), static_cast<DWORD>(file.gcount()), 0);
    }
    CryptHashData(h_hash, reinterpret_cast<BYTE*>(buffer), static_cast<DWORD>(file.gcount()), 0);

    if (CryptGetHashParam(h_hash, HP_HASHVAL, hash, &hash_size, 0))
    {
        for (DWORD i = 0; i < hash_size; i++)
            sprintf_s(hex_str + (i * 2), 3, xorstr_("%02x"), hash[i]);
        hex_str[64] = '\0';
    }

    CryptDestroyHash(h_hash);
    CryptReleaseContext(h_prov, 0);

    return std::string(hex_str);
    }
    catch (...) { return ""; }
}

bool ai_scanner::is_hidden_or_system(const std::filesystem::directory_entry& entry)
{
    try{
    DWORD attributes = GetFileAttributesW(entry.path().c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES) return false;
    return (attributes & FILE_ATTRIBUTE_HIDDEN) || (attributes & FILE_ATTRIBUTE_SYSTEM);
    }
    catch (...) { return false; }
}

void ai_scanner::scan_ai()
{
    try
    {
        std::error_code _ai_ec;
        if (!std::filesystem::exists(BASE_PATH, _ai_ec) || _ai_ec)
        {
            return;
        }

        bool found_cheat = false;
        for (auto it = std::filesystem::directory_iterator(BASE_PATH,
                std::filesystem::directory_options::skip_permission_denied, _ai_ec);
             !_ai_ec && it != std::filesystem::directory_iterator();
             it.increment(_ai_ec))
        {
            if (_ai_ec) { _ai_ec.clear(); continue; }
            const auto& entry = *it;
            if (!entry.is_regular_file(_ai_ec) || _ai_ec) { _ai_ec.clear(); continue; }

            std::string file_path = c_utils::path_to_utf8(entry.path());
            std::string file_name = c_utils::path_to_utf8(entry.path().filename());

            if (is_hidden_or_system(entry))
            {
                LOG (DETECTION , xorstr_("N/A")) << xorstr_("Hidden Cheat Detected:") << file_path;
                found_cheat = true;
            }

            if (std::find(DETECTED_FILES.begin(), DETECTED_FILES.end(), file_name) != DETECTED_FILES.end())
            {
                LOG (DETECTION , xorstr_("N/A")) << xorstr_("AI Cheat Detected:") << file_path;
                found_cheat = true;
            }

            std::string file_hash = get_file_hash(file_path);
            if (std::find(DETECTED_HASHES.begin(), DETECTED_HASHES.end(), file_hash) != DETECTED_HASHES.end())
            {
                LOG (DETECTION , xorstr_("N/A")) << xorstr_("AI Cheat Detected:") << file_path;
                found_cheat = true;
            }
        }
    }
    catch (...) {}
}
