#include "c_lua_script_detection.h"

std::string LuaScanner::fixPath(const std::string& path) {
    try{
    std::string result;
    for (size_t i = 0; i < path.size(); ++i) {
        if (path[i] == '\\' && i + 1 < path.size() && path[i + 1] == '\\') {
            result += '\\';
            ++i;
        }
        else {
            result += path[i];
        }
    }
    return result;
    }
    catch (...) {}
    return {};
}

bool LuaScanner::hasSuspiciousStrings(const std::string& filePath) {
    try{
    std::ifstream file(filePath);
    if (!file.is_open()) return false;

    std::string line;
    while (std::getline(file, line)) {
        std::string lowerLine = line;
        std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(),
            [](unsigned char c) { return std::tolower(c); });

        if (lowerLine.find(xorstr_("movemouserelative(")) != std::string::npos ||
            lowerLine.find(xorstr_("local sensitivity")) != std::string::npos ||
            lowerLine.find(xorstr_("movemouseto(")) != std::string::npos) {
            return true;
        }
    }
    return false;
    }
    catch (...) {}
    return false;
}

std::string LuaScanner::ScanForMaliciousScripts() {
    try{
    const char* user_env = std::getenv(xorstr_("USERNAME"));
    if (!user_env) return "";
    std::string username = user_env;
    std::filesystem::path scriptsPath = xorstr_("C:\\Users\\") + username + xorstr_("\\AppData\\Local\\LGHUB\\scripts");

    std::error_code _lua_ec;
    if (!std::filesystem::exists(scriptsPath, _lua_ec) || _lua_ec) {
        return "";
    }

    for (auto it = std::filesystem::recursive_directory_iterator(scriptsPath,
            std::filesystem::directory_options::skip_permission_denied, _lua_ec);
         !_lua_ec && it != std::filesystem::recursive_directory_iterator();
         it.increment(_lua_ec))
    {
        if (_lua_ec) { _lua_ec.clear(); continue; }
        const auto& entry = *it;
        if (entry.is_regular_file(_lua_ec) && !_lua_ec && entry.path().extension() == xorstr_(L".lua")) {
            std::string path_utf8 = c_utils::path_to_utf8(entry.path());
            if (hasSuspiciousStrings(path_utf8)) {
                return fixPath(path_utf8);
            }
        }
    }

    return "";
    }
    catch (...) {}
    return {};
}

void LuaScanner::start_luascripts_scan() {
    try{
    std::string result = LuaScanner::ScanForMaliciousScripts();
    if (!result.empty()) {
        LOG ( DETECTION , xorstr_("N/A")) << xorstr_("Malicious Mouse Script Found:") << result;
        return;
    }

    return;
    }
    catch (...) {}
}