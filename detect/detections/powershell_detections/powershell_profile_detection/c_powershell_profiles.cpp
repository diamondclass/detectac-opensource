#include "c_powershell_profiles.h"

bool PowerShellProfileChecker::checkProfileExists(const std::string& profilePath) {
    try{
    return std::filesystem::exists(profilePath);
    }
    catch (...) {}
    return false;
}

bool PowerShellProfileChecker::containsKeywords(const std::string& content) {
    try{
    static const std::vector<std::string> keywords = { xorstr_("invoke-ex"), xorstr_("invoke-rest"), xorstr_("invoke-webrequest"), xorstr_("Install-Module -Name PSReadLine -AllowClobber -Force"), xorstr_("Invoke-CommandInDesktopPackage"), xorstr_("iex "), xorstr_("irm "), xorstr_("$env:TEMP"), xorstr_("sEvErance LOaDer"), xorstr_("password"), xorstr_("asplaintext"), xorstr_("token"), xorstr_("apikey"), xorstr_("secret") };
    std::string lowerContent = content;

    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    for (const auto& keyword : keywords) {
        if (lowerContent.find(keyword) != std::string::npos) {
            return true;
        }
    }
    return false;
    }
    catch (...) {}
    return false;
}

bool PowerShellProfileChecker::readProfileContents(const std::string& profilePath, std::string& contents) {
    try{
    std::ifstream file(profilePath);
    if (!file.is_open()) {
        return false;
    }

    std::ostringstream buffer;
    buffer << file.rdbuf();
    contents = buffer.str();

    return true;
    }
    catch (...) {}
    return false;
}

void PowerShellProfileChecker::checkProfiles() {
    try{
    const char* userProfileEnv = std::getenv(xorstr_("USERPROFILE"));
    const char* psHomeEnv = std::getenv(xorstr_("PSHOME"));

    if (!userProfileEnv) {
        return;
    }

    std::string userProfile = userProfileEnv;
    std::string psHome = psHomeEnv ? psHomeEnv : "";

    std::string profiles[] = {
        userProfile + xorstr_("\\Documents\\PowerShell\\Microsoft.PowerShell_profile.ps1"),
        userProfile + xorstr_("\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1"),
        psHome + xorstr_("\\Microsoft.PowerShell_profile.ps1")
    };

    for (const auto& profile : profiles) {
        if (checkProfileExists(profile)) {
            std::string contents;
            if (readProfileContents(profile, contents) && containsKeywords(contents)) {
                LOG(WARNING, xorstr_("N/A")) << xorstr_("Potentually Malicious Powershell Profile found (PowerShell Startup Script):") << profile;
            }
        }
    }
    }
    catch (...) {}
}