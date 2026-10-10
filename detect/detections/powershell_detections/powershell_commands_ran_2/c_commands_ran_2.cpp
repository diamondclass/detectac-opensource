#include "c_commands_ran_2.h"
#include "../powershell_whitelist.h"

std::string c_commands_ran_2::toLower(const std::string& input) {
    try{
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    return lower;
    }
    catch (...) {}
    return {};
}

bool c_commands_ran_2::containsKeyword(const std::string& line, const std::vector<std::string>& keywords) {
    try{
    std::string lowerLine = toLower(line);
    for (const auto& keyword : keywords) {
        if (lowerLine.find(toLower(keyword)) != std::string::npos) {
            return true;
        }
    }
    return false;
    }
    catch (...) {}
    return false;
}

void c_commands_ran_2::scanFile(const std::string& filePath, const std::vector<std::string>& keywords) {
    try{
    std::ifstream file(filePath);
    if (!file.is_open()) {
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (containsKeyword(line, keywords) && !ps_whitelist::IsWhitelisted(line)
            && line.find(xorstr_("Chrome/128.0.0.0")) == std::string::npos) {
            LOG (WARNING , xorstr_("N/A")) << xorstr_("Possible Suspicious Powershell Command:") << line;
        }
    }
    file.close();
    }
    catch (...) {}
}

void c_commands_ran_2::start_commands2() {
    try{
    std::vector<std::string> keywords = {
        xorstr_("invoke-ex"),
        xorstr_("invoke-rest"),
        xorstr_("invoke-webrequest"),
        xorstr_("Install-Module -Name PSReadLine -AllowClobber -Force"),
        xorstr_("Invoke-CommandInDesktopPackage"),
        xorstr_("iex "),
        xorstr_("irm "),
        xorstr_("$env:TEMP"),
        xorstr_("sEvErance LOaDer"),
        xorstr_("asplaintext"),
        xorstr_("token"),
        xorstr_("apikey"),
        xorstr_("secret"),
        xorstr_("password")
    };

    char appDataBuffer[MAX_PATH];
    DWORD appDataLength = GetEnvironmentVariableA(xorstr_("APPDATA"), appDataBuffer, MAX_PATH);
    if (appDataLength == 0 || appDataLength > MAX_PATH) {
        return;
    }
    std::string appData(appDataBuffer);

    std::string file1 = appData + xorstr_("\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
    std::string file2 = appData + xorstr_("\\Microsoft\\Windows\\PowerShell\\PSReadLine\\Windows PowerShell ISE Host_history.txt");

    scanFile(file1, keywords);
    scanFile(file2, keywords);

    return;
    }
    catch (...) {}
}