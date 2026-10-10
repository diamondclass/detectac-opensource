#include "c_steam_alt_detection.h"

bool steam_alt::Is17DigitNumber(const std::string& str) {
    try{
    return str.size() == 17 && std::all_of(str.begin(), str.end(), ::isdigit);
    }
    catch (...) {}
    return false;
}

std::string steam_alt::RemoveKeywords(const std::string& line, const std::vector<std::string>& keywords) {
    try{
    std::string result = line;
    for (const auto& keyword : keywords) {
        size_t pos = result.find(keyword);
        if (pos != std::string::npos) {
            result.erase(pos, keyword.size());
        }
    }
    return result;
    }
    catch (...) {}
    return {};
}

std::string steam_alt::RemoveQuotes(const std::string& line) {
    try{
    std::string result = line;
    result.erase(std::remove(result.begin(), result.end(), '"'), result.end());
    return result;
    }
    catch (...) {}
    return {};
}

void steam_alt::ProcessLoginUsersFile(const std::string& filePath) {
    try{
    std::ifstream file(filePath);

    if (!file.is_open()) {
        return;
    }

    std::vector<std::string> steam_ids, usernames, account_ids;
    std::string line;
    const std::vector<std::string> keywords_to_remove = { xorstr_ ( "AccountName" ), xorstr_ ( "PersonaName" ) };

    while (std::getline(file, line)) {
        line.erase(std::remove(line.begin(), line.end(), '\t'), line.end());
        line.erase(std::remove(line.begin(), line.end(), ' '), line.end());

        if (line.find(xorstr_("\"")) == 0 && line.back() == '"' && line.find(xorstr_("{")) == std::string::npos) {
            std::string possible_id = line.substr(1, line.size() - 2);
            if (Is17DigitNumber(possible_id)) {
                steam_ids.push_back(possible_id);
                continue;
            }
        }

        if (line.find( xorstr_ ( "AccountName" )) != std::string::npos) {
            std::string processed_line = RemoveKeywords(line, keywords_to_remove);
            processed_line = RemoveQuotes(processed_line);
            account_ids.push_back(processed_line);
            continue;
        }

        if (line.find( xorstr_ ( "PersonaName" ) ) != std::string::npos) {
            std::string processed_line = RemoveKeywords(line, keywords_to_remove);
            processed_line = RemoveQuotes(processed_line);
            usernames.push_back(processed_line);
        }
    }

    file.close();

    size_t max_size = std::max({ steam_ids.size(), usernames.size(), account_ids.size() });

    if (max_size > 0) {
        for (size_t i = 0; i < max_size; ++i) {
            std::string steam_id = (i < steam_ids.size()) ? steam_ids[i] : xorstr_ ( "N/A" ) ;
            std::string account_id = (i < account_ids.size()) ? account_ids[i] : xorstr_ ( "N/A" ) ;
            std::string username = (i < usernames.size()) ? usernames[i] : xorstr_( "N/A" ) ;

            LOG ( INFO , xorstr_ ( "N/A" ) ) << xorstr_("Steam Account: Steam ID: ") << steam_id << xorstr_(" ")
                << xorstr_ ( "Account ID: " ) << account_id << xorstr_(" ")
                << xorstr_ ( "Username: " ) << username << xorstr_(" ");
        }
    }
    }
    catch (...) {}
}

void steam_alt::start_steam_alt_detection() {
    try{
    const std::string filePath = xorstr_ ( R"(C:\Program Files (x86)\Steam\config\loginusers.vdf)" );
    steam_alt::ProcessLoginUsersFile(filePath);
    }
    catch (...) {}
}