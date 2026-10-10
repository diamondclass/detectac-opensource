#include "c_anydesk_files.h"

std::string file_transfer_parser::get_username()
{
    try
    {
        char username[256];
        DWORD username_len = 256;
        if (GetUserNameA(username, &username_len))
        {
            return std::string(username);
        }
    }
    catch (...) {}
    return xorstr_("");
}

bool file_transfer_parser::is_wide_string(const std::string& str)
{
    try
    {
        if (str.length() < 2) return false;

        for (size_t i = 1; i < str.length(); i += 2)
        {
            if (str[i] != ' ')
            {
                return false;
            }
        }
        return true;
    }
    catch (...) {}
    return false;
}

std::string file_transfer_parser::clean_string(const std::string& str)
{
    std::string cleaned;
    for (size_t i = 0; i < str.size(); i++)
    {
        if (isprint((unsigned char)str[i]))
        {
            cleaned += str[i];
        }
    }

    size_t start = cleaned.find_first_not_of(xorstr_(" \t\n\r\f\v"));
    if (start == std::string::npos) return "";

    size_t end = cleaned.find_last_not_of(xorstr_(" \t\n\r\f\v"));
    return cleaned.substr(start, end - start + 1);
}

std::unordered_set<std::string> file_transfer_parser::extract_unique_quoted_strings(const std::string& filepath)
{
    std::unordered_set<std::string> result;
    try
    {
        std::ifstream file(filepath);

        if (!file.is_open())
        {
            return result;
        }

        std::string line;
        while (std::getline(file, line))
        {
            size_t start_pos = 0;
            while (true)
            {
                start_pos = line.find('\'', start_pos);
                if (start_pos == std::string::npos) break;

                size_t end_pos = line.find('\'', start_pos + 1);
                if (end_pos == std::string::npos) break;

                std::string quoted = line.substr(start_pos + 1, end_pos - start_pos - 1);
                if (!quoted.empty() && !is_wide_string(quoted))
                {
                    std::string cleaned = clean_string(quoted);
                    if (!cleaned.empty())
                    {
                        result.insert(cleaned);
                    }
                }

                start_pos = end_pos + 1;
            }
        }

        file.close();
    }
    catch (...) {}
    return result;
}

void file_transfer_parser::start_anydesk_scan()
{
    try
    {
        std::string username = file_transfer_parser::get_username();
        if (username.empty())
        {
            return;
        }

        std::string filepath = xorstr_("C:\\Users\\") + username + xorstr_("\\AppData\\Roaming\\AnyDesk\\file_transfer_trace.txt");

        std::unordered_set<std::string> quoted_strings = file_transfer_parser::extract_unique_quoted_strings(filepath);

        if (quoted_strings.empty())
        {
            return;
        }

        std::vector<std::string> sorted_strings(quoted_strings.begin(), quoted_strings.end());
        std::sort(sorted_strings.begin(), sorted_strings.end());

        for (const auto& str : sorted_strings)
        {
            LOG ( INFO , xorstr_("N/A")) << xorstr_("File Transferred Over Anydesk:") << str;
        }
    }
    catch (...) {}
    return;
}