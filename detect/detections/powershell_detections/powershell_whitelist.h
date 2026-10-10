#pragma once

#include "../../pch.h"

namespace ps_whitelist {

    inline const std::vector<std::string>& GetWhitelist()
    {
        static const std::vector<std::string> whitelist = {
            xorstr_("vcpkg"),
            xorstr_("redlotus"),
            xorstr_("get.activated.win"),
            xorstr_("massgrave.dev"),
            xorstr_("Chocolatey"),
            xorstr_("spokwn"),
            xorstr_("praiselily"),
            xorstr_("ChrisTitus"),
            xorstr_("PC-Gaming-Redists-AIO"),
        };
        return whitelist;
    }

    inline bool IsWhitelisted(const std::string& command)
    {
        try
        {
            std::string lower = command;
            std::transform(lower.begin(), lower.end(), lower.begin(),
                [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

            for (const auto& entry : GetWhitelist())
            {
                std::string entryLower = entry;
                std::transform(entryLower.begin(), entryLower.end(), entryLower.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

                if (lower.find(entryLower) != std::string::npos)
                    return true;
            }
        }
        catch (...)
        {
            return false;
        }
        return false;
    }

}
