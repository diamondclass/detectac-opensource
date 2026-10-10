#pragma once

#include "../../pch.h"

class DiscordAsarScanner
{
public:
    static bool ScanForInjectedRequire(std::string& outInjectedModule);
    static std::string GetUsername();
    static bool ReadFileAll(const std::string& path, std::vector<char>& data);
    static bool ExtractMainScreenJS(const std::vector<char>& asar, std::string& outJs);
    static bool DetectInjectedRequire(const std::string& js, std::string& outModuleName);

    static void asar_checks();
};

inline auto c_asar = std::make_unique<DiscordAsarScanner>();