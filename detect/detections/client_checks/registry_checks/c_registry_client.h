#pragma once

#include "../../../pch.h"

class PERegistryScanner {
public:
    static void start_Regsitry_scan();

private:
    static void ScanRoot(HKEY root, const std::wstring& rootName, YR_RULES* rules);
    static int  RegistryYaraCallback(YR_SCAN_CONTEXT*, int message, void* message_data, void* user_data);
    static void CheckAptitudeProductsKey();
    static std::string FormatFileTimeLocal(const FILETIME& ft);
};

inline auto c_regscan = std::make_unique<PERegistryScanner>();
