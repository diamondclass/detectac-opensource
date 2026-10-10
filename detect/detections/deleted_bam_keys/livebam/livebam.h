#pragma once

#include "../c_deleted_bam.h"

class RegistryUtils {
public:
    static std::string device_path_to_dos(const std::string& device_path);
    static bool is_drive_path(const std::string& path);
    static void query_registry_values(HKEY root, const std::string& subkey, std::vector<std::string>& results);
    static std::vector<std::string> start_live_bam();
};