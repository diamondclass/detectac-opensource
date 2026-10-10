#pragma once

#include "../../../pch.h"

struct jvm_process_info
{
    DWORD       pid = 0;
    std::string name;
    std::string image_path;
    std::string command_line;
};

class JvmArgScanner
{
public:
    static void start_jvm_arg_scan();

    static std::vector<jvm_process_info> collect_jvm_processes();

    static bool        has_launch_time_agent(const std::string& command_line);
    static bool        environment_agent_present();
    static std::string wideToNarrow(const std::wstring& ws);
    static std::string lower_copy(const std::string& s);

private:
    static std::vector<std::string> parseCommandLine(const std::string& cmdLine);
    static std::vector<std::string> extract_flag_values(const std::string& cmdLine, const std::string& flag);
    static std::vector<std::string> split_classpath(const std::string& value);

    static bool is_trusted_agent_path(const std::string& path_lower);
    static bool is_launcher_temp_agent(const std::string& path_lower);
    static bool is_staging_path(const std::string& path_lower);
    static bool looks_like_jvm(const jvm_process_info& proc);

    static void inspect_agent_args(const jvm_process_info& proc);
    static void inspect_debug_args(const jvm_process_info& proc);
    static void inspect_attach_policy_args(const jvm_process_info& proc);
    static void inspect_classpath_args(const jvm_process_info& proc);
    static void inspect_environment_overrides();
};

inline auto c_jvmarg = std::make_unique<JvmArgScanner>();
