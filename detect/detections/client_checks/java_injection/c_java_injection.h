#pragma once

#include "../../../pch.h"
#include "../jvm_arg_scanner/c_jvm_arg_scanner.h"

class JavaInjectionScanner
{
public:
    static void start_java_injection_scan();

private:
    struct module_findings
    {
        bool instrument_loaded = false;
        bool attach_loaded     = false;
        bool jdwp_loaded       = false;
    };

    struct memory_findings
    {
        bool weave_marker = false;
    };

    static bool enable_debug_privilege();

    static void scan_weave_artifacts();
    static void scan_loader_processes();
    static void scan_attach_pipes();

    static module_findings scan_process_modules(HANDLE h_process, const jvm_process_info& proc);
    static bool            scan_process_threads(const jvm_process_info& proc);
    static memory_findings scan_process_markers(HANDLE h_process);

    static void inspect_jvm_process(const jvm_process_info& proc);
};

inline auto c_javainj = std::make_unique<JavaInjectionScanner>();
