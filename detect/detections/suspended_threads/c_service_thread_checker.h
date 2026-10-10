#pragma once

#include "../../pch.h"


class service_thread_checker {
public:
    using pfn_nt_query_information_thread = NTSTATUS(WINAPI*)(
        HANDLE thread_handle,
        int thread_information_class,
        PVOID thread_information,
        ULONG thread_information_length,
        PULONG return_length);

    static bool initialize();
    static void check_services_for_suspended_threads(const std::vector<std::wstring>& services);
    static void check_processes_for_suspended_threads(const std::vector<std::wstring>& process_names);
    static pfn_nt_query_information_thread nt_query_information_thread;
    static bool enable_debug_privilege();
    static bool load_nt_query_information_thread();
    static bool is_thread_suspended(HANDLE h_thread);
    static void check_process_threads(DWORD process_id, const std::wstring& name);
    static DWORD get_service_process_id(const std::wstring& service_name);
    static DWORD get_process_id_by_name(const std::wstring& process_name);

    static void start_suspeced_threads_detection();
};

inline auto c_sus_threads = std::make_unique<service_thread_checker>();