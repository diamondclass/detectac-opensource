#pragma once

#include "../../pch.h"

class bam_state
{
public:
    static bool open_sc_manager();
    static bool open_service(const std::wstring& service_name);
    static bool query_service_status();
    static void print_service_state();
    static SC_HANDLE scm_handle;
    static SC_HANDLE service_handle;
    static SERVICE_STATUS_PROCESS service_status;
    static void interpret_service_state(DWORD state);
    static std::string message;
    static void start_bam_state_detection();
};

inline auto c_bam = std::make_unique<bam_state>();