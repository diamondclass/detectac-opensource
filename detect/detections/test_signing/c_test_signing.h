#pragma once

#include "../../pch.h"

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define SystemExtendedHandleInformation 64

extern "C" NTSTATUS NTAPI NtQuerySystemInformation (
    ULONG SystemInformationClass ,
    PVOID SystemInformation ,
    ULONG SystemInformationLength ,
    PULONG ReturnLength
);


class c_test_signing
{
public:
    static bool is_test_signing_enabled ( );
    static void start_test_signing_checks ( );
     
};

inline auto c_test = std::make_unique<c_test_signing> ( );

