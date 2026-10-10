#include "c_test_signing.h"

#include <windows.h>
#include <iostream>

bool c_test_signing::is_test_signing_enabled ( )
{
    try{
    typedef LONG NTSTATUS;

    NTSTATUS ( NTAPI * NtQuerySystemInformationFunc )(
        ULONG SystemInformationClass ,
        PVOID SystemInformation ,
        ULONG SystemInformationLength ,
        PULONG ReturnLength
        ) = ( NTSTATUS ( NTAPI* )( ULONG , PVOID , ULONG , PULONG ) )
        GetProcAddress ( GetModuleHandleW ( xorstr_ ( L"ntdll.dll") ) , xorstr_ ( "NtQuerySystemInformation") );

    if ( NtQuerySystemInformationFunc )
    {
        ULONG testSigning = 0;
        NTSTATUS status = NtQuerySystemInformationFunc (
            SystemExtendedHandleInformation ,
            &testSigning ,
            sizeof ( testSigning ) ,
            NULL
        );

        if ( status == STATUS_INFO_LENGTH_MISMATCH && ( testSigning & 0x02 ) )
        {
            return true;
        }
    }

    return false;
    }
    catch (...) { return false; }
}

void c_test_signing::start_test_signing_checks ( )
{
    try{
    if ( is_test_signing_enabled ( ) )
    {
        LOG ( DETECTION, xorstr_ ( "N/A") ) << xorstr_ ( "Test Signing Is Enabled");

        Logger::instance ( ).flush_logs ( );
    }
    }
    catch (...) {}
}
