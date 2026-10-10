#pragma once
#include "common.h"

namespace atlas {
namespace nt {

typedef LONG NTSTATUS;
#define ATLAS_NT_SUCCESS(s) (((LONG)(s)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    HANDLE    HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
    WCHAR          NameBuffer[1];
} OBJECT_NAME_INFORMATION;

#undef SystemExtendedHandleInformation
#undef ProcessBasicInformation
#undef ProcessWow64Information
#undef ThreadBasicInformation
#undef ThreadQuerySetWin32StartAddress
#undef ThreadHideFromDebugger
#undef ObjectNameInformation

enum {
    SystemExtendedHandleInformation = 64,
};
enum {
    ProcessBasicInformation  = 0,
    ProcessWow64Information  = 26,
};
enum {
    ThreadBasicInformation          = 0,
    ThreadQuerySetWin32StartAddress = 9,
    ThreadHideFromDebugger          = 17,
};
enum {
    ObjectNameInformation = 1,
};

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION;

extern NTSTATUS (NTAPI* NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS (NTAPI* NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS (NTAPI* NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS (NTAPI* NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS (NTAPI* NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);

bool Init();

bool EnableDebugPrivilege();

}
}
