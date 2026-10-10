#pragma once

#include <Windows.h>

#ifndef _PROTECTION_NT_TYPES_H_
#define _PROTECTION_NT_TYPES_H_

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif

#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif

namespace protection {
namespace nt {

typedef struct _IO_STATUS_BLOCK_X {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK_X, *PIO_STATUS_BLOCK_X;

typedef VOID (NTAPI *PIO_APC_ROUTINE_X)(
    PVOID              ApcContext,
    PIO_STATUS_BLOCK_X IoStatusBlock,
    ULONG              Reserved
);

typedef struct _OBJECT_ATTRIBUTES_X {
    ULONG  Length;
    HANDLE RootDirectory;
    PVOID  ObjectName;
    ULONG  Attributes;
    PVOID  SecurityDescriptor;
    PVOID  SecurityQualityOfService;
} OBJECT_ATTRIBUTES_X, *POBJECT_ATTRIBUTES_X;

typedef struct _UNICODE_STRING_X {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING_X, *PUNICODE_STRING_X;

typedef struct _CLIENT_ID_X {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID_X, *PCLIENT_ID_X;

typedef struct _LIST_ENTRY_X {
    struct _LIST_ENTRY_X *Flink;
    struct _LIST_ENTRY_X *Blink;
} LIST_ENTRY_X, *PLIST_ENTRY_X;

typedef struct _PROCESS_BASIC_INFORMATION_X {
    NTSTATUS  ExitStatus;
    PVOID     PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG      BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION_X, *PPROCESS_BASIC_INFORMATION_X;

typedef struct _PEB_LDR_DATA_X {
    ULONG        Length;
    BOOLEAN      Initialized;
    HANDLE       SsHandle;
    LIST_ENTRY_X InLoadOrderModuleList;
    LIST_ENTRY_X InMemoryOrderModuleList;
    LIST_ENTRY_X InInitializationOrderModuleList;
} PEB_LDR_DATA_X, *PPEB_LDR_DATA_X;

typedef struct _LDR_DATA_TABLE_ENTRY_X {
    LIST_ENTRY_X     InLoadOrderLinks;
    LIST_ENTRY_X     InMemoryOrderLinks;
    LIST_ENTRY_X     InInitializationOrderLinks;
    PVOID            DllBase;
    PVOID            EntryPoint;
    ULONG            SizeOfImage;
    UNICODE_STRING_X FullDllName;
    UNICODE_STRING_X BaseDllName;
    ULONG            Flags;
    USHORT           LoadCount;
    USHORT           TlsIndex;
    LIST_ENTRY_X     HashLinks;
    PVOID            SectionPointer;
    ULONG            CheckSum;
    ULONG            TimeDateStamp;
} LDR_DATA_TABLE_ENTRY_X, *PLDR_DATA_TABLE_ENTRY_X;

typedef struct _CURDIR_X {
    UNICODE_STRING_X DosPath;
    HANDLE           Handle;
} CURDIR_X, *PCURDIR_X;

typedef struct _RTL_USER_PROCESS_PARAMETERS_X {
    ULONG            MaximumLength;
    ULONG            Length;
    ULONG            Flags;
    ULONG            DebugFlags;
    PVOID            ConsoleHandle;
    ULONG            ConsoleFlags;
    HANDLE           StandardInput;
    HANDLE           StandardOutput;
    HANDLE           StandardError;
    CURDIR_X         CurrentDirectory;
    UNICODE_STRING_X DllPath;
    UNICODE_STRING_X ImagePathName;
    UNICODE_STRING_X CommandLine;
} RTL_USER_PROCESS_PARAMETERS_X, *PRTL_USER_PROCESS_PARAMETERS_X;

typedef struct _PEB_X {
    BOOLEAN                        InheritedAddressSpace;
    BOOLEAN                        ReadImageFileExecOptions;
    BOOLEAN                        BeingDebugged;
    BOOLEAN                        BitField;
    HANDLE                         Mutant;
    PVOID                          ImageBaseAddress;
    PPEB_LDR_DATA_X                Ldr;
    PRTL_USER_PROCESS_PARAMETERS_X ProcessParameters;
    PVOID                          SubSystemData;
    PVOID                          ProcessHeap;
    PVOID                          FastPebLock;
    PVOID                          AtlThunkSListPtr;
    PVOID                          IFEOKey;
    ULONG                          CrossProcessFlags;
    PVOID                          KernelCallbackTable;
    ULONG                          SystemReserved;
    ULONG                          AtlThunkSListPtr32;
    PVOID                          ApiSetMap;
    ULONG                          TlsExpansionCounter;
    PVOID                          TlsBitmap;
    ULONG                          TlsBitmapBits[2];
    PVOID                          ReadOnlySharedMemoryBase;
    PVOID                          SharedData;
    PVOID                          *ReadOnlyStaticServerData;
    PVOID                          AnsiCodePageData;
    PVOID                          OemCodePageData;
    PVOID                          UnicodeCaseTableData;
    ULONG                          NumberOfProcessors;
    ULONG                          NtGlobalFlag;
} PEB_X, *PPEB_X;

constexpr ULONG kProcessBasicInformation_X     = 0;
constexpr ULONG kProcessDebugPort_X            = 7;
constexpr ULONG kProcessDebugObjectHandle_X    = 30;
constexpr ULONG kProcessDebugFlags_X           = 31;
constexpr ULONG kThreadHideFromDebugger_X      = 17;

inline PPEB_X CurrentPeb() noexcept {
#if defined(_WIN64)
    return reinterpret_cast<PPEB_X>(__readgsqword(0x60));
#else
    return reinterpret_cast<PPEB_X>(__readfsdword(0x30));
#endif
}

} // namespace nt
} // namespace protection

#endif // _PROTECTION_NT_TYPES_H_
