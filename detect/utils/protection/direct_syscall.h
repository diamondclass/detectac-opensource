#pragma once

#include <Windows.h>
#include <cstdint>

namespace protection {
namespace syscalls {

bool Initialize() noexcept;
bool IsAvailable() noexcept;
unsigned Reverify() noexcept;

NTSTATUS NtClose(HANDLE Handle) noexcept;

NTSTATUS NtOpenFile(
    PHANDLE        FileHandle,
    ACCESS_MASK    DesiredAccess,
    PVOID          ObjectAttributes,
    PVOID          IoStatusBlock,
    ULONG          ShareAccess,
    ULONG          OpenOptions
) noexcept;

NTSTATUS NtCreateFile(
    PHANDLE        FileHandle,
    ACCESS_MASK    DesiredAccess,
    PVOID          ObjectAttributes,
    PVOID          IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG          FileAttributes,
    ULONG          ShareAccess,
    ULONG          CreateDisposition,
    ULONG          CreateOptions,
    PVOID          EaBuffer,
    ULONG          EaLength
) noexcept;

NTSTATUS NtReadFile(
    HANDLE         FileHandle,
    HANDLE         Event,
    PVOID          ApcRoutine,
    PVOID          ApcContext,
    PVOID          IoStatusBlock,
    PVOID          Buffer,
    ULONG          Length,
    PLARGE_INTEGER ByteOffset,
    PULONG         Key
) noexcept;

NTSTATUS NtQueryInformationProcess(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
) noexcept;

NTSTATUS NtQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
) noexcept;

NTSTATUS NtSetInformationThread(
    HANDLE ThreadHandle,
    ULONG  ThreadInformationClass,
    PVOID  ThreadInformation,
    ULONG  ThreadInformationLength
) noexcept;

} // namespace syscalls
} // namespace protection
