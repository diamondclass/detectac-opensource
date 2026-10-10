#include "ntdefs.h"

namespace atlas {
namespace nt {

NTSTATUS (NTAPI* NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = nullptr;
NTSTATUS (NTAPI* NtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG) = nullptr;
NTSTATUS (NTAPI* NtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG) = nullptr;
NTSTATUS (NTAPI* NtQueryObject)(HANDLE, ULONG, PVOID, ULONG, PULONG) = nullptr;
NTSTATUS (NTAPI* NtDuplicateObject)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG) = nullptr;

bool Init() {
    HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!nt) return false;
#define BIND(x) *(FARPROC*)&x = GetProcAddress(nt, #x)
    BIND(NtQuerySystemInformation);
    BIND(NtQueryInformationProcess);
    BIND(NtQueryInformationThread);
    BIND(NtQueryObject);
    BIND(NtDuplicateObject);
#undef BIND
    return NtQueryInformationProcess != nullptr;
}

bool EnableDebugPrivilege() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    LUID luid{};
    bool ok = false;
    if (LookupPrivilegeValueW(nullptr, xorstr_(L"SeDebugPrivilege"), &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr) &&
             GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

}
}
