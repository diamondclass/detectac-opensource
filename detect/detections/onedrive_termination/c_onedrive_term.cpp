#include "c_onedrive_term.h"

bool onedrive_term::terminate_process_by_name(const std::wstring& process_name) {
    try {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W entry;
        entry.dwSize = sizeof(PROCESSENTRY32W);

        if (Process32FirstW(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, process_name.c_str()) == 0) {
                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                    if (hProcess) {
                        BOOL result = TerminateProcess(hProcess, 1);
                        CloseHandle(hProcess);
                        CloseHandle(snapshot);
                        return result;
                    }
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return false;
    }
    catch (...) {}
}

void onedrive_term::term_onedrive() {
    try {

        terminate_process_by_name(xorstr_(L"OneDrive.exe"));

        return;
    }
    catch (...) {}
}