#include "c_nvidia_driver_patch.h"
#include <dxgi.h>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "dxgi.lib")

static const BYTE PATCH_1[] = { 0x45,0x31,0xC0,0x90,0x90,0x90,0x90,0x45,0x85,0xC0 };
static const BYTE PATCH_2[] = { 0x31,0xC9,0x90,0x90,0x90,0x90,0x85,0xC9 };

bool NvidiaDriverPatch::IsNvidiaGpu() {
    try {
        IDXGIFactory* factory = nullptr;
        if (FAILED(CreateDXGIFactory(__uuidof(IDXGIFactory), (void**)&factory)) || !factory)
            return false;

        bool found = false;
        IDXGIAdapter* adapter = nullptr;
        for (UINT i = 0; ; i++) {
            HRESULT hr = factory->EnumAdapters(i, &adapter);
            if (FAILED(hr) || !adapter)
                break;

            try {
                DXGI_ADAPTER_DESC desc{};
                if (SUCCEEDED(adapter->GetDesc(&desc)) && desc.VendorId == 0x10DE)
                    found = true;
            }
            catch (...) {}

            adapter->Release();
            adapter = nullptr;
            if (found) break;
        }

        factory->Release();
        return found;
    }
    catch (...) { return false; }
}

bool NvidiaDriverPatch::ScanModuleForPatches(HANDLE hProcess, HMODULE hModule) {
    try {
        MODULEINFO mi{};
        if (!GetModuleInformation(hProcess, hModule, &mi, sizeof(mi)))
            return false;

        if (mi.SizeOfImage == 0 || mi.SizeOfImage > 200 * 1024 * 1024)
            return false;

        std::vector<BYTE> buf;
        try { buf.resize(mi.SizeOfImage); }
        catch (...) { return false; }

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, mi.lpBaseOfDll, buf.data(), mi.SizeOfImage, &bytesRead) || bytesRead == 0)
            return false;

        for (size_t i = 0; i + sizeof(PATCH_1) <= bytesRead; i++) {
            if (memcmp(buf.data() + i, PATCH_1, sizeof(PATCH_1)) == 0)
                return true;
        }

        for (size_t i = 0; i + sizeof(PATCH_2) <= bytesRead; i++) {
            if (memcmp(buf.data() + i, PATCH_2, sizeof(PATCH_2)) == 0)
                return true;
        }

        return false;
    }
    catch (...) { return false; }
}

bool NvidiaDriverPatch::CheckNvidiaProcesses() {
    try {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return false;

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (!Process32FirstW(snap, &pe)) {
            CloseHandle(snap);
            return false;
        }

        do {
            try {
                if (_wcsicmp(pe.szExeFile, xorstr_(L"nvcontainer.exe")) != 0 &&
                    _wcsicmp(pe.szExeFile, xorstr_(L"NVIDIA Share.exe")) != 0)
                    continue;

                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (!hProc) continue;

                HMODULE mods[1024];
                DWORD cbNeeded = 0;
                if (EnumProcessModules(hProc, mods, sizeof(mods), &cbNeeded)) {
                    DWORD count = cbNeeded / sizeof(HMODULE);
                    if (count > _countof(mods))
                        count = _countof(mods);

                    for (DWORD i = 0; i < count; i++) {
                        try {
                            wchar_t modName[MAX_PATH]{};
                            if (GetModuleBaseNameW(hProc, mods[i], modName, MAX_PATH)) {
                                if (_wcsicmp(modName, xorstr_(L"nvd3dumx.dll")) == 0 &&
                                    ScanModuleForPatches(hProc, mods[i])) {
                                    CloseHandle(hProc);
                                    CloseHandle(snap);
                                    return true;
                                }
                            }
                        }
                        catch (...) { continue; }
                    }
                }

                CloseHandle(hProc);
            }
            catch (...) { continue; }
        } while (Process32NextW(snap, &pe));

        CloseHandle(snap);
        return false;
    }
    catch (...) { return false; }
}

bool NvidiaDriverPatch::CheckStreamproofRegistry() {
    try {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\NVIDIA Corporation\\Global\\NvApp\\ShadowPlay\\FTS"),
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        DWORD val = 0, sz = sizeof(DWORD), type = 0;
        LONG result = RegQueryValueExW(hKey,
            xorstr_(L"{497B8458-4244-4EE6-BFEA-F3D2BA294F21}"),
            nullptr, &type, reinterpret_cast<LPBYTE>(&val), &sz);
        RegCloseKey(hKey);

        if (result != ERROR_SUCCESS)
            return false;

        if (type != REG_DWORD || val == 0x14)
            return true;

        return false;
    }
    catch (...) { return false; }
}

bool NvidiaDriverPatch::CheckFTSLastWriteTime() {
    try {
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\NVIDIA Corporation\\Global\\NvApp\\ShadowPlay\\FTS"),
            0, KEY_READ, &hKey) != ERROR_SUCCESS)
            return false;

        FILETIME ftWrite{};
        if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, &ftWrite) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }
        RegCloseKey(hKey);

        SYSTEMTIME stNowUtc;
        GetSystemTime(&stNowUtc);
        FILETIME ftNow;
        SystemTimeToFileTime(&stNowUtc, &ftNow);

        ULARGE_INTEGER now, writeTime;
        now.LowPart = ftNow.dwLowDateTime;
        now.HighPart = ftNow.dwHighDateTime;
        writeTime.LowPart = ftWrite.dwLowDateTime;
        writeTime.HighPart = ftWrite.dwHighDateTime;

        const ULONGLONG twentyFourHours = 24ULL * 60 * 60 * 10000000ULL;
        const ULONGLONG sixHours = 6ULL * 60 * 60 * 10000000ULL;

        if (now.QuadPart - writeTime.QuadPart > twentyFourHours)
            return false;

        DWORD installDate = system_install_info::get_install_date();
        if (installDate != 0) {
            ULONGLONG installFiletime =
                (static_cast<ULONGLONG>(installDate) + 11644473600ULL) * 10000000ULL;

            ULONGLONG diff = (writeTime.QuadPart > installFiletime)
                ? (writeTime.QuadPart - installFiletime)
                : (installFiletime - writeTime.QuadPart);

            if (diff <= sixHours)
                return false;
        }

        FILETIME ftLocal;
        FileTimeToLocalFileTime(&ftWrite, &ftLocal);
        SYSTEMTIME stWrite;
        FileTimeToSystemTime(&ftLocal, &stWrite);

        char timestamp[32];
        snprintf(timestamp, sizeof(timestamp), xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            static_cast<int>(stWrite.wYear), static_cast<int>(stWrite.wMonth),
            static_cast<int>(stWrite.wDay), static_cast<int>(stWrite.wHour),
            static_cast<int>(stWrite.wMinute), static_cast<int>(stWrite.wSecond));

        LOG(WARNING, timestamp) << xorstr_("NVIDIA Streamproof Bypass:ShadowPlay FTS registry modified");
        return true;
    }
    catch (...) { return false; }
}

void NvidiaDriverPatch::CheckNvidiaDriverPatch() {
    try {
        if (!IsNvidiaGpu())
            return;

        if (CheckNvidiaProcesses()) {
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("NVIDIA Driver Patched:Overlay bypass detected in nvd3dumx.dll");
        }

        if (CheckStreamproofRegistry()) {
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("NVIDIA Streamproof Bypass:ShadowPlay FTS registry tampered");
        }

        CheckFTSLastWriteTime();
    }
    catch (...) {}
}
