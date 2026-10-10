#pragma once

#include "../../pch.h"

class NvidiaDriverPatch
{
public:
    static void CheckNvidiaDriverPatch();

private:
    static bool IsNvidiaGpu();
    static bool ScanModuleForPatches(HANDLE hProcess, HMODULE hModule);
    static bool CheckNvidiaProcesses();
    static bool CheckStreamproofRegistry();
    static bool CheckFTSLastWriteTime();
};

inline auto c_nvidia_patch = std::make_unique<NvidiaDriverPatch>();
