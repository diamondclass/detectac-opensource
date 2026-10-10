#pragma once

#include "../../pch.h"

class Prefetch_Scanner2 {
public:
    static void start_deleted_prefetch();

private:
    struct DeleteEntry {
        LONGLONG secondBucket;
        std::wstring fullPath;
        std::string timestamp;
        FILETIME rawTime;
    };

    static constexpr int kBurstThreshold = 5; //delete threshold

    static std::wstring ToLower(std::wstring s);
    static std::string FormatTimestamp(const LARGE_INTEGER& ft);
    static std::wstring ResolveParentDir(HANDLE hVolume, ULONGLONG parentRef,
        std::map<ULONGLONG, std::wstring>& cache);
    static void ScanVolume(const wchar_t* volumePath, std::vector<DeleteEntry>& out);
};

inline auto c_prefdel = std::make_unique<Prefetch_Scanner2>();