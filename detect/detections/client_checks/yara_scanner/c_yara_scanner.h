#pragma once

#define NOMINMAX

#include "../../../pch.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <vector>
#include <string>
#include <memory>
#include <cstdint>
#include <unordered_set>
#include <yara.h>

struct ScanResult
{
    uint64_t  filesScanned;
    uint64_t  filesSkipped;
    uint64_t  detections;
    uint64_t  errors;
    uint64_t  bytesScanned;
    long long elapsedSeconds;
    bool      timedOut;
};

class YaraScanner
{
public:
    static void start_yara_scan();
    static ScanResult yara_Scanner();

    YaraScanner() = default;

private:
    static constexpr ULONGLONG MAX_FILE_SIZE = 160ULL * 1024 * 1024;
    static constexpr int       SCAN_TIMEOUT = 3;
    static constexpr size_t    BATCH_SIZE = 256;
    static constexpr size_t    READ_BUF_SIZE = 4ULL * 1024 * 1024;
    static constexpr int       MAX_SCAN_SECS = 600;
    static constexpr size_t    MAX_PATH_DEPTH_CHARS = 4096;

    struct FileEntry
    {
        std::wstring path;
        uint64_t     size;
        DWORD        attrs;
    };

    class FileQueue
    {
    public:
        void   PushBatch(std::vector<FileEntry>& batch);
        bool   Pop(FileEntry& out);
        void   SetDone();
        size_t Size() const;
        void   Reset();
    private:
        std::queue<FileEntry>   q_;
        mutable std::mutex      mtx_;
        std::condition_variable cv_;
        bool                    done_ = false;
    };

    static std::atomic<uint64_t>                 s_filesScanned;
    static std::atomic<uint64_t>                 s_filesSkipped;
    static std::atomic<uint64_t>                 s_detections;
    static std::atomic<uint64_t>                 s_errors;
    static std::atomic<uint64_t>                 s_bytesScanned;
    static std::atomic<bool>                     s_scanDone;
    static std::atomic<bool>                     s_abort;
    static std::mutex                            s_consoleMtx;
    static std::chrono::steady_clock::time_point s_startTime;
    static FileQueue                             s_queue;
    static std::unordered_set<std::wstring>      s_visitedVolumes;
    static std::mutex                            s_visitedVolumesMtx;

    static void                      ResetState();
    static bool                      HasSuspiciousFilenameChars(const std::wstring& path);
    static std::vector<std::wstring> GetAllDrives();
    static bool                      IsExcludedDir(const std::wstring& path);
    static bool                      IsScanExtension(const wchar_t* filename);
    static bool                      TryClaimMountedVolume(const std::wstring& parentDir, const std::wstring& mountPointPath);
    static void                      EnumerateFiles(const std::wstring& root);
    static int                       YaraCallback(YR_SCAN_CONTEXT*, int, void*, void*);
    static void                      ScanWorker(YR_RULES* rules);
    static void                      ProgressThread();
};

inline auto c_yara = std::make_unique<YaraScanner>();