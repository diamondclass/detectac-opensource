#pragma once

#include "../../pch.h"

struct BAMEntry {
    std::wstring path;
    std::wstring executionTime;
    std::wstring signatureStatus;
    bool isInCurrentInstance;
};

struct LogonSessionInfo {
    FILETIME logonTime;
    ULONG sessionId;
    bool isInteractive;
};

class BAMParser {
public:
    static bool VerifyFileViaCatalog(LPCWSTR filePath);
    static std::vector<BAMEntry> entries;
    static std::wstring ConvertHardDiskVolumeToLetter(const std::wstring& path);
    static std::wstring FileTimeToStringLocal(const FILETIME& ft);
    static std::wstring CheckDigitalSignature(const std::wstring& filePath);
    static bool IsInCurrentInstance(const std::wstring& execTime);
    static void Parse();
    static bool IsValidTimeFormat(const std::wstring& timeStr);
    static FILETIME StringToFileTimeUTC(const std::wstring& timeStr);
    static std::vector<LogonSessionInfo> GetInteractiveLogonSessions();
    static const std::vector<BAMEntry>& GetEntries() { return entries; }
    static bool CompareExecutionTime(const BAMEntry& entry1, const BAMEntry& entry2);
    static void start_executed_file_checks();
};


inline auto c_executed_files = std::make_unique<BAMParser>();