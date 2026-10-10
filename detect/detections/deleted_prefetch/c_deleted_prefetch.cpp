#include "c_deleted_prefetch.h"

std::wstring Prefetch_Scanner2::ToLower(std::wstring s) {
    try {
        for (auto& c : s) c = static_cast<wchar_t>(std::towlower(c));
    }
    catch (...) {}
    return s;
}

std::string Prefetch_Scanner2::FormatTimestamp(const LARGE_INTEGER& ft) {
    try {
        FILETIME fileTime;
        fileTime.dwLowDateTime = ft.LowPart;
        fileTime.dwHighDateTime = ft.HighPart;

        SYSTEMTIME stUTC{}, stLocal{};
        if (!FileTimeToSystemTime(&fileTime, &stUTC)) return {};
        if (!SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal)) return {};

        char buf[32];
        if (sprintf_s(buf, xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            stLocal.wYear, stLocal.wMonth, stLocal.wDay,
            stLocal.wHour, stLocal.wMinute, stLocal.wSecond) <= 0) {
            return {};
        }
        return std::string(buf);
    }
    catch (...) {
        return {};
    }
}

std::wstring Prefetch_Scanner2::ResolveParentDir(HANDLE hVolume, ULONGLONG parentRef,
    std::map<ULONGLONG, std::wstring>& cache) {
    try {
        try {
            auto it = cache.find(parentRef);
            if (it != cache.end()) return it->second;
        }
        catch (...) {}

        FILE_ID_DESCRIPTOR fileIdDesc{};
        try {
            fileIdDesc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
            fileIdDesc.Type = FileIdType;
            fileIdDesc.FileId.QuadPart = static_cast<LONGLONG>(parentRef);
        }
        catch (...) { return {}; }

        HANDLE hFile = INVALID_HANDLE_VALUE;
        try {
            hFile = OpenFileById(hVolume, &fileIdDesc, 0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, 0);
        }
        catch (...) { return {}; }

        if (hFile == INVALID_HANDLE_VALUE) {
            try { cache[parentRef] = std::wstring{}; }
            catch (...) {}
            return {};
        }

        wchar_t pathBuf[MAX_PATH];
        DWORD result = 0;
        try {
            result = GetFinalPathNameByHandleW(hFile, pathBuf, MAX_PATH, FILE_NAME_NORMALIZED);
        }
        catch (...) {}
        try { CloseHandle(hFile); }
        catch (...) {}

        if (result == 0 || result >= MAX_PATH) {
            try { cache[parentRef] = std::wstring{}; }
            catch (...) {}
            return {};
        }

        std::wstring resolved;
        try { resolved.assign(pathBuf); }
        catch (...) { return {}; }

        try {
            if (resolved.compare(0, 4, xorstr_(L"\\\\?\\")) == 0)
                resolved = resolved.substr(4);
        }
        catch (...) {}

        try {
            if (!resolved.empty() && resolved.back() != L'\\')
                resolved += L'\\';
        }
        catch (...) {}

        try { cache[parentRef] = resolved; }
        catch (...) {}
        return resolved;
    }
    catch (...) {
        return {};
    }
}

void Prefetch_Scanner2::ScanVolume(const wchar_t* volumePath, std::vector<DeleteEntry>& out) {
    HANDLE hVolume = INVALID_HANDLE_VALUE;
    try {
        try {
            hVolume = CreateFileW(volumePath,
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
        }
        catch (...) { return; }
        if (hVolume == INVALID_HANDLE_VALUE) return;

        USN_JOURNAL_DATA journalData{};
        DWORD bytesReturned = 0;
        BOOL ok = FALSE;
        try {
            ok = DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL,
                nullptr, 0, &journalData, sizeof(journalData),
                &bytesReturned, nullptr);
        }
        catch (...) {}
        if (!ok) {
            try { CloseHandle(hVolume); }
            catch (...) {}
            return;
        }

        READ_USN_JOURNAL_DATA_V0 readData{};
        try {
            readData.StartUsn = journalData.FirstUsn;
            readData.ReasonMask = USN_REASON_FILE_DELETE;
            readData.ReturnOnlyOnClose = FALSE;
            readData.Timeout = 0;
            readData.BytesToWaitFor = 0;
            readData.UsnJournalID = journalData.UsnJournalID;
        }
        catch (...) {
            try { CloseHandle(hVolume); }
            catch (...) {}
            return;
        }

        std::vector<BYTE> buffer;
        try { buffer.resize(1 << 16); }
        catch (...) {
            try { CloseHandle(hVolume); }
            catch (...) {}
            return;
        }

        std::map<ULONGLONG, std::wstring> parentCache;
        std::wstring targetDir;
        try { targetDir.assign(xorstr_(L"c:\\windows\\prefetch\\")); }
        catch (...) {}

        for (;;) {
            DWORD bytesRead = 0;
            BOOL readOk = FALSE;
            try {
                readOk = DeviceIoControl(hVolume, FSCTL_READ_USN_JOURNAL,
                    &readData, sizeof(readData),
                    buffer.data(), static_cast<DWORD>(buffer.size()),
                    &bytesRead, nullptr);
            }
            catch (...) { break; }
            if (!readOk) break;
            if (bytesRead <= sizeof(USN)) break;

            USN nextUsn = 0;
            try { nextUsn = *reinterpret_cast<USN*>(buffer.data()); }
            catch (...) { break; }

            BYTE* ptr = buffer.data() + sizeof(USN);
            BYTE* end = buffer.data() + bytesRead;

            while (ptr < end) {
                try {
                    auto* record = reinterpret_cast<USN_RECORD*>(ptr);
                    if (record->RecordLength == 0) { ptr = end; break; }

                    if (record->Reason & USN_REASON_FILE_DELETE) {
                        std::wstring parentDir = ResolveParentDir(
                            hVolume, record->ParentFileReferenceNumber, parentCache);

                        if (!parentDir.empty() && ToLower(parentDir) == targetDir) {
                            std::wstring fileName;
                            try {
                                fileName.assign(record->FileName,
                                    record->FileNameLength / sizeof(WCHAR));
                            }
                            catch (...) {}

                            bool isPrefetchFile = false;
                            try {
                                size_t n = fileName.size();
                                if (n >= 3) {
                                    wchar_t c1 = fileName[n - 3];
                                    wchar_t c2 = static_cast<wchar_t>(std::towlower(fileName[n - 2]));
                                    wchar_t c3 = static_cast<wchar_t>(std::towlower(fileName[n - 1]));
                                    isPrefetchFile = (c1 == L'.') && (c2 == L'p') && (c3 == L'f');
                                }
                            }
                            catch (...) {}

                            if (isPrefetchFile) {
                                try {
                                    DeleteEntry e;
                                    e.secondBucket = record->TimeStamp.QuadPart / 10000000LL;
                                    e.fullPath = parentDir + fileName;
                                    e.timestamp = FormatTimestamp(record->TimeStamp);
                                    e.rawTime.dwLowDateTime = record->TimeStamp.LowPart;
                                    e.rawTime.dwHighDateTime = record->TimeStamp.HighPart;
                                    out.push_back(std::move(e));
                                }
                                catch (...) {}
                            }
                        }
                    }

                    ptr += record->RecordLength;
                }
                catch (...) { break; }
            }

            try { readData.StartUsn = nextUsn; }
            catch (...) { break; }
        }

        try { CloseHandle(hVolume); }
        catch (...) {}
    }
    catch (...) {
        if (hVolume != INVALID_HANDLE_VALUE) {
            try { CloseHandle(hVolume); }
            catch (...) {}
        }
    }
}

void Prefetch_Scanner2::start_deleted_prefetch() {
    try {
        std::vector<DeleteEntry> entries;
        try { ScanVolume(xorstr_(L"\\\\.\\C:"), entries); }
        catch (...) {}

        std::unordered_map<LONGLONG, int> perSecondCount;
        try {
            for (const auto& e : entries) ++perSecondCount[e.secondBucket];
        }
        catch (...) {}

        FILETIME logon_time_local = {};
        bool have_logon_time = false;
        try {
            logon_time_local = utils->get_logon_time();
            have_logon_time = (logon_time_local.dwLowDateTime != 0 || logon_time_local.dwHighDateTime != 0);
        }
        catch (...) {}

        for (const auto& e : entries) {
            try {
                if (perSecondCount[e.secondBucket] - 1 > kBurstThreshold) continue;

                int needed = WideCharToMultiByte(CP_UTF8, 0,
                    e.fullPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
                if (needed <= 1) continue;

                std::string narrow(static_cast<size_t>(needed - 1), '\0');
                if (WideCharToMultiByte(CP_UTF8, 0, e.fullPath.c_str(), -1,
                    narrow.data(), needed, nullptr, nullptr) <= 0) continue;

                bool after_logon = false;
                if (have_logon_time) {
                    FILETIME delete_time_local = {};
                    if (FileTimeToLocalFileTime(&e.rawTime, &delete_time_local)) {
                        after_logon = CompareFileTime(&delete_time_local, &logon_time_local) >= 0;
                    }
                }

                if (after_logon) {
                    LOG ( DETECTION , e.timestamp ) << xorstr_("Manually Deleted Prefetch File (After Logon):") << narrow;
                }
                else {
                    LOG ( WARNING , e.timestamp ) << xorstr_("Manually Deleted Prefetch File (Before Logon):") << narrow;
                }
            }
            catch (...) {}
        }
    }
    catch (...) {}
}
