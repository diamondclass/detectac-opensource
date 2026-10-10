#include "c_tasksch_bypass.h"

std::unordered_map<std::wstring, std::time_t> c_tasksch_bypass::set1_events;
std::unordered_map<ULONGLONG, std::wstring>   c_tasksch_bypass::file_reference_cache;

static constexpr DWORD kSet1Mask = USN_REASON_FILE_CREATE | USN_REASON_DATA_EXTEND | USN_REASON_CLOSE;
static constexpr DWORD kSet2Mask = USN_REASON_FILE_DELETE | USN_REASON_CLOSE;
static constexpr ULONGLONG kEpochDelta = 116444736000000000ULL;
static constexpr ULONGLONG kTicksPerSec = 10000000ULL;
static constexpr std::time_t kWindowSecs = 300;
static constexpr size_t kInitialCacheCapacity = 1 << 16;

__forceinline std::time_t c_tasksch_bypass::filetime_to_epoch(const LARGE_INTEGER& file_time)
{
    const ULONGLONG ticks =
        (static_cast<ULONGLONG>(file_time.HighPart) << 32) |
        static_cast<ULONGLONG>(static_cast<DWORD>(file_time.LowPart));

    return static_cast<std::time_t>((ticks - kEpochDelta) / kTicksPerSec);
}

__forceinline bool c_tasksch_bypass::is_set1(DWORD reason) { return reason == kSet1Mask; }
__forceinline bool c_tasksch_bypass::is_set2(DWORD reason) { return reason == kSet2Mask; }

bool c_tasksch_bypass::starts_with_tasks_path(const std::wstring& path)
{
    try
    {
        static const std::wstring kTarget = xorstr_(L"c:\\windows\\system32\\tasks");
        static constexpr size_t kTargetLen = 25;

        if (path.size() < kTargetLen) return false;

        for (size_t i = 0; i < kTargetLen; ++i)
        {
            if (::towlower(path[i]) != kTarget[i])
                return false;
        }

        return true;
    }
    catch (...) { return false; }
}

std::string c_tasksch_bypass::convert_wstring_to_string(const std::wstring& wstr)
{
    try
    {
        if (wstr.empty()) return {};

        int sz = WideCharToMultiByte(
            CP_UTF8,
            0,
            wstr.data(),
            static_cast<int>(wstr.size()),
            nullptr,
            0,
            nullptr,
            nullptr);

        if (sz <= 0) return {};

        std::string out(sz, '\0');

        WideCharToMultiByte(
            CP_UTF8,
            0,
            wstr.data(),
            static_cast<int>(wstr.size()),
            out.data(),
            sz,
            nullptr,
            nullptr);

        return out;
    }
    catch (...) { return {}; }
}

std::string c_tasksch_bypass::parse_reason(DWORD reason)
{
    try
    {
        std::ostringstream os;

        if (reason & USN_REASON_DATA_OVERWRITE) os << xorstr_("Data Overwrite, ");
        if (reason & USN_REASON_DATA_EXTEND) os << xorstr_("Data Extend, ");
        if (reason & USN_REASON_DATA_TRUNCATION) os << xorstr_("Data Truncation, ");
        if (reason & USN_REASON_FILE_CREATE) os << xorstr_("File Created, ");
        if (reason & USN_REASON_FILE_DELETE) os << xorstr_("File Deleted, ");
        if (reason & USN_REASON_RENAME_OLD_NAME) os << xorstr_("File Renamed Old Name, ");
        if (reason & USN_REASON_RENAME_NEW_NAME) os << xorstr_("File Renamed New Name, ");
        if (reason & USN_REASON_CLOSE) os << xorstr_("File Closed, ");
        if (reason & USN_REASON_BASIC_INFO_CHANGE) os << xorstr_("File Changed, ");
        if (reason & USN_REASON_REPARSE_POINT_CHANGE) os << xorstr_("Junction Change, ");

        std::string s = os.str();

        if (s.size() >= 2)
        {
            s.pop_back();
            s.pop_back();
        }

        return s;
    }
    catch (...) { return {}; }
}

std::wstring c_tasksch_bypass::resolve_parent_directory(HANDLE volume_handle, ULONGLONG file_reference)
{
    try
    {
        auto [it, inserted] = file_reference_cache.try_emplace(file_reference, std::wstring{});

        if (!inserted)
            return it->second;

        FILE_ID_DESCRIPTOR fid{};
        fid.dwSize = sizeof(FILE_ID_DESCRIPTOR);
        fid.Type = FileIdType;
        fid.FileId.QuadPart = static_cast<LONGLONG>(file_reference);

        HANDLE fh = OpenFileById(
            volume_handle,
            &fid,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            0);

        if (fh == INVALID_HANDLE_VALUE)
            return it->second;

        WCHAR buf[MAX_PATH];

        DWORD r = GetFinalPathNameByHandleW(
            fh,
            buf,
            MAX_PATH,
            FILE_NAME_NORMALIZED);

        CloseHandle(fh);

        if (r == 0)
            return it->second;

        std::wstring resolved(buf, r);

        if (resolved.size() >= 4 &&
            resolved[0] == L'\\' &&
            resolved[1] == L'\\' &&
            resolved[2] == L'?' &&
            resolved[3] == L'\\')
        {
            resolved.erase(0, 4);
        }

        if (!resolved.empty() && resolved.back() != L'\\')
            resolved += L'\\';

        it->second = std::move(resolved);

        return it->second;
    }
    catch (...)
    {
        return {};
    }
}

std::string c_tasksch_bypass::convert_file_time_to_string(const LARGE_INTEGER& file_time)
{
    try
    {
        FILETIME ft;
        ft.dwLowDateTime = file_time.LowPart;
        ft.dwHighDateTime = file_time.HighPart;

        SYSTEMTIME stUTC{};
        SYSTEMTIME stLocal{};

        FileTimeToSystemTime(&ft, &stUTC);
        SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal);

        char buf[32];

        std::snprintf(
            buf,
            sizeof(buf),
            xorstr_("%04d-%02d-%02d %02d:%02d:%02d"),
            stLocal.wYear,
            stLocal.wMonth,
            stLocal.wDay,
            stLocal.wHour,
            stLocal.wMinute,
            stLocal.wSecond);

        return buf;
    }
    catch (...)
    {
        return {};
    }
}

void c_tasksch_bypass::read_usn_journal(const std::string& drive_letter)
{
    try
    {
        std::string volume_path = xorstr_("\\\\.\\") + drive_letter;

        HANDLE volume_handle = CreateFileA(
            volume_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);

        if (volume_handle == INVALID_HANDLE_VALUE)
            return;

        USN_JOURNAL_DATA journal_data{};
        DWORD bytes_returned = 0;

        if (!DeviceIoControl(
            volume_handle,
            FSCTL_QUERY_USN_JOURNAL,
            nullptr,
            0,
            &journal_data,
            sizeof(journal_data),
            &bytes_returned,
            nullptr))
        {
            CloseHandle(volume_handle);
            return;
        }

        READ_USN_JOURNAL_DATA_V0 read_data{};
        read_data.StartUsn = journal_data.FirstUsn;
        read_data.ReasonMask = 0xFFFFFFFF;
        read_data.UsnJournalID = journal_data.UsnJournalID;

        std::vector<BYTE> buffer(65536);

        std::unordered_map<std::wstring, std::time_t> local_set1;
        local_set1.reserve(kInitialCacheCapacity);
        file_reference_cache.reserve(kInitialCacheCapacity);

        while (true)
        {
            DWORD bytes_read = 0;

            if (!DeviceIoControl(
                volume_handle,
                FSCTL_READ_USN_JOURNAL,
                &read_data,
                sizeof(read_data),
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytes_read,
                nullptr))
            {
                break;
            }

            if (bytes_read <= sizeof(USN))
                break;

            const BYTE* ptr = buffer.data() + sizeof(USN);
            const BYTE* end = buffer.data() + bytes_read;

            while (ptr < end)
            {
                const USN_RECORD* record =
                    reinterpret_cast<const USN_RECORD*>(ptr);

                if (record->RecordLength == 0)
                    break;

                const DWORD reason = record->Reason;

                if (reason == kSet1Mask || reason == kSet2Mask)
                {
                    const wchar_t* fn_ptr = record->FileName;
                    const int fn_len =
                        record->FileNameLength / sizeof(WCHAR);

                    std::wstring parent =
                        resolve_parent_directory(
                            volume_handle,
                            record->ParentFileReferenceNumber);

                    if (starts_with_tasks_path(parent))
                    {
                        std::wstring full_path;

                        full_path.reserve(parent.size() + fn_len);

                        full_path = parent;
                        full_path.append(fn_ptr, fn_len);

                        for (auto& ch : full_path)
                        {
                            if (ch < 32 || ch > 126)
                                ch = L'?';
                        }

                        const std::time_t event_time =
                            filetime_to_epoch(record->TimeStamp);

                        if (reason == kSet1Mask)
                        {
                            local_set1[full_path] = event_time;
                        }
                        else
                        {
                            auto it = local_set1.find(full_path);

                            if (it != local_set1.end() &&
                                (event_time - it->second) <= kWindowSecs)
                            {
                                LOG(DETECTION, xorstr_("N/A"))
                                    << xorstr_("Task Scheduler Bypass Found: The following task has been created, executed, then deleted  ->  ")
                                    << convert_wstring_to_string(full_path);
                            }
                        }
                    }
                }

                ptr += record->RecordLength;
            }

            read_data.StartUsn =
                *reinterpret_cast<const USN*>(buffer.data());
        }

        CloseHandle(volume_handle);
    }
    catch (...) {}
}

void c_tasksch_bypass::start_task_scan()
{
    try
    {
        DWORD drives = GetLogicalDrives();

        if (!drives)
            return;

        std::vector<std::thread> threads;
        threads.reserve(26);

        for (char drive = 'A'; drive <= 'Z'; ++drive)
        {
            if (drives & (1u << (drive - 'A')))
            {
                std::string dl = std::string(1, drive) + xorstr_(":");

                threads.emplace_back([dl]()
                    {
                        try
                        {
                            c_tasksch_bypass::read_usn_journal(dl);
                        }
                        catch (...) {}
                    });
            }
        }

        for (auto& t : threads)
        {
            if (t.joinable())
                t.join();
        }
    }
    catch (...) {}
}