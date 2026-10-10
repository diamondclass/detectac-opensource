#include "c_junctions.h"

std::string junc_scan::convert_wstring_to_string(const std::wstring& wstr) {
    try {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.to_bytes(wstr);
    }
    catch (...) { return ""; }
}

std::string junc_scan::parse_reason(DWORD reason) {
    try {
        std::ostringstream os;
        if (reason == (USN_REASON_FILE_DELETE | USN_REASON_REPARSE_POINT_CHANGE | USN_REASON_CLOSE)) {
            os << xorstr_("Junction Deleted");
        }
        return os.str();
    }
    catch (...) { return ""; }
}

std::string junc_scan::convert_file_time_to_string(const LARGE_INTEGER& file_time) {
    try {
        FILETIME ft;
        ft.dwLowDateTime = file_time.LowPart;
        ft.dwHighDateTime = file_time.HighPart;
        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&ft, &stUTC);
        SystemTimeToTzSpecificLocalTime(nullptr, &stUTC, &stLocal);
        std::ostringstream os;
        os << std::setw(4) << stLocal.wYear << xorstr_("-")
            << std::setw(2) << std::setfill('0') << stLocal.wMonth << xorstr_("-")
            << std::setw(2) << std::setfill('0') << stLocal.wDay << xorstr_(" ")
            << std::setw(2) << std::setfill('0') << stLocal.wHour << xorstr_(":")
            << std::setw(2) << std::setfill('0') << stLocal.wMinute << xorstr_(":")
            << std::setw(2) << std::setfill('0') << stLocal.wSecond;
        return os.str();
    }
    catch (...) { return ""; }
}

bool junc_scan::read_usn_journal(const std::string& drive_letter, std::atomic<bool>& found_flag) {
    try {
        std::string volume_path = xorstr_("\\\\.\\") + drive_letter;
        HANDLE volume_handle = CreateFileA(volume_path.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (volume_handle == INVALID_HANDLE_VALUE) return false;

        USN_JOURNAL_DATA journal_data;
        DWORD bytes_returned;
        if (!DeviceIoControl(volume_handle, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &journal_data,
            sizeof(journal_data), &bytes_returned, nullptr)) {
            CloseHandle(volume_handle);
            return false;
        }

        READ_USN_JOURNAL_DATA_V0 read_data = {};
        read_data.StartUsn = journal_data.FirstUsn;
        read_data.ReasonMask = 0xFFFFFFFF;
        read_data.UsnJournalID = journal_data.UsnJournalID;

        std::vector<BYTE> buffer(4096);
        while (!found_flag.load()) {
            DWORD bytes_read;
            if (!DeviceIoControl(volume_handle, FSCTL_READ_USN_JOURNAL, &read_data, sizeof(read_data),
                buffer.data(), static_cast<DWORD>(buffer.size()), &bytes_read, nullptr)) {
                break;
            }
            if (bytes_read == 0) break;

            USN* next_usn = reinterpret_cast<USN*>(buffer.data());
            USN_RECORD* record = reinterpret_cast<USN_RECORD*>(buffer.data() + sizeof(USN));

            while (reinterpret_cast<BYTE*>(record) < buffer.data() + bytes_read) {
                DWORD reason = record->Reason;
                if (reason == (USN_REASON_FILE_DELETE | USN_REASON_REPARSE_POINT_CHANGE | USN_REASON_CLOSE)) {
                    std::wstring file_name(record->FileName, record->FileNameLength / sizeof(WCHAR));
                    LOG(WARNING, convert_file_time_to_string(record->TimeStamp))
                        << xorstr_("Bypass Method Found:Junction Deleted: ")
                        << convert_wstring_to_string(file_name);
                    found_flag.store(true);
                    CloseHandle(volume_handle);
                    return true;
                }
                record = reinterpret_cast<USN_RECORD*>(reinterpret_cast<BYTE*>(record) + record->RecordLength);
            }
            read_data.StartUsn = *next_usn;
        }
        CloseHandle(volume_handle);
    }
    catch (...) {}
    return false;
}

void junc_scan::start_junc_scan() {
    try {
        DWORD drives = GetLogicalDrives();
        if (drives == 0) return;

        std::atomic<bool> found_flag(false);
        std::thread scan_thread([&]() {
            for (char drive = 'A'; drive <= 'Z' && !found_flag.load(); ++drive) {
                if (drives & (1 << (drive - 'A'))) {
                    std::string drive_letter = std::string(1, drive) + xorstr_(":");
                    if (junc_scan::read_usn_journal(drive_letter, found_flag)) return;
                }
            }
            });

        for (int i = 0; i < 100; i++) {
            if (found_flag.load()) break;
            Sleep(100);
        }
        found_flag.store(true);
        if (scan_thread.joinable()) scan_thread.join();
        return;
    }
    catch (...) {}
}