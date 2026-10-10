#include "c_usnjournal_ex.h"

std::vector<usn_ex_scan::custom_check> usn_ex_scan::custom_checks_ex = {


        { xorstr_("WindowsDB File Cleaned:"), xorstr_("File Deleted"), xorstr_(L"Windows.db") },
        { xorstr_("Activitiescache Artifact Cleaned:"), xorstr_("Data Truncation"), xorstr_(L"ActivitiesCache.db") },
        { xorstr_("Activitiescache Artifact Cleaned:"), xorstr_("File Deleted"), xorstr_(L"ActivitiesCache.db") },

};

std::map<ULONGLONG, std::wstring> usn_ex_scan::file_reference_cache_ex;

std::string usn_ex_scan::convert_wstring_to_string_ex(const std::wstring& wstr) {
    try{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
    }
    catch (...) { return ""; }
}

std::string usn_ex_scan::parse_reason_ex(DWORD reason) {
    try{
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

    std::string reasons = os.str();
    if (!reasons.empty()) {
        reasons.pop_back();
        reasons.pop_back();
    }
    return reasons;
    }
    catch (...) { return ""; }
}

std::wstring usn_ex_scan::resolve_parent_directory_ex(HANDLE volume_handle, ULONGLONG file_reference) {
    try{
    if (file_reference_cache_ex.find(file_reference) != file_reference_cache_ex.end()) {
        return file_reference_cache_ex[file_reference];
    }

    FILE_ID_DESCRIPTOR file_id_desc = {};
    file_id_desc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
    file_id_desc.Type = FileIdType;
    file_id_desc.FileId.QuadPart = file_reference;

    HANDLE file_handle = OpenFileById(volume_handle, &file_id_desc, 0, 0, nullptr, 0);
    if (file_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        if (error == ERROR_FILE_NOT_FOUND) {
            return xorstr_(L"");
        }
        return xorstr_(L"");
    }

    WCHAR path_buffer[MAX_PATH];
    DWORD result = GetFinalPathNameByHandleW(file_handle, path_buffer, MAX_PATH, FILE_NAME_NORMALIZED);
    CloseHandle(file_handle);

    if (result == 0) {
        return xorstr_(L"");
    }

    std::wstring resolved_path(path_buffer);

    const std::wstring prefix = xorstr_(L"\\\\?\\");
    if (resolved_path.compare(0, prefix.length(), prefix) == 0) {
        resolved_path = resolved_path.substr(prefix.length());
    }

    if (!resolved_path.empty() && resolved_path.back() != L'\\') {
        resolved_path += L'\\';
    }

    file_reference_cache_ex[file_reference] = resolved_path;
    return resolved_path;
    }
    catch (...) { return L""; }
}

std::string usn_ex_scan::convert_file_time_to_string_ex(const LARGE_INTEGER& file_time) {
    try{
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

void usn_ex_scan::read_usn_journal_ex(const std::string& drive_letter) {
    try{
    std::string volume_path = xorstr_("\\\\.\\") + drive_letter;

    HANDLE volume_handle = CreateFileA(
        volume_path.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr);

    if (volume_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return;
    }

    USN_JOURNAL_DATA journal_data;
    DWORD bytes_returned;
    if (!DeviceIoControl(
        volume_handle,
        FSCTL_QUERY_USN_JOURNAL,
        nullptr,
        0,
        &journal_data,
        sizeof(journal_data),
        &bytes_returned,
        nullptr)) {
        DWORD error = GetLastError();
        CloseHandle(volume_handle);
        return;
    }


    READ_USN_JOURNAL_DATA_V0 read_data = {};
    read_data.StartUsn = journal_data.FirstUsn;
    read_data.ReasonMask = 0xFFFFFFFF;
    read_data.UsnJournalID = journal_data.UsnJournalID;

    std::vector<BYTE> buffer(4096);

    DWORD64 last_output_time = GetTickCount64();

    while (true) {
        DWORD bytes_read;
        if (!DeviceIoControl(
            volume_handle,
            FSCTL_READ_USN_JOURNAL,
            &read_data,
            sizeof(read_data),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &bytes_read,
            nullptr)) {
            DWORD error = GetLastError();
            if (error == ERROR_HANDLE_EOF) {
                break;
            }
            else {
                LOG(WARNING, xorstr_("N/A")) << xorstr_("USN Journal Not Present On Drive:") << drive_letter;
                break;
            }
        }

        if (bytes_read == 0) {
            if (GetTickCount64() - last_output_time > 5000) {
                break;
            }
            continue;
        }

        USN* next_usn = reinterpret_cast<USN*>(buffer.data());
        USN_RECORD* record = reinterpret_cast<USN_RECORD*>(buffer.data() + sizeof(USN));

        bool output_occurred = false;

        std::set<std::wstring> logged_entries;

        while (reinterpret_cast<BYTE*>(record) < buffer.data() + bytes_read) {
            std::wstring file_name(record->FileName, record->FileNameLength / sizeof(WCHAR));

            for (auto& ch : file_name) {
                if (ch < 32 || ch > 126) {
                    ch = L'?';
                }
            }

            std::string reason = parse_reason_ex(record->Reason);

            std::wstring parent_directory = resolve_parent_directory_ex(volume_handle, record->ParentFileReferenceNumber);

            bool has_custom_output = false;

            for (const auto& check : custom_checks_ex) {
                if (_wcsicmp(file_name.c_str(), check.substring.c_str()) == 0
                    && reason.find(check.reason) != std::string::npos) {
                    has_custom_output = true;
                    break;
                }
            }

            if (has_custom_output) {
                for (const auto& check : custom_checks_ex) {
                    if (_wcsicmp(file_name.c_str(), check.substring.c_str()) == 0
                        && reason.find(check.reason) != std::string::npos) {
                        LOG (WARNING, convert_file_time_to_string_ex(record->TimeStamp))
                            << check.description
                            << convert_wstring_to_string_ex(parent_directory)
                            << convert_wstring_to_string_ex(file_name);
                    }
                }

                output_occurred = true;
                last_output_time = GetTickCount64();
            }

            record = reinterpret_cast<USN_RECORD*>(reinterpret_cast<BYTE*>(record) + record->RecordLength);
        }

        if (!output_occurred && GetTickCount64() - last_output_time > 5000) {
            break;
        }

        read_data.StartUsn = *next_usn;
    }

    CloseHandle(volume_handle); }
    catch (...) {}
}

void usn_ex_scan::start_scan_ex() {
    try{
    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        return;
    }

    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        if (drives & (1 << (drive - 'A'))) {
            std::string drive_letter = std::string(1, drive) + xorstr_(":");
            usn_ex_scan::read_usn_journal_ex(drive_letter);
        }
    }
    return;
    }
    catch (...) {}
}