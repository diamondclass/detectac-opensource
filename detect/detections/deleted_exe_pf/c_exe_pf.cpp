#include "c_exe_pf.h"

std::vector<exe_pf_scan::custom_check> exe_pf_scan::custom_checks = {

        {xorstr_("Deleted Exe:"), xorstr_("File Deleted"), xorstr_(L".exe")},
        {xorstr_("Deleted VBS:"), xorstr_("File Deleted"), xorstr_(L".vbs")},
        {xorstr_("Eventlog Bypass:User Changed Eventlog To \"Read Only\" to bypass logs ->  Eventlog File: "), xorstr_("File Changed"), xorstr_(L".evtx")},

#ifdef DETECT_FIVEM

        {xorstr_("Deleted RPF:"), xorstr_("File Deleted"), xorstr_(L".rpf")},
        {xorstr_("Edited RPF:"), xorstr_("Data Truncation"), xorstr_(L".rpf")},
#endif

        {xorstr_("Prefetch File Typed/Modified:"), xorstr_("Data Overwrite"), xorstr_(L".pf")},
        {xorstr_("Eventlog File Renamed:"), xorstr_("File Renamed Old Name"), xorstr_(L".evtx")},
        {xorstr_("Eventlog File Renamed:"), xorstr_("File Renamed New Name"), xorstr_(L".evtx")},
        {xorstr_("Virtual Disk Deleted:"), xorstr_("File Deleted"), xorstr_(L".vhd")},
        {xorstr_("ICACLS.EXE Used:"), xorstr_("Data Extend"), xorstr_(L"icacls.exe-")},
        {xorstr_("Amcache Cleaned:"), xorstr_("File Deleted"), xorstr_(L"Amcache.hve") },
        {xorstr_("PCA Cleaned:"), xorstr_("File Deleted"), xorstr_(L"PcaGeneralDb0") },
        {xorstr_("PCA Cleaned:"), xorstr_("File Deleted"), xorstr_(L"PcaAppLaunchDic") },
        {xorstr_("PCA Cleaned:"), xorstr_("File Deleted"), xorstr_(L"PcaGeneralDb1") }

};

std::map<ULONGLONG, std::wstring> exe_pf_scan::file_reference_cache;

static bool is_warning_description(const std::string& desc) {
    return desc.find(xorstr_("Prefetch File Typed/Modified")) != std::string::npos
        || desc.find(xorstr_("Eventlog File Renamed"))         != std::string::npos
        || desc.find(xorstr_("Virtual Disk Deleted"))          != std::string::npos
        || desc.find(xorstr_("ICACLS.EXE Used"))               != std::string::npos;
}

std::string exe_pf_scan::convert_wstring_to_string(const std::wstring& wstr) {
    try{
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
    return converter.to_bytes(wstr);
    }
    catch (...) { return ""; }
}

std::string exe_pf_scan::parse_reason(DWORD reason) {
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

    std::string reasons = os.str();
    if (!reasons.empty()) {
        reasons.pop_back();
        reasons.pop_back();
    }
    return reasons;
    }
    catch (...) { return ""; }
}

std::wstring exe_pf_scan::resolve_parent_directory(HANDLE volume_handle, ULONGLONG file_reference) {
    try{
    if (file_reference_cache.find(file_reference) != file_reference_cache.end()) {
        return file_reference_cache[file_reference];
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

    file_reference_cache[file_reference] = resolved_path;
    return resolved_path;
    }
    catch (...) { return L""; }
}

std::string exe_pf_scan::convert_file_time_to_string(const LARGE_INTEGER& file_time) {
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

void exe_pf_scan::read_usn_journal(const std::string& drive_letter) {
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

        while (reinterpret_cast<BYTE*>(record) < buffer.data() + bytes_read) {
            std::wstring file_name(record->FileName, record->FileNameLength / sizeof(WCHAR));
            std::string reason = parse_reason(record->Reason);

            std::wstring parent_directory = resolve_parent_directory(volume_handle, record->ParentFileReferenceNumber);

            bool has_custom_output = false;

            for (const auto& check : custom_checks) {
                if (file_name.size() >= check.substring.size() &&
                    file_name.compare(file_name.size() - check.substring.size(), check.substring.size(), check.substring) == 0 &&
                    reason.find(check.reason) != std::string::npos) {
                    
                    // Additional check for .pf files
                    if (check.substring == xorstr_(L".pf")) {
                        std::wstring full_path = parent_directory + file_name;
                        std::wstring prefetch_path = xorstr_(L"C:\\Windows\\Prefetch");
                        if (full_path.find(prefetch_path) != std::wstring::npos) {
                            has_custom_output = true;
                        }
                    } else {
                        has_custom_output = true;
                    }
                    break;
                }
            }

            if (has_custom_output) {
                for (const auto& check : custom_checks) {
                    if (file_name.size() >= check.substring.size() &&
                        file_name.compare(file_name.size() - check.substring.size(), check.substring.size(), check.substring) == 0 &&
                        reason.find(check.reason) != std::string::npos) {
                        
                        if (check.substring == xorstr_(L".pf")) {
                            std::wstring full_path = parent_directory + file_name;
                            std::wstring prefetch_path = xorstr_(L"C:\\Windows\\Prefetch");
                            if (full_path.find(prefetch_path) != std::wstring::npos) {
                                if (is_warning_description(check.description)) {
                                    LOG(WARNING, convert_file_time_to_string(record->TimeStamp))
                                        << check.description
                                        << convert_wstring_to_string(parent_directory)
                                        << convert_wstring_to_string(file_name);
                                } else {
                                    LOG(INFO, convert_file_time_to_string(record->TimeStamp))
                                        << check.description
                                        << convert_wstring_to_string(parent_directory)
                                        << convert_wstring_to_string(file_name);
                                }
                            }
                        } else {
                            if (is_warning_description(check.description)) {
                                LOG(WARNING, convert_file_time_to_string(record->TimeStamp))
                                    << check.description
                                    << convert_wstring_to_string(parent_directory)
                                    << convert_wstring_to_string(file_name);
                            } else {
                                LOG(INFO, convert_file_time_to_string(record->TimeStamp))
                                    << check.description
                                    << convert_wstring_to_string(parent_directory)
                                    << convert_wstring_to_string(file_name);
                            }
                        }
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

    CloseHandle(volume_handle);
    }
    catch (...) {}
}

void exe_pf_scan::start_exe_pf_scan() {
    try{
    DWORD drives = GetLogicalDrives();
    if (drives == 0) {
        return;
    }

    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        if (drives & (1 << (drive - 'A'))) {
            std::string drive_letter = std::string(1, drive) + xorstr_(":");
            exe_pf_scan::read_usn_journal(drive_letter);
        }
    }

    return;
    }
    catch (...) {}
}