#include "c_fat32_modification2.h"

const std::vector<std::wstring> valid_extensions = { xorstr_ ( L".dll"), xorstr_(L".zip"),  xorstr_( L".exe"),  xorstr_(L".res"),  xorstr_(L".ico"),  xorstr_(L".ini"), xorstr_(L".mui") };

bool c_fat32_modification2::enable_debug_privilege()
{
    try{
    HANDLE h_token;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &h_token))
    {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(h_token);
        return false;

    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(h_token, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr))
    {
        CloseHandle(h_token);
        return false;
    }

    CloseHandle(h_token);
    return true;
    }
    catch (...) {}
}

DWORD c_fat32_modification2::get_process_id_by_name(const std::string& process_name)
{
    try{
    PROCESSENTRY32 process_entry;
    process_entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32First(snapshot, &process_entry))
    {
        do {
            if (process_name == process_entry.szExeFile)
            {
                CloseHandle(snapshot);
                return process_entry.th32ProcessID;
            }
        } while (Process32Next(snapshot, &process_entry));
    }

    CloseHandle(snapshot);
    return 0;
    }
    catch (...) {}
}

bool c_fat32_modification2::has_valid_extension(const std::wstring& file_path)
{
    try{
    for (const auto& ext : valid_extensions)
    {
        if (file_path.find(ext) != std::wstring::npos)
        {
            return true;
        }
    }
    return false;
    }
    catch (...) {}
}

std::vector<std::wstring> c_fat32_modification2::get_fat32_drives()
{
    try{
        std::vector<std::wstring> fat32_drives;
    DWORD drives = GetLogicalDrives();
    std::wstring drive_path = xorstr_(L"?:\\");

    for (int i = 0; i < 26; ++i)
    {
        if (drives & (1 << i))
        {
            drive_path[0] = L'A' + i;
            wchar_t file_system_name[MAX_PATH];

            if (GetVolumeInformationW(drive_path.c_str(), NULL, 0, NULL, NULL, NULL, file_system_name, MAX_PATH))
            {
                if (wcscmp(file_system_name, xorstr_ ( L"FAT32")) == 0)
                {
                    fat32_drives.push_back(drive_path);
                }
            }
        }
    }

    return fat32_drives;
    }
    catch (...) {}
    return {};
}

bool c_fat32_modification2::is_private_memory_region(const MEMORY_BASIC_INFORMATION& mbi)
{
    try{
    return mbi.Type == MEM_PRIVATE;
    }
    catch (...) {}
}

void c_fat32_modification2::search_for_unicode_strings(const wchar_t* buffer, SIZE_T size, const std::wstring& drive_letter)
{
    try{
    for (SIZE_T i = 0; i < size / sizeof(wchar_t) - 2; ++i) {
        if (buffer[i] == drive_letter[0] && buffer[i + 1] == L':' && buffer[i + 2] == L'\\')
        {
            SIZE_T str_start = i;
            SIZE_T str_end = i;

            while (str_end < size / sizeof(wchar_t) && std::iswprint(buffer[str_end]))
            {
                ++str_end;
            }

            std::wstring found_string(&buffer[str_start], str_end - str_start);

            if (has_valid_extension(found_string) && utils->file_exists(found_string))
            {
                std::stringstream message_stream;
                message_stream << xorstr_ ( "File Replaced/Renamed On FAT Drive: ") << utils->convert_wstring_to_string( found_string );
                std::string message = message_stream.str ( );

                LOG ( WARNING, xorstr_ ( "N/A") ) << message;

                std::wcout << xorstr_ ( L" ") << found_string << std::endl;
            }

            i = str_end;
        }
    }
    }
    catch (...) {}
}

void c_fat32_modification2::search_for_ascii_strings(const char* buffer, SIZE_T size, const std::string& drive_letter)
{
    try{
    for (SIZE_T i = 0; i < size - 3; ++i) {
        if (buffer[i] == drive_letter[0] && buffer[i + 1] == ':' && buffer[i + 2] == '\\')
        {
            SIZE_T str_start = i;
            SIZE_T str_end = i;

            while (str_end < size && isprint(buffer[str_end]))
            {
                ++str_end;
            }

            std::string found_string(&buffer[str_start], str_end - str_start);

            if (has_valid_extension(std::wstring(found_string.begin(), found_string.end()))
                && utils->file_exists(std::wstring(found_string.begin(), found_string.end())))
            {
                std::stringstream message_stream;
                message_stream << xorstr_ ( "FAT Drive File Replaced/Renamed: ") << found_string;
                std::string message = message_stream.str ( );

                LOG ( WARNING, xorstr_( "N/A" ) ) << message;
            }
            i = str_end;
        }
    }
    }
    catch (...) {}
}

void c_fat32_modification2::scan_memory_for_drive(DWORD process_id, const std::wstring& drive_letter)
{
    try{
    HANDLE process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, process_id);
    if (!process_handle) return;

    LPCVOID address = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (VirtualQueryEx(process_handle, address, &mbi, sizeof(mbi)) == sizeof(mbi))
    {
        if (mbi.State == MEM_COMMIT && is_private_memory_region(mbi)) {
            std::vector<char> buffer(mbi.RegionSize);
            SIZE_T bytes_read;

            if (ReadProcessMemory(process_handle, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytes_read)) {
                search_for_ascii_strings(buffer.data(), bytes_read, ascii_wstring_to_string(drive_letter));
                search_for_unicode_strings(reinterpret_cast<wchar_t*>(buffer.data()), bytes_read, drive_letter);
            }
            else {
                DWORD error_code = GetLastError();
                if (error_code != ERROR_PARTIAL_COPY) { }
            }
        }

        address = (LPCVOID)((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    CloseHandle(process_handle);
    }
    catch (...) {}
}

void c_fat32_modification2::start_fat32_2_modification_check()
{
    try{
    if (!enable_debug_privilege()) { }

    std::string process_name = xorstr_ ( "SearchIndexer.exe");
    DWORD process_id = get_process_id_by_name(process_name);
    std::vector<std::wstring> fat32_drives = get_fat32_drives();
    for (const auto& drive_letter : fat32_drives) 
    {
        std::stringstream message_stream;
        message_stream << xorstr_ ( "Found FAT Drive: ") << utils->convert_wstring_to_string ( drive_letter.c_str ( ) );
        std::string message = message_stream.str ( );

        LOG ( WARNING, xorstr_ ( "N/A" ) ) << message;

        scan_memory_for_drive(process_id, drive_letter);
    }
    }
    catch (...) {}
}
