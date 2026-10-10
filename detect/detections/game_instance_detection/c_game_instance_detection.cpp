#include "c_game_instance_detection.h"

bool c_game_instance_detection::is_approved_client(const std::wstring& window_title)
{
    try{
    std::vector<std::wstring> approved_clients
    {
        xorstr_ ( L"Lunar"),
        xorstr_ ( L"Badlion"),
        xorstr_ ( L"Feather"),
        xorstr_ ( L"PvPLounge"),
        xorstr_ ( L"Minecraft*")
    };

    for (const auto& client : approved_clients)
    {
        if (window_title.find(client) != std::wstring::npos)
        {
            return true;
        }
    }

    return false;
    }
    catch (...) { return false; }
}

BOOL CALLBACK c_game_instance_detection::enum_windows_callback(HWND hwnd, LPARAM l_param)
{
    try{
    wchar_t class_name[256], window_title[256];
    bool* game_window_found = reinterpret_cast<bool*>(l_param);

    GetClassNameW(hwnd, class_name, sizeof(class_name) / sizeof(wchar_t));
    GetWindowTextW(hwnd, window_title, sizeof(window_title) / sizeof(wchar_t));

    if (std::wstring(class_name) == xorstr_ ( L"LWJGL"))
    {
        *game_window_found = true;

        if (!is_approved_client(std::wstring(window_title)))
        {
            LOG(WARNING, xorstr_ ( "N/A") ) << xorstr_ ( "Unknown Minecraft Game Instance. (Possibly Not A Known PvP Client)");
        }
    }

    return TRUE;
    }
    catch (...) { return FALSE; }
}

void c_game_instance_detection::start_game_instance_detection()
{
    try{
    bool game_window_found = false;

    EnumWindows(enum_windows_callback, reinterpret_cast<LPARAM>(&game_window_found));
    }
    catch (...) {}
}