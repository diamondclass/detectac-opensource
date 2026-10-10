#pragma once

#include "../../pch.h"

class c_game_instance_detection
{
public:
    static bool is_approved_client(const std::wstring& window_title);
    static BOOL CALLBACK enum_windows_callback(HWND hwnd, LPARAM l_param);

    static void start_game_instance_detection();
};

inline auto c_game_instance = std::make_unique<c_game_instance_detection>();
