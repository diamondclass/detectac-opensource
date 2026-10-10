#include "UI/webview_ui.h"
#include "resource.h"
#include "utils/protection/protection.h"
#include "utils/protection/relaunch.h"
#include <windows.h>
#include <tchar.h>
#include <thread>
#include <atomic>
#include <stdlib.h>
#include <string>
#include <exception>
#include <new>

static void crt_invalid_parameter_handler(
    const wchar_t*, const wchar_t*, const wchar_t*,
    unsigned int, uintptr_t) {
}

static void detect_terminate_handler() noexcept {
    ::TerminateProcess(::GetCurrentProcess(), 0);
}

static void detect_new_handler() {
    ::TerminateProcess(::GetCurrentProcess(), 0);
}

#define IDT_TIMER 1
#define TIMER_INTERVAL 5000

[[nodiscard]]
auto
show_notification
(
    const HWND hwnd,
    const TCHAR* const title,
    const TCHAR* const message
) noexcept -> void
{
    NOTIFYICONDATA nid;
    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = 0;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_USER + 1;
    nid.hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(IDI_ICON1));
    _tcscpy_s(nid.szTip, _countof(nid.szTip), title);

    Shell_NotifyIcon(NIM_ADD, &nid);

    nid.uFlags |= NIF_INFO;
    _tcscpy_s(nid.szInfo, _countof(nid.szInfo), message);
    _tcscpy_s(nid.szInfoTitle, _countof(nid.szInfoTitle), title);
    nid.dwInfoFlags = NIIF_INFO;
    nid.uTimeout = 10000;

    Shell_NotifyIcon(NIM_MODIFY, &nid);
    SetTimer(hwnd, IDT_TIMER, TIMER_INTERVAL, nullptr);
}

LRESULT
CALLBACK
wnd_proc
(
    const HWND hwnd,
    const UINT msg,
    const WPARAM wParam,
    const LPARAM lParam
) noexcept
{
    static NOTIFYICONDATA nid;
    switch (msg) {
    case WM_CREATE:
        break;
    case WM_TIMER:
        KillTimer(hwnd, IDT_TIMER);
        Shell_NotifyIcon(NIM_DELETE, &nid);
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, msg, wParam, lParam);
    }
    return 0;
}

[[noreturn]]
auto
listen_for_detection_complete
(
    const HWND hwnd
) noexcept -> void*
{
    while (true)
    {
        if (detect.completed)
        {
            show_notification(hwnd, xorstr_("Scan Complete!"), xorstr_("Detect has finished scanning. You may close detect now."));
            detect.completed = false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

int
WINAPI
wWinMain
(
    const HINSTANCE hInstance,
    const HINSTANCE hPrevInstance,
    const LPWSTR lpCmdLine,
    const int nShowCmd
)
{
    _set_invalid_parameter_handler(crt_invalid_parameter_handler);

    std::set_terminate(detect_terminate_handler);
    std::set_new_handler(detect_new_handler);

    protection::Initialize();

    if (!IsUserAnAdmin()) [[likely]]
    {
        MessageBox(NULL, xorstr_("Detect must be ran as administrator."), xorstr_("Error"), MB_ICONERROR | MB_OK);
        exit(0);
    }

    static const std::wstring s_wndClass = xorstr_(L"sys_") + protection::relaunch::MakeRandomAlnum(8, 12);
    static const std::wstring s_wndTitle = protection::relaunch::MakeRandomAlnum(10, 14);

    auto wide_to_narrow = [](const std::wstring& w) {
        std::string s; s.reserve(w.size());
        for (wchar_t c : w) s.push_back(static_cast<char>(c));
        return s;
    };
    detect.window_name  = wide_to_narrow(s_wndTitle);
    detect.window_class = wide_to_narrow(s_wndClass);

    utils->check_server_status();

    WNDCLASSW wndClass = { 0 };
    wndClass.lpfnWndProc = wnd_proc;
    wndClass.hInstance = hInstance;
    wndClass.lpszClassName = s_wndClass.c_str();

    if (!RegisterClassW(&wndClass)) [[unlikely]] assert(false && xorstr_("Class not registered #!main.cpp:98"));
    const HWND hwnd = CreateWindowW(s_wndClass.c_str(), s_wndTitle.c_str(), 0, 0, 0, 0, 0, 0, nullptr, hInstance, nullptr);
    if (hwnd == nullptr) [[unlikely]] assert(false && xorstr_("HWND should not be NULL #!main.cpp:108"));

    std::thread notification_thread(listen_for_detection_complete, hwnd);
    notification_thread.detach();  

    webview_ui::Render();

    return 0;
}