#pragma once

#include "../../pch.h"

class UsbBypassRegistry
{
public:
    static void start_usb_bypass_check();

private:
    static bool KeyExists(HKEY hRoot, const wchar_t* subKey);
};

inline auto c_usbbypass = std::make_unique<UsbBypassRegistry>();
