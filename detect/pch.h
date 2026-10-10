#pragma once

#ifndef PCH_H
#define PCH_H

#include <Windows.h>
#include <unordered_map>
#include <tchar.h>
#include <string>
#include <iostream>
#include <shlobj.h>
#include <d3d11.h>
#include <vector>
#include <set>
#include <regex>
#include <thread>
#include <winevt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <unordered_set>
#include <sstream>
#include <locale>
#include <codecvt>
#include <filesystem>
#include <cstdio>
#include <array>
#include <memory>
#include <stdexcept>
#include <taskschd.h>
#include <comdef.h>
#include <iomanip>
#include <sddl.h>
#include <map>
#include <chrono>
#include <ctime>
#include <cwctype>
#include <cctype>
#include <mutex>
#include <fstream>
#include <condition_variable>
#include <functional>
#include <exception>
#include <queue>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cmath>
#include <future>
#include <cstdlib>
#include <random>
#include <wincrypt.h>

#include <Lmcons.h>
#include <NTSecAPI.h>
#include <wintrust.h>
#include <softpub.h>
#include <Shlwapi.h>
#include <ntstatus.h>
#include <mscat.h>
#include <wtsapi32.h>
#pragma push_macro("GetObject")
#undef GetObject
#include <Wbemidl.h>
#pragma pop_macro("GetObject")
#include <comutil.h>
#include <netfw.h>
#include <evntcons.h>
#include <winhttp.h>
#include <lowlevelmonitorconfigurationapi.h>
#include <physicalmonitorenumerationapi.h>
#include <highlevelmonitorconfigurationapi.h>
#include <winioctl.h>
#include <dbghelp.h>
#include <initguid.h>
#include <devpropdef.h>
#include <devpkey.h>
#include <devguid.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <fcntl.h>
#include <io.h>
#include <esent.h>

#include <fmt/core.h>
#include <fmt/format.h>
#include <yara.h>

#include "vars.h"
#include "utils/logger/logger.h"
#include "utils/detection/utils.h"
#include "utils/custom_strings.h"
#include "utils/crypt/xorstr.h"
#include "UI/webview_ui.h"
#include "detections/detection_root.h"

inline std::string ascii_wstring_to_string(const std::wstring& w) {
    std::string out;
    out.reserve(w.size());
    for (wchar_t wc : w) out.push_back(static_cast<char>(wc));
    return out;
}

#endif
