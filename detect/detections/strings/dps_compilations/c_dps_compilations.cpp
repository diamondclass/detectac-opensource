#include "c_dps_compilations.h"

bool compilationscan::IsPrintableAscii(unsigned char c) noexcept {
    try {
        return c >= 0x20 && c < 0x7F;
    }
    catch (...) {
        return false;
    }
}

bool compilationscan::IsPrintableWide(wchar_t c) noexcept {
    try {
        if (c == 0) return false;
        if (c < 0x20) return false;
        if (c == 0x7F) return false;
        return true;
    }
    catch (...) {
        return false;
    }
}

bool compilationscan::IsReadableProtection(unsigned long protect) noexcept {
    try {
        if (protect & PAGE_GUARD) return false;
        unsigned long p = protect & 0xFFu;
        return p == PAGE_READONLY || p == PAGE_READWRITE ||
            p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE ||
            p == PAGE_WRITECOPY || p == PAGE_EXECUTE_WRITECOPY;
    }
    catch (...) {
        return false;
    }
}

std::string compilationscan::WideToUtf8(const std::wstring& w) noexcept {
    try {
        if (w.empty()) return {};
        int needed = WideCharToMultiByte(CP_UTF8, 0, w.c_str(),
            static_cast<int>(w.size()), nullptr, 0,
            nullptr, nullptr);
        if (needed <= 0) return {};
        std::string out(static_cast<std::size_t>(needed), '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()),
            out.data(), needed, nullptr, nullptr);
        return out;
    }
    catch (...) {
        return {};
    }
}

std::wstring compilationscan::Utf8ToWide(const std::string& s) noexcept {
    try {
        if (s.empty()) return {};
        int needed = MultiByteToWideChar(CP_UTF8, 0, s.c_str(),
            static_cast<int>(s.size()), nullptr, 0);
        if (needed <= 0) return {};
        std::wstring out(static_cast<std::size_t>(needed), L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
            out.data(), needed);
        return out;
    }
    catch (...) {
        return {};
    }
}

void compilationscan::ExtractAscii(const unsigned char* data, std::size_t n,
    std::set<std::string>& out) noexcept {
    try {
        if (n < 2) return;
        std::size_t i = 0;
        while (i + 1 < n) {
            if (data[i] == '!' && data[i + 1] == '!') {
                std::size_t end = i + 2;
                while (end < n && IsPrintableAscii(data[end])) ++end;
                if (end - i >= 3) {
                    out.emplace(reinterpret_cast<const char*>(&data[i]), end - i);
                }
                i = (end < n) ? end + 1 : end;
            }
            else {
                ++i;
            }
        }
    }
    catch (...) {
    }
}

void compilationscan::ExtractWide(const unsigned char* data, std::size_t n,
    std::set<std::wstring>& out) noexcept {
    try {
        if (n < 4) return;
        std::size_t i = 0;
        while (i + 3 < n) {
            if (data[i] == '!' && data[i + 1] == 0 &&
                data[i + 2] == '!' && data[i + 3] == 0) {
                std::wstring s;
                s.push_back(L'!');
                s.push_back(L'!');
                std::size_t end = i + 4;
                while (end + 1 < n) {
                    wchar_t wc = static_cast<wchar_t>(
                        static_cast<unsigned>(data[end]) |
                        (static_cast<unsigned>(data[end + 1]) << 8));
                    if (!IsPrintableWide(wc)) break;
                    s.push_back(wc);
                    end += 2;
                }
                if (s.size() >= 3) out.insert(std::move(s));
                i = end + 2;
            }
            else {
                ++i;
            }
        }
    }
    catch (...) {
    }
}

bool compilationscan::ParseRecord(const std::wstring& s, std::wstring& outName,
    std::wstring& outDate) noexcept {
    try {
        const std::size_t kDate = 19;
        if (s.size() < 2 + 1 + kDate) return false;
        if (s[0] != L'!' || s[1] != L'!') return false;

        std::size_t i = 2;
        const std::size_t nameStart = i;
        while (i < s.size() && s[i] != L'!') ++i;
        if (i >= s.size() || i == nameStart) return false;

        std::wstring name(s.data() + nameStart, i - nameStart);
        ++i;

        if (i + kDate > s.size()) return false;
        const wchar_t* d = s.data() + i;
        auto digit = [](wchar_t c) { return c >= L'0' && c <= L'9'; };
        if (!(digit(d[0]) && digit(d[1]) && digit(d[2]) && digit(d[3]) &&
            d[4] == L'/' &&
            digit(d[5]) && digit(d[6]) &&
            d[7] == L'/' &&
            digit(d[8]) && digit(d[9]) &&
            d[10] == L':' &&
            digit(d[11]) && digit(d[12]) &&
            d[13] == L':' &&
            digit(d[14]) && digit(d[15]) &&
            d[16] == L':' &&
            digit(d[17]) && digit(d[18]))) {
            return false;
        }
        if (i + kDate >= s.size() || s[i + kDate] != L'!') return false;

        outName = std::move(name);
        outDate.assign(d, kDate);
        return true;
    }
    catch (...) {
        return false;
    }
}

bool compilationscan::EnableDebugPrivilege() noexcept {
    try {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
            return false;
        }
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        if (!LookupPrivilegeValueW(nullptr, xorstr_(L"SeDebugPrivilege"),
            &tp.Privileges[0].Luid)) {
            CloseHandle(token);
            return false;
        }
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr,
            nullptr);
        DWORD err = GetLastError();
        CloseHandle(token);
        return ok && err != ERROR_NOT_ALL_ASSIGNED;
    }
    catch (...) {
        return false;
    }
}

unsigned long compilationscan::FindDpsPid() noexcept {
    try {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!scm) return 0;
        SC_HANDLE svc = OpenServiceW(scm, xorstr_(L"DPS"), SERVICE_QUERY_STATUS);
        if (!svc) {
            CloseServiceHandle(scm);
            return 0;
        }
        SERVICE_STATUS_PROCESS status{};
        DWORD needed = 0;
        BOOL ok = QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status), &needed);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        if (!ok) return 0;
        if (status.dwCurrentState != SERVICE_RUNNING) return 0;
        return status.dwProcessId;
    }
    catch (...) {
        return 0;
    }
}

void compilationscan::ScanRegion(void* process, unsigned char* base,
    std::size_t size,
    std::set<std::string>& asciiOut,
    std::set<std::wstring>& wideOut) noexcept {
    try {
        const std::size_t kChunk = 8u * 1024u * 1024u;
        const std::size_t kOverlap = 4096u;

        std::vector<unsigned char> buf;
        try {
            buf.resize(size < kChunk ? size : kChunk);
        }
        catch (...) {
            return;
        }

        std::size_t offset = 0;
        while (offset < size) {
            std::size_t toRead =
                (size - offset < buf.size()) ? (size - offset) : buf.size();
            SIZE_T read = 0;
            BOOL ok = ReadProcessMemory(static_cast<HANDLE>(process),
                base + offset, buf.data(), toRead,
                &read);
            if (!ok && read == 0) return;
            if (read == 0) return;

            ExtractAscii(buf.data(), read, asciiOut);
            ExtractWide(buf.data(), read, wideOut);

            if (read < toRead) return;
            if (offset + read >= size) return;

            std::size_t step = (read > kOverlap) ? (read - kOverlap) : read;
            offset += step;
        }
    }
    catch (...) {
    }
}

void compilationscan::CollectStrings(void* process,
    std::set<std::string>& asciiOut,
    std::set<std::wstring>& wideOut) noexcept {
    try {
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        auto addr =
            reinterpret_cast<unsigned char*>(si.lpMinimumApplicationAddress);
        auto maxAddr =
            reinterpret_cast<unsigned char*>(si.lpMaximumApplicationAddress);

        MEMORY_BASIC_INFORMATION mbi{};
        while (addr < maxAddr &&
            VirtualQueryEx(static_cast<HANDLE>(process), addr, &mbi,
                sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && IsReadableProtection(mbi.Protect)) {
                ScanRegion(process,
                    reinterpret_cast<unsigned char*>(mbi.BaseAddress),
                    mbi.RegionSize, asciiOut, wideOut);
            }
            auto next =
                reinterpret_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    }
    catch (...) {
    }
}

void compilationscan::Report(const std::set<std::string>& ascii,
    const std::set<std::wstring>& wide) noexcept {
    try {
        std::vector<std::pair<std::wstring, std::wstring>> known;
        try {
            known = {

#ifdef DETECT_MINECRAFT
                {xorstr_(L"2024/08/26:18:47:34"), xorstr_(L"Vape Lite Signed Cheat")},
                {xorstr_(L"2102/01/27:22:25:01"), xorstr_(L"Sapphire Lite Clicker")},
                {xorstr_(L"2063/05/14:03:24:37"), xorstr_(L"ZenClicker")},
                {xorstr_(L"2020/09/28:01:13:10"), xorstr_(L"Itami 2.0")},
                {xorstr_(L"2019/04/15:12:11:37"), xorstr_(L"Ahk Clicker")},
                {xorstr_(L"2019/04/04:21:13:43"), xorstr_(L"Ahkclicker")},
                {xorstr_(L"2023/05/01:18:07:52"), xorstr_(L"Akira Client")},
                {xorstr_(L"2023/05/19:19:20:07"), xorstr_(L"Akira Client")},
                {xorstr_(L"2022/12/20:18:11:46"), xorstr_(L"Akira Client")},
                {xorstr_(L"2022/07/15:05:18:49"), xorstr_(L"Akira Client")},
                {xorstr_(L"2021/07/29:07:36:56"), xorstr_(L"Akira Client")},
                {xorstr_(L"2020/05/01:21:31:01"), xorstr_(L"B1Scoito Clicker")},
                {xorstr_(L"2022/03/27:18:47:58"), xorstr_(L"Biscoito Client")},
                {xorstr_(L"2091/08/01:01:16:09"), xorstr_(L"Cc Clicker")},
                {xorstr_(L"2020/09/30:21:11:58"), xorstr_(L"Crypt Client")},
                {xorstr_(L"2020/06/23:21:14:50"), xorstr_(L"Crypt Client")},
                {xorstr_(L"2058/08/14:19:28:51"), xorstr_(L"Crypt Cracked")},
                {xorstr_(L"2020/06/23:21:14:50"), xorstr_(L"Crypt Cracked")},
                {xorstr_(L"2020/05/22:12:10:58"), xorstr_(L"Cucklord Client")},
                {xorstr_(L"2020/05/22:12:10:58"), xorstr_(L"Cucklord Client")},
                {xorstr_(L"2018/12/09:16:58:13"), xorstr_(L"Cucklord Cracked")},
                {xorstr_(L"2074/06/28:13:58:41"), xorstr_(L"Cucklord Ghost")},
                {xorstr_(L"2020/05/29:06:27:30"), xorstr_(L"Cucklordghost Client")},
                {xorstr_(L"2018/12/09:17:58:13"), xorstr_(L"Cucklord Multitool")},
                {xorstr_(L"2069/11/13:21:49:24"), xorstr_(L"Cucklord Tool")},
                {xorstr_(L"2019/04/18:16:14:30"), xorstr_(L"Cucklord Tool")},
                {xorstr_(L"2042/05/29:09:33:43"), xorstr_(L"Cucklord Tool")},
                {xorstr_(L"2070/03/23:07:14:09"), xorstr_(L"Cucklord Tool")},
                {xorstr_(L"2093/10/10:16:14:32"), xorstr_(L"Cucklord Tool")},
                {xorstr_(L"2090/07/25:10:24:22"), xorstr_(L"Cucklord Tool")},
                {xorstr_(L"2021/04/29:14:14:50"), xorstr_(L"Doge Clicker")},
                {xorstr_(L"2023/04/15:13:54:14"), xorstr_(L"Dope-Loader")},
                {xorstr_(L"2038/07/25:04:08:45"), xorstr_(L"Dope Clicker")},
                {xorstr_(L"2086/12/01:00:14:42"), xorstr_(L"Dope Clicker")},
                {xorstr_(L"2019/08/16:16:17:36"), xorstr_(L"Drip X Client")},
                {xorstr_(L"2085/12/15:04:10:36"), xorstr_(L"Dusk Clicker")},
                {xorstr_(L"2022/04/07:13:33:41"), xorstr_(L"Dusk Clicker")},
                {xorstr_(L"2022/04/19:21:08:17"), xorstr_(L"Dusk Clicker")},
                {xorstr_(L"2022/04/25:18:19:08"), xorstr_(L"Dusk Clicker")},
                {xorstr_(L"2022/04/07:16:33:41"), xorstr_(L"Duskv4 Clicker")},
                {xorstr_(L"2089/05/18:07:20:20"), xorstr_(L"Eclipse Client")},
                {xorstr_(L"2021/04/28:01:58:32"), xorstr_(L"Eclipse Client")},
                {xorstr_(L"2089/05/18:07:20:20"), xorstr_(L"Eclipse Ghost Client")},
                {xorstr_(L"2020/06/12:11:12:12"), xorstr_(L"Entropy Ghost Client")},
                {xorstr_(L"2020/05/21:23:13:01"), xorstr_(L"Entropy Ghost Client")},
                {xorstr_(L"2022/07/16:16:58:28"), xorstr_(L"Eternal Aimassist")},
                {xorstr_(L"2022/07/16:16:58:28"), xorstr_(L"Eternal Client")},
                {xorstr_(L"2069/08/19:02:03:19"), xorstr_(L"Ettelen1.0 Client")},
                {xorstr_(L"2019/11/30:13:51:20"), xorstr_(L"Ettelen2.0 Client")},
                {xorstr_(L"2019/11/08:00:11:02"), xorstr_(L"Ettelen Client (Cracked)")},
                {xorstr_(L"2019/11/08:00:11:02"), xorstr_(L"Ettelen Client")},
                {xorstr_(L"2019/11/19:16:48:04"), xorstr_(L"Ettelen Client")},
                {xorstr_(L"2019/11/19:16:48:04"), xorstr_(L"Ettelen Client / Fake Discord")},
                {xorstr_(L"2019/11/08:00:11:02"), xorstr_(L"Ettelen Cracked")},
                {xorstr_(L"2019/08/19:19:01:21"), xorstr_(L"Ettlen External Ghost Client")},
                {xorstr_(L"2020/02/16:03:20:05"), xorstr_(L"Euphoria Clicker")},
                {xorstr_(L"2022/06/20:13:39:41"), xorstr_(L"Exelon Clicker")},
                {xorstr_(L"2022/06/21:17:13:46"), xorstr_(L"Exelon Clicker")},
                {xorstr_(L"2022/06/20:13:49:57"), xorstr_(L"Exelon Clicker")},
                {xorstr_(L"2022/06/21:20:13:46"), xorstr_(L"Exelon Client")},
                {xorstr_(L"2017/12/23:20:26:05"), xorstr_(L"F4 Clicker")},
                {xorstr_(L"2019/07/11:12:20:09"), xorstr_(L"Glock Clicker (Cracked)")},
                {xorstr_(L"2080/04/23:03:35:31"), xorstr_(L"Glock Clicker")},
                {xorstr_(L"2020/10/17:21:52:02"), xorstr_(L"Glock Clicker")},
                {xorstr_(L"2065/10/18:18:56:08"), xorstr_(L"Glock Clicker")},
                {xorstr_(L"2019/07/11:09:20:09"), xorstr_(L"Glock Clicker")},
                {xorstr_(L"2019/07/11:02:11:52"), xorstr_(L"Glock Clicker")},
                {xorstr_(L"2050/10/29:11:13:57"), xorstr_(L"Glock Clicker")},
                {xorstr_(L"2080/04/23:06:35:31"), xorstr_(L"Glock V2")},
                {xorstr_(L"2020/05/26:03:27:09"), xorstr_(L"Icetea")},
                {xorstr_(L"2020/06/29:13:55:36"), xorstr_(L"Icetea")},
                {xorstr_(L"2020/05/26:03:27:09"), xorstr_(L"Icetea Clicker (Cracked)")},
                {xorstr_(L"2020/05/26:03:27:09"), xorstr_(L"Icetea Clicker")},
                {xorstr_(L"2020/02/24:15:18:47"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/09:00:55:22"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/22:07:12:31"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/21:15:49:58"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/02:18:48:40"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/06/23:09:45:05"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/24:06:33:40"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/22:05:58:43"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/13:06:37:22"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/22:18:37:28"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/02/23:19:38:33"), xorstr_(L"Icetea Client")},
                {xorstr_(L"2020/06/23:09:45:05"), xorstr_(L"Ice Tea Client")},
                {xorstr_(L"2018/09/03:01:51:27"), xorstr_(L"Iridium Clicker (Cracked)")},
                {xorstr_(L"2018/05/21:20:44:36"), xorstr_(L"Iridium Clicker")},
                {xorstr_(L"2018/09/03:01:51:27"), xorstr_(L"Iridium Clicker")},
                {xorstr_(L"2018/12/26:10:43:13"), xorstr_(L"Iridium Clicker")},
                {xorstr_(L"2018/09/03:01:51:27"), xorstr_(L"Iridium Clicker Cracked")},
                {xorstr_(L"2018/12/26:10:43:13"), xorstr_(L"Iridium Client")},
                {xorstr_(L"2020/06/29:13:55:36"), xorstr_(L"Iridium Cracked")},
                {xorstr_(L"2018/12/26:10:43:13"), xorstr_(L"Iridium Ghost (Cracked)")},
                {xorstr_(L"2007/03/16:20:40:44"), xorstr_(L"Iridium Ghost")},
                {xorstr_(L"2018/12/26:10:43:13"), xorstr_(L"Iridium Ghost")},
                {xorstr_(L"2060/01/01:05:17:38"), xorstr_(L"Ispo Clicker")},
                {xorstr_(L"2020/07/08:21:50:06"), xorstr_(L"Itami 1.2")},
                {xorstr_(L"2018/12/09:00:22:03"), xorstr_(L"Itami 1.4")},
                {xorstr_(L"2020/09/28:01:13:10"), xorstr_(L"Itami 2.0")},
                {xorstr_(L"2020/07/08:21:50:06"), xorstr_(L"Itami")},
                {xorstr_(L"2020/09/28:01:13:10"), xorstr_(L"Itami")},
                {xorstr_(L"2018/11/09:01:13:38"), xorstr_(L"Itami Client")},
                {xorstr_(L"2020/08/25:23:53:56"), xorstr_(L"Itami Client")},
                {xorstr_(L"2018/12/09:00:22:03"), xorstr_(L"Itami Client")},
                {xorstr_(L"2020/07/08:21:50:06"), xorstr_(L"Itami Client")},
                {xorstr_(L"2020/07/04:22:47:49"), xorstr_(L"Itami Client")},
                {xorstr_(L"2020/07/21:00:58:02"), xorstr_(L"Itami Client")},
                {xorstr_(L"2013/07/28:07:58:34"), xorstr_(L"Itami Ghost")},
                {xorstr_(L"2020/08/24:15:03:39"), xorstr_(L"Itami Client")},
                {xorstr_(L"2086/05/10:17:48:01"), xorstr_(L"Itori Clicker")},
                {xorstr_(L"2038/04/17:11:40:48"), xorstr_(L"Itori Client")},
                {xorstr_(L"2020/10/02:11:40:25"), xorstr_(L"Itori Client")},
                {xorstr_(L"2020/09/30:08:48:23"), xorstr_(L"Itori Client")},
                {xorstr_(L"2084/05/16:17:47:50"), xorstr_(L"Katana 2.1")},
                {xorstr_(L"2047/01/11:22:35:09"), xorstr_(L"Katana Anti-SS Tool")},
                {xorstr_(L"2020/05/29:06:27:30"), xorstr_(L"Koid")},
                {xorstr_(L"2020/07/22:23:28:56"), xorstr_(L"Koid")},
                {xorstr_(L"2019/10/31:21:32:32"), xorstr_(L"Koid")},
                {xorstr_(L"2019/10/07:19:27:30"), xorstr_(L"Koid")},
                {xorstr_(L"2019/11/06:23:38:27"), xorstr_(L"Koid")},
                {xorstr_(L"2019/11/24:18:42:59"), xorstr_(L"Koid")},
                {xorstr_(L"2020/03/17:20:34:34"), xorstr_(L"Koid")},
                {xorstr_(L"2019/10/04:17:19:54"), xorstr_(L"Koid")},
                {xorstr_(L"2019/11/01:17:59:39"), xorstr_(L"Koid")},
                {xorstr_(L"2019/11/08:23:33:58"), xorstr_(L"Koid")},
                {xorstr_(L"2020/05/29:06:27:30"), xorstr_(L"Koid")},
                {xorstr_(L"2019/11/22:20:21:37"), xorstr_(L"Koid")},
                {xorstr_(L"2019/10/07:19:27:30"), xorstr_(L"Koid")},
                {xorstr_(L"2019/10/06:20:22:46"), xorstr_(L"Koid")},
                {xorstr_(L"2020/07/22:23:28:56"), xorstr_(L"Koid Client")},
                {xorstr_(L"2020/05/29:06:27:30"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/10/04:17:19:54"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/10/06:20:22:46"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/10/31:21:32:32"), xorstr_(L"Koid Client")},
                {xorstr_(L"2020/07/22:23:28:56"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/11/24:18:42:59"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/03/14:17:46:40"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/11/01:17:59:39"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/11/06:23:38:27"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/10/31:21:32:32"), xorstr_(L"Koid Client")},
                {xorstr_(L"2020/05/29:06:27:30"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/11/08:23:33:58"), xorstr_(L"Koid Client")},
                {xorstr_(L"2020/03/17:20:34:34"), xorstr_(L"Koid Client")},
                {xorstr_(L"2020/05/29:06:27:30"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/11/08:23:33:58"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/11/22:20:21:37"), xorstr_(L"Koid Client")},
                {xorstr_(L"2019/10/07:19:27:30"), xorstr_(L"Koid Client")},
                {xorstr_(L"2020/08/05:00:22:09"), xorstr_(L"Koid Client")},
                {xorstr_(L"2095/02/04:10:23:25"), xorstr_(L"Lunar Client Clicker")},
                {xorstr_(L"2095/02/04:10:23:25"), xorstr_(L"Lunar Client Clicker")},
                {xorstr_(L"2022/04/20:12:53:29"), xorstr_(L"Luvsy Clicker")},
                {xorstr_(L"2093/11/26:07:00:11"), xorstr_(L"Mango 2.0")},
                {xorstr_(L"2068/09/21:04:41:53"), xorstr_(L"Mango Clicker 5.1.1")},
                {xorstr_(L"2048/01/24:10:47:39"), xorstr_(L"Mango Clicker 5.1.2")},
                {xorstr_(L"2058/11/12:01:33:08"), xorstr_(L"Mango Clicker 5.1.3")},
                {xorstr_(L"2053/02/09:07:36:27"), xorstr_(L"Mango Clicker 5.1.5")},
                {xorstr_(L"2045/08/19:08:23:18"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2058/11/12:01:33:08"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2068/09/09:20:23:59"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2093/11/26:07:00:11"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2093/11/26:07:00:11"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2048/02/18:23:55:10"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2048/01/24:10:47:39"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2053/02/09:07:36:27"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2068/09/21:04:41:53"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2068/09/21:04:41:53"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2048/02/18:23:55:10"), xorstr_(L"Mango Clicker")},
                {xorstr_(L"2068/09/21:04:41:53"), xorstr_(L"Mangoclicker")},
                {xorstr_(L"2077/12/06:06:28:12"), xorstr_(L"Mango Clicker Lite")},
                {xorstr_(L"2077/12/06:06:28:12"), xorstr_(L"Mangoclicker Lite")},
                {xorstr_(L"2068/09/09:20:23:59"), xorstr_(L"Mango Lite")},
                {xorstr_(L"2086/06/09:22:00:46"), xorstr_(L"Mango Lite Clicker")},
                {xorstr_(L"2086/06/10:01:00:46"), xorstr_(L"Mangolite Client")},
                {xorstr_(L"2086/06/10:01:00:46"), xorstr_(L"Mango Lite Ph Edition")},
                {xorstr_(L"2065/07/24:20:06:40"), xorstr_(L"Night Client")},
                {xorstr_(L"2017/02/13:00:44:51"), xorstr_(L"Notepad Clicker")},
                {xorstr_(L"2017/02/13:00:44:51"), xorstr_(L"Notepad Clicker")},
                {xorstr_(L"2022/10/16:04:19:09"), xorstr_(L"Ozix Anti-Ss Tool")},
                {xorstr_(L"2020/06/03:16:25:46"), xorstr_(L"Ozix Antisstools")},
                {xorstr_(L"2085/03/14:07:59:52"), xorstr_(L"Ozix Anydesk Ip Resolver")},
                {xorstr_(L"2020/06/25:23:07:52"), xorstr_(L"Ozix Clicker")},
                {xorstr_(L"2022/06/27:22:55:06"), xorstr_(L"Ozix Clicker Fake Ss-Tool")},
                {xorstr_(L"2021/08/25:16:51:14"), xorstr_(L"Ploow Client")},
                {xorstr_(L"2087/07/29:17:55:28"), xorstr_(L"Ploow Industries Cheat")},
                {xorstr_(L"2018/11/03:02:34:55"), xorstr_(L"Plow Clicker")},
                {xorstr_(L"2023/05/15:18:40:37"), xorstr_(L"Ppclicker")},
                {xorstr_(L"2049/01/19:09:42:40"), xorstr_(L"Spotify Clicker")},
                {xorstr_(L"2017/06/01:13:26:40"), xorstr_(L"Spotify Clicker")},
                {xorstr_(L"2021/10/17:12:24:08"), xorstr_(L"Tuke Client")},
                {xorstr_(L"2021/10/17:12:24:08"), xorstr_(L"Tuke Client")},
                {xorstr_(L"2019/05/19:20:48:16"), xorstr_(L"Vape Lite Cracked")},
                {xorstr_(L"2021/05/28:18:15:37"), xorstr_(L"Vape V4 Edited")},
                {xorstr_(L"2014/08/02:11:33:12"), xorstr_(L"Void Clicker 1.3")},
                {xorstr_(L"2014/08/02:06:33:12"), xorstr_(L"Void Clicker")},
                {xorstr_(L"2014/08/02:11:33:12"), xorstr_(L"Void Clicker V1.3")},
                {xorstr_(L"2020/10/18:00:52:02"), xorstr_(L"Vroom Clicker")},
                {xorstr_(L"2018/09/02:07:30:58"), xorstr_(L"Vroom Client")},
                {xorstr_(L"2021/01/31:06:05:27"), xorstr_(L"Wannacry Client")},
                {xorstr_(L"2013/04/01:07:08:22"), xorstr_(L"Xenon Clicker")},
                {xorstr_(L"2020/06/24:00:08:44"), xorstr_(L"Xenon Client")},
                {xorstr_(L"2071/02/11:08:23:33"), xorstr_(L"Zoom Clicker")},
                {xorstr_(L"2072/06/11:14:31:15"), xorstr_(L"Elite Loader Cheat")},
                {xorstr_(L"2024/11/16:13:10:41"), xorstr_(L"Xcap-setup Cheat")},
                {xorstr_(L"2024/11/16:13:05:38"), xorstr_(L"Xcap Cheat")},
                {xorstr_(L"2025/01/20:14:04:09"), xorstr_(L"Slinky Cheat")},
                {xorstr_(L"2024/12/25:06:25:16"), xorstr_(L"Drip X Cheat")},
                {xorstr_(L"2024/12/19:19:42:57"), xorstr_(L"Grim Cheat")},
                {xorstr_(L"2024/10/22:20:53:04"), xorstr_(L"Prestige Injector Cheat")},
                {xorstr_(L"2024/10/26:17:44:42"), xorstr_(L"Elite Injector Cheat")},
                {xorstr_(L"2024/12/19:19:42:57"), xorstr_(L"Grim Cheat")},
                {xorstr_(L"2025/02/08:20:23:50"), xorstr_(L"Grim Cheat")},
                {xorstr_(L"2021/06/06:19:01:40"), xorstr_(L"Hamzee Cheat Cheat")},
                {xorstr_(L"2085/02/26:02:59:48"), xorstr_(L"Elite Loader")},
                {xorstr_(L"2083/12/16:08:21:21"), xorstr_(L"Unknown Bypass")},
                {xorstr_(L"2089/11/07:12:18:56"), xorstr_(L"Unknown Injector")},
                {xorstr_(L"2025/06/08:20:51:26"), xorstr_(L"Grim Cheat")},
                {xorstr_(L"2065/01/07:12:40:17"), xorstr_(L"Sputtered Cheat")},
                {xorstr_(L"2065/10/11:07:55:34"), xorstr_(L"Nigerave Cheat")},
                {xorstr_(L"2050/03/23:07:03:36"), xorstr_(L"Basketball Cheat")},
                {xorstr_(L"2019/04/06:17:57:15"), xorstr_(L"Afaan Cheat")},
                {xorstr_(L"2024/01/14:13:44:57"), xorstr_(L"Toad Cheat")},
                {xorstr_(L"2090/10/26:03:46:23"), xorstr_(L"SrumDPS2 Cheat")},
                {xorstr_(L"2024/09/16:23:11:06"), xorstr_(L"FileDelete Cheat")},
                {xorstr_(L"2105/03/07:19:44:54"), xorstr_(L"Jfh Cheat")},
                {xorstr_(L"2025/07/24:03:03:37"), xorstr_(L"Entropy Client")},
                {xorstr_(L"2100/08/02:00:29:30"), xorstr_(L"Fake Journaltrace Cheat")},
                {xorstr_(L"2025/08/17:18:52:21"), xorstr_(L"Echo Free Cheat")},
                {xorstr_(L"2026/01/12:13:48:05"), xorstr_(L"Dopium External Cheat")},
                {xorstr_(L"2026/06/04:19:51:30"), xorstr_(L"Dopium Cheat")},
                {xorstr_(L"2026/06/04:19:51:30"), xorstr_(L"Dopium Cheat")},
                {xorstr_(L"2026/07/12:11:18:50"), xorstr_(L"Snow Bypass")},
                {xorstr_(L"2026/03/28:06:50:31"), xorstr_(L"7th Clicker Cheat")},
                {xorstr_(L"2026/01/20:23:14:28"), xorstr_(L"Engourance Cheat")},
                {xorstr_(L"2026/01/20:22:29:07"), xorstr_(L"Engourance Cheat")},
                {xorstr_(L"2083/08/27:21:42:13"), xorstr_(L"Engourance Cheat")},
                {xorstr_(L"2074/07/10:13:12:32"), xorstr_(L"Dopium Bypass")},
                {xorstr_(L"2026/05/30:07:06:21"), xorstr_(L"Memory.win Loader")},
                {xorstr_(L"2026/06/01:01:22:25"), xorstr_(L"Cold Client")},
                {xorstr_(L"2026/07/06:00:42:07"), xorstr_(L"Cold Client")},
                {xorstr_(L"2026/08/02:23:43:20"), xorstr_(L"Cold Client")},
                {xorstr_(L"2025/06/05:16:44:28"), xorstr_(L"Karma Client")},
                {xorstr_(L"2017/10/15:11:23:19"), xorstr_(L"Dream Client")},
                {xorstr_(L"2026/08/28:03:03:59"), xorstr_(L"Drip Lite Client")},
                {xorstr_(L"2026/05/26:11:03:24"), xorstr_(L"Prestige Client")},
                {xorstr_(L"2025/01/01:19:57:36"), xorstr_(L"MHUB Loader")},
                {xorstr_(L"2023/12/02:05:24:47"), xorstr_(L"MHUB Loader")},
                {xorstr_(L"2025/12/31:21:40:13"), xorstr_(L"MHUB Loader")},
                {xorstr_(L"2025/09/01:13:23:04"), xorstr_(L"MHUB Loader")},
                {xorstr_(L"2024/03/16:09:30:49"), xorstr_(L"MHUB Loader")},
                {xorstr_(L"2026/04/28:22:50:49"), xorstr_(L"MHUB Loader")},
                {xorstr_(L"2026/06/12:21:05:12"), xorstr_(L"Grim Client")},
                {xorstr_(L"2026/08/17:14:06:05"), xorstr_(L"Prestige Launcher")},

#elif DETECT_FIVEM
                {xorstr_(L"2026/07/27:19:24:25"), xorstr_(L"MVP Slotted Cheat")},
                {xorstr_(L"2026/08/23:06:54:46"), xorstr_(L"Sacred Cheat")},
                {xorstr_(L"2026/05/29:12:45:52"), xorstr_(L"Bypass.fun")},
                {xorstr_(L"2026/05/21:22:50:40"), xorstr_(L"Bypass.fun Bypass")},
                {xorstr_(L"2026/05/19:23:56:53"), xorstr_(L"Bypass.fun Loader")},
                {xorstr_(L"2026/01/11:17:37:18"), xorstr_(L"Severence Bypass")},
                {xorstr_(L"2026/05/23:00:22:28"), xorstr_(L"Phase Uno Cheat")},
                {xorstr_(L"2025/11/19:21:57:56"), xorstr_(L"MWFree+ Cheat")},
                {xorstr_(L"2025/05/31:07:43:39"), xorstr_(L"PureMode Bypass")},
                {xorstr_(L"2024/06/05:14:15:28"), xorstr_(L"Puremode Bypass")},
                {xorstr_(L"1990/08/01:00:05:13"), xorstr_(L"Club44xJefe Bypass")},
                {xorstr_(L"2026/03/21:08:18:16"), xorstr_(L"Genesis Bypass")},
                {xorstr_(L"2026/02/19:23:09:24"), xorstr_(L"Genesis Bypass")},
                {xorstr_(L"2026/02/15:19:45:28"), xorstr_(L"Genesis Bypass")},
                {xorstr_(L"2026/03/21:21:37:36"), xorstr_(L"Stainless Bypass Cheat")},
                {xorstr_(L"2025/08/17:18:52:21"), xorstr_(L"Echo Free Cheat")},
                {xorstr_(L"2021/05/05:23:17:59"), xorstr_(L"Eulen Cheat")},
                {xorstr_(L"2024/10/04:19:25:15"), xorstr_(L"TZX Client")},
                {xorstr_(L"2023/12/13:20:14:01"), xorstr_(L"Gosth Client")},
                {xorstr_(L"2024/09/17:22:59:41"), xorstr_(L"Skript Client")},
                {xorstr_(L"2098/02/08:06:47:01"), xorstr_(L"Italo Bypass")},
                {xorstr_(L"2069/10/05:12:07:19"), xorstr_(L"Slotted Bypass")},
                {xorstr_(L"2024/07/08:18:17:51"), xorstr_(L"Cobra Loader")},
                {xorstr_(L"2023/11/22:11:16:31"), xorstr_(L"External Cheat")},
                {xorstr_(L"2086/12/14:10:49:36"), xorstr_(L"TD Loader Cheat")},
                {xorstr_(L"2024/08/08:10:35:27"), xorstr_(L"TZ Loader Cheat")},
                {xorstr_(L"2024/09/05:00:21:21"), xorstr_(L"ViperX Cheat")},
                {xorstr_(L"2024/06/21:00:15:36"), xorstr_(L"Void Cheat")},
                {xorstr_(L"2024/09/17:19:42:21"), xorstr_(L"Anti-Echo Cheat")},
                {xorstr_(L"2072/11/16:05:34:41"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2024/11/14:20:17:08"), xorstr_(L"Eulen Loader")},
                {xorstr_(L"2024/02/29:02:10:02"), xorstr_(L"Eulen Loader")},
                {xorstr_(L"2024/11/22:16:13:03"), xorstr_(L"Eulen Loader")},
                {xorstr_(L"2024/07/28:15:46:52"), xorstr_(L"Moster Bypass")},
                {xorstr_(L"2024/08/22:22:08:31"), xorstr_(L"NexHub Woofer")},
                {xorstr_(L"2024/09/09:15:41:17"), xorstr_(L"Stopped Bypass")},
                {xorstr_(L"2024/08/04:23:00:03"), xorstr_(L"Onyx Cheat")},
                {xorstr_(L"2083/11/16:07:08:02"), xorstr_(L"Opium Bypass")},
                {xorstr_(L"2024/06/21:00:15:36"), xorstr_(L"Caducado Cheat")},
                {xorstr_(L"2024/08/20:18:38:13"), xorstr_(L"PI Solution Spoofer")},
                {xorstr_(L"2090/10/05:02:19:08"), xorstr_(L"RavenX Cleaner")},
                {xorstr_(L"2024/09/19:14:24:18"), xorstr_(L"RedEngine Cheat")},
                {xorstr_(L"2024/09/19:16:28:53"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2024/10/27:07:29:27"), xorstr_(L"Spotless Private")},
                {xorstr_(L"2024/09/09:15:41:17"), xorstr_(L"Stopped Bypass")},
                {xorstr_(L"2024/07/08:23:42:07"), xorstr_(L"TD Premium Cracked")},
                {xorstr_(L"2086/12/14:10:49:36"), xorstr_(L"TD Loader")},
                {xorstr_(L"2024/07/08:23:42:07"), xorstr_(L"TD Premium")},
                {xorstr_(L"2024/07/03:20:29:52"), xorstr_(L"Unload Lite")},
                {xorstr_(L"2024/10/05:03:34:22"), xorstr_(L"Unload Cheat")},
                {xorstr_(L"2021/11/29:17:36:29"), xorstr_(L"USB Oblivion")},
                {xorstr_(L"2024/08/29:00:12:49"), xorstr_(L"Uzui Spoofer")},
                {xorstr_(L"2023/10/30:15:45:40"), xorstr_(L"Dxil Cheat")},
                {xorstr_(L"2024/10/25:16:30:11"), xorstr_(L"Veax Cheat")},
                {xorstr_(L"2024/09/05:00:21:21"), xorstr_(L"Vipex Cheat")},
                {xorstr_(L"2046/02/10:10:36:19"), xorstr_(L"Vlexzy Multitool Cheat")},
                {xorstr_(L"2024/07/24:01:25:59"), xorstr_(L"WriteMini Dump Bypass")},
                {xorstr_(L"2023/03/11:14:46:52"), xorstr_(L"Xine Team Cheat")},
                {xorstr_(L"2023/10/30:15:45:40"), xorstr_(L"Genesis")},
                {xorstr_(L"2023/12/28:18:18:43"), xorstr_(L"XRC")},
                {xorstr_(L"2023/08/17:17:20:03"), xorstr_(L"Mind Selling Bypass")},
                {xorstr_(L"2091/08/09:07:40:44"), xorstr_(L"Mind Selling Bypass")},
                {xorstr_(L"2041/11/25:10:24:57"), xorstr_(L"Stoppados")},
                {xorstr_(L"2022/04/13:17:33:54"), xorstr_(L"Asscrack")},
                {xorstr_(L"2067/02/18:01:33:05"), xorstr_(L"AG")},
                {xorstr_(L"2023/09/20:01:00:20"), xorstr_(L"Stars")},
                {xorstr_(L"2023/06/12:20:28:54"), xorstr_(L"Sicario Cleaner")},
                {xorstr_(L"2044/07/26:05:09:44"), xorstr_(L"Mylon")},
                {xorstr_(L"2041/05/27:12:23:56"), xorstr_(L"Deguard")},
                {xorstr_(L"2023/10/20:06:45:01"), xorstr_(L"Origin Bypass")},
                {xorstr_(L"2023/10/13:03:54:38"), xorstr_(L"Skript")},
                {xorstr_(L"2021/05/23:16:39:55"), xorstr_(L"Monster")},
                {xorstr_(L"2022/05/17:12:54:04"), xorstr_(L"Space YX")},
                {xorstr_(L"2023/06/19:18:06:05"), xorstr_(L"Eulen")},
                {xorstr_(L"2023/06/10:15:51:52"), xorstr_(L"CFX Mafia")},
                {xorstr_(L"2021/11/29:17:36:29"), xorstr_(L"USB Oblivion")},
                {xorstr_(L"2024/03/16:13:29:49"), xorstr_(L"88cheats")},
                {xorstr_(L"2024/04/15:21:03:39"), xorstr_(L"HX loader")},
                {xorstr_(L"2022/12/28:14:39:24"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/12/16:15:44:33"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/10/23:04:52:02"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/03/28:15:40:17"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/08/15:21:03:45"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/11/04:11:23:02"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/09/06:18:17:42"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/10/01:16:37:21"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/10/17:16:20:38"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/12/17:00:11:46"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2022/09/30:10:45:22"), xorstr_(L"Monster Menu")},
                {xorstr_(L"2100/01/17:19:52:37"), xorstr_(L"Purity")},
                {xorstr_(L"2021/11/13:21:10:48"), xorstr_(L"Bleach Bit")},
                {xorstr_(L"2022/02/19:22:03:15"), xorstr_(L"Veracrypt Bypass")},
                {xorstr_(L"2022/08/07:12:40:54"), xorstr_(L"ProjectYX Free")},
                {xorstr_(L"2022/10/23:11:46:08"), xorstr_(L"ProjectYX ScriptHook")},
                {xorstr_(L"2022/10/14:21:34:30"), xorstr_(L"Astaroth Bypass")},
                {xorstr_(L"2022/01/04:02:23:48"), xorstr_(L"Degeo Cheat")},
                {xorstr_(L"2022/11/11:14:32:22"), xorstr_(L"Degeo Cheat")},
                {xorstr_(L"2022/11/11:14:35:47"), xorstr_(L"Degeo Cheat")},
                {xorstr_(L"2022/11/18:15:43:03"), xorstr_(L"Degeo Cheat")},
                {xorstr_(L"2018/02/01:19:43:01"), xorstr_(L"Bullet Damage")},
                {xorstr_(L"2022/10/02:17:15:03"), xorstr_(L"Katana")},
                {xorstr_(L"2022/11/12:05:40:31"), xorstr_(L"Degeo Cheat Cracked")},
                {xorstr_(L"2022/09/01:17:11:11"), xorstr_(L"Redengine")},
                {xorstr_(L"2022/09/10:01:10:00"), xorstr_(L"Project Loader")},
                {xorstr_(L"2022/11/11:16:36:49"), xorstr_(L"ProjectLoader")},
                {xorstr_(L"2022/12/28:01:38:18"), xorstr_(L"ProjectLoader")},
                {xorstr_(L"2022/11/26:01:53:44"), xorstr_(L"Caveira Bypass")},
                {xorstr_(L"2021/03/16:07:19:45"), xorstr_(L"Asgard")},
                {xorstr_(L"2022/08/23:07:50:15"), xorstr_(L"Macro A-D")},
                {xorstr_(L"2022/12/12:04:43:06"), xorstr_(L"Eulen Cracked")},
                {xorstr_(L"2007/05/25:14:27:07"), xorstr_(L"MacroMov")},
                {xorstr_(L"2022/12/22:04:47:34"), xorstr_(L"Cutie External Cheat")},
                {xorstr_(L"2022/12/08:15:58:32"), xorstr_(L"Lunacy Cheat")},
                {xorstr_(L"2022/12/16:18:48:46"), xorstr_(L"RedEngine Cheat")},
                {xorstr_(L"2022/10/01:13:44:55"), xorstr_(L"Eulen")},
                {xorstr_(L"2022/12/14:01:42:45"), xorstr_(L"Eventvwr Clearer Cheat")},
                {xorstr_(L"2022/12/29:22:57:45"), xorstr_(L"CombatProject Cheat")},
                {xorstr_(L"2022/12/27:20:32:17"), xorstr_(L"Gosth Cheat")},
                {xorstr_(L"2022/12/02:12:40:49"), xorstr_(L"Gosth Cheat")},
                {xorstr_(L"2022/11/22:00:56:50"), xorstr_(L"Gosth Cheat")},
                {xorstr_(L"2022/11/15:18:04:20"), xorstr_(L"Gosth Cheat")},
                {xorstr_(L"2022/10/28:01:28:36"), xorstr_(L"Gosth Cheat")},
                {xorstr_(L"2021/05/24:02:07:42"), xorstr_(L"Monster FiveM Cheat")},
                {xorstr_(L"2021/05/05:23:17:59"), xorstr_(L"Eulen FiveM Cheat")},
                {xorstr_(L"2022/01/27:06:14:36"), xorstr_(L"Red Engine FiveM Cheat")},
                {xorstr_(L"2071/10/20:08:43:47"), xorstr_(L"Anti-SS Tool")},
                {xorstr_(L"2022/07/01:16:01:03"), xorstr_(L"Asgard Free Cheat")},
                {xorstr_(L"1997/03/04:05:00:52"), xorstr_(L"Susano")},
                {xorstr_(L"2096/12/05:10:36:10"), xorstr_(L"Susano")},
                {xorstr_(L"2076/01/29:15:06:16"), xorstr_(L"Susano")},
                {xorstr_(L"2007/09/27:03:43:52"), xorstr_(L"Susano")},
                {xorstr_(L"2024/01/11:09:21:13"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2024/02/12:22:48:27"), xorstr_(L"Loader.exe")},
                {xorstr_(L"2024/01/27:12:07:24"), xorstr_(L"External Cheat")},
                {xorstr_(L"2024/02/13:05:21:10"), xorstr_(L"Testo")},
                {xorstr_(L"2022/06/07:13:38:58"), xorstr_(L"Stopped Bypass")},
                {xorstr_(L"2022/01/28:16:21:07"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2021/12/31:01:17:02"), xorstr_(L"MonkeyWare")},
                {xorstr_(L"2024/02/21:21:49:07"), xorstr_(L"RedEngine Cheat")},
                {xorstr_(L"2024/02/23:02:43:18"), xorstr_(L"HXSoftwares Cheat")},
                {xorstr_(L"2041/03/22:17:41:29"), xorstr_(L"Susano Spoofer")},
                {xorstr_(L"2024/01/20:11:56:54"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2024/01/23:19:31:21"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2024/02/29:02:10:02"), xorstr_(L"Eulen Cheat")},
                {xorstr_(L"2024/02/10:08:54:03"), xorstr_(L"Anti Echo Cheat")},
                {xorstr_(L"2024/04/06:01:59:22"), xorstr_(L"HXCheats")},
                {xorstr_(L"2024/04/07:15:11:52"), xorstr_(L"Cobra Loader Cheat")},
                {xorstr_(L"2023/06/12:20:28:54"), xorstr_(L"Sicario Cleaner")},
                {xorstr_(L"2023/08/31:02:18:35"), xorstr_(L"Ov Projekt")},
                {xorstr_(L"2023/06/10:15:51:52"), xorstr_(L"Cfx mafia Cheat")},
                {xorstr_(L"2023/08/17:19:19:34"), xorstr_(L"Sicario Cleaner")},
                {xorstr_(L"2050/03/24:17:47:55"), xorstr_(L"Ciapak Cheat")},
                {xorstr_(L"2023/10/04:18:22:10"), xorstr_(L"Nightware Cheat")},
                {xorstr_(L"2024/01/29:23:57:59"), xorstr_(L"Vex Loader")},
                {xorstr_(L"2035/12/05:07:50:22"), xorstr_(L"Susano Cheat")},
                {xorstr_(L"2026/05/18:09:46:47"), xorstr_(L"Susano Cheat")},
                {xorstr_(L"2024/04/05:23:07:25"), xorstr_(L"420 Spoofer")},
                {xorstr_(L"2024/02/25:22:42:48"), xorstr_(L"Byte Cleaner")},
                {xorstr_(L"2024/04/28:20:54:58"), xorstr_(L"Mindselling Cheat")},
                {xorstr_(L"2024/05/10:18:00:55"), xorstr_(L"TZ Cheat")},
                {xorstr_(L"2024/06/01:01:50:16"), xorstr_(L"RedEngine Cheat")},
                {xorstr_(L"2024/06/14:16:41:05"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2016/10/24:00:51:41"), xorstr_(L"Susano Cheat")},
                {xorstr_(L"2024/05/18:20:20:27"), xorstr_(L"HXCheats")},
                {xorstr_(L"2024/06/18:16:22:15"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2024/01/11:18:57:18"), xorstr_(L"KHub Free Cheat")},
                {xorstr_(L"2024/01/19:23:04:32"), xorstr_(L"KHub Free Launcher")},
                {xorstr_(L"2025/01/13:10:25:08"), xorstr_(L"9z Cheat")},
                {xorstr_(L"2103/08/10:01:25:47"), xorstr_(L"9z Launcher")},
                {xorstr_(L"2024/08/08:12:15:48"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2025/01/16:20:29:25"), xorstr_(L"Response Cheat")},
                {xorstr_(L"2026/05/24:22:58:45"), xorstr_(L"Response Cheat")},
                {xorstr_(L"2024/05/18:20:20:27"), xorstr_(L"HXCheats Cheat")},
                {xorstr_(L"2024/10/08:15:52:54"), xorstr_(L"Spotless public Cheat")},
                {xorstr_(L"2024/09/22:07:34:34"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2024/12/07:23:22:33"), xorstr_(L"Sinister Cheat")},
                {xorstr_(L"2025/01/03:16:56:41"), xorstr_(L"Homicide Cheat")},
                {xorstr_(L"2024/11/07:16:50:50"), xorstr_(L"Homicide Cheat")},
                {xorstr_(L"2024/05/10:22:20:17"), xorstr_(L"Aegis Private External Cheat")},
                {xorstr_(L"2044/06/14:14:17:44"), xorstr_(L"Opium Cheat")},
                {xorstr_(L"2024/09/17:19:42:21"), xorstr_(L"Anti Echo Cheat")},
                {xorstr_(L"2024/11/30:14:28:17"), xorstr_(L"Anti echo Cheat")},
                {xorstr_(L"2062/07/25:12:18:00"), xorstr_(L"Prefetch Cleaner Cheat")},
                {xorstr_(L"2025/01/18:11:50:40"), xorstr_(L"Blackware Cheat")},
                {xorstr_(L"2024/12/26:21:33:52"), xorstr_(L"Spotless driver Cheat")},
                {xorstr_(L"2025/02/01:16:10:52"), xorstr_(L"Miguel Cheat")},
                {xorstr_(L"2024/10/18:23:12:47"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2024/12/15:05:53:32"), xorstr_(L"DC Cheat")},
                {xorstr_(L"2025/02/03:19:49:58"), xorstr_(L"Cwel Cheat")},
                {xorstr_(L"2024/02/29:01:21:26"), xorstr_(L"Dow Cheat")},
                {xorstr_(L"2024/09/10:16:29:05"), xorstr_(L"Wexless Cheat")},
                {xorstr_(L"2025/02/09:21:47:54"), xorstr_(L"Signer Private Cheat")},
                {xorstr_(L"2025/02/14:23:43:41"), xorstr_(L"Signer Cheat")},
                {xorstr_(L"2025/01/05:21:21:30"), xorstr_(L"Macho Cheat")},
                {xorstr_(L"2008/01/24:21:20:43"), xorstr_(L"Susano Cheat")},
                {xorstr_(L"2025/02/16:16:41:54"), xorstr_(L"Signer Cheat")},
                {xorstr_(L"2025/02/15:13:58:00"), xorstr_(L"Signer Cheat")},
                {xorstr_(L"2025/01/24:20:51:27"), xorstr_(L"Mwbyte Cheat")},
                {xorstr_(L"2025/01/28:17:57:04"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2025/01/14:11:41:43"), xorstr_(L"TZ Cheat")},
                {xorstr_(L"2025/01/19:13:18:23"), xorstr_(L"TZ Beta Cheat")},
                {xorstr_(L"2025/07/25:12:04:35"), xorstr_(L"TZX Spoofer")},
                {xorstr_(L"2025/09/15:15:47:46"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2026/06/04:16:38:51"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2026/07/01:09:04:59"), xorstr_(L"TZX Beta Cheat")},
                {xorstr_(L"2026/05/27:15:33:02"), xorstr_(L"TZX Spoofer")},
                {xorstr_(L"2026/06/29:14:33:50"), xorstr_(L"TZX Online Cheat")},
                {xorstr_(L"2025/01/11:23:11:41"), xorstr_(L"Mwbyte Cheat")},
                {xorstr_(L"2025/02/05:16:47:04"), xorstr_(L"Mwbyte Cheat")},
                {xorstr_(L"2025/01/15:15:50:07"), xorstr_(L"Runner Cheat")},
                {xorstr_(L"2025/02/14:17:27:19"), xorstr_(L"Mwbyte Cheat")},
                {xorstr_(L"2025/02/24:18:57:00"), xorstr_(L"Forte Cheat")},
                {xorstr_(L"2025/02/27:05:10:57"), xorstr_(L"Red Engine Cheat")},
                {xorstr_(L"2025/02/07:11:17:41"), xorstr_(L"Bypass.Fun Cheat")},
                {xorstr_(L"2025/02/21:04:33:19"), xorstr_(L"Skript Cheat")},
                {xorstr_(L"2025/02/02:17:18:02"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2052/07/18:05:44:50"), xorstr_(L"Susano Cheat")},
                {xorstr_(L"2024/03/09:19:54:59"), xorstr_(L"RedEngine Cheat")},
                {xorstr_(L"2025/03/09:21:24:52"), xorstr_(L"Gosth Cheat")},
                {xorstr_(L"2024/12/17:19:41:06"), xorstr_(L"FCS Bypass Cheat")},
                {xorstr_(L"2025/02/18:16:54:46"), xorstr_(L"Bypass.fun Cheat")},
                {xorstr_(L"2025/03/16:22:01:38"), xorstr_(L"Signer Cheat")},
                {xorstr_(L"2025/03/12:22:41:57"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2025/01/08:04:39:11"), xorstr_(L"Cold Cheat")},
                {xorstr_(L"2025/03/26:12:34:41"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2025/03/08:04:03:53"), xorstr_(L"Revenge Bypass")},
                {xorstr_(L"2025/02/26:20:19:49"), xorstr_(L"Fivem External Cheat")},
                {xorstr_(L"2023/05/22:18:18:22"), xorstr_(L"String Cleaner")},
                {xorstr_(L"2070/10/22:11:54:27"), xorstr_(L"Glock Cleaner")},
                {xorstr_(L"2025/03/25:22:11:36"), xorstr_(L"Be Better Cheat")},
                {xorstr_(L"2025/03/28:23:00:31"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2025/04/13:19:18:05"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2025/03/25:15:24:50"), xorstr_(L"FLK External")},
                {xorstr_(L"2025/03/18:19:27:37"), xorstr_(L"FLK Guard")},
                {xorstr_(L"2024/12/18:22:23:34"), xorstr_(L"FLK Spoofer")},
                {xorstr_(L"2064/04/06:16:39:21"), xorstr_(L"9z Cleaner")},
                {xorstr_(L"2025/03/12:20:39:32"), xorstr_(L"9z")},
                {xorstr_(L"2025/03/12:09:07:15"), xorstr_(L"9zx")},
                {xorstr_(L"2025/01/15:23:41:59"), xorstr_(L"NexHub")},
                {xorstr_(L"2025/03/01:14:50:23"), xorstr_(L"Skyline")},
                {xorstr_(L"2099/10/30:19:30:46"), xorstr_(L"X Cleaner")},
                {xorstr_(L"2025/04/17:12:33:22"), xorstr_(L"Solite Cheat")},
                {xorstr_(L"2024/12/06:15:26:53"), xorstr_(L"Efi Bypass Cheat")},
                {xorstr_(L"2025/03/29:15:32:15"), xorstr_(L"Mem Bypass")},
                {xorstr_(L"2025/04/19:18:45:19"), xorstr_(L"Quanta Cheat")},
                {xorstr_(L"2025/03/07:21:11:59"), xorstr_(L"Runner+ Cheat")},
                {xorstr_(L"2024/12/18:22:23:34"), xorstr_(L"FLK Spoofer")},
                {xorstr_(L"2025/04/20:22:02:47"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2025/04/21:16:14:50"), xorstr_(L"Quanta Cheat")},
                {xorstr_(L"2025/03/15:14:38:02"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2024/09/24:15:50:49"), xorstr_(L"Escape Service")},
                {xorstr_(L"2025/04/23:20:04:12"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2024/09/23:13:13:07"), xorstr_(L"KO Cheat")},
                {xorstr_(L"2025/03/04:19:53:19"), xorstr_(L"Miau External Cheat")},
                {xorstr_(L"2025/02/25:03:10:01"), xorstr_(L"Pau V2 Cheat")},
                {xorstr_(L"2025/03/15:14:38:02"), xorstr_(L"TZX Cheat")},
                {xorstr_(L"2025/04/21:19:16:28"), xorstr_(L"Zahars Bypass")},
                {xorstr_(L"2024/02/27:22:16:10"), xorstr_(L"Stopped Bypass")},
                {xorstr_(L"2025/04/24:22:18:38"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2025/04/25:20:49:27"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2025/04/23:20:36:10"), xorstr_(L"Fresh Bypass")},
                {xorstr_(L"2025/04/12:19:36:00"), xorstr_(L"Venacy Bypass")},
                {xorstr_(L"2025/04/27:03:12:41"), xorstr_(L"Be Better Cheat")},
                {xorstr_(L"2024/11/04:23:57:51"), xorstr_(L"Anti-Echo Cheat")},
                {xorstr_(L"2090/05/13:18:47:14"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2025/04/19:16:14:48"), xorstr_(L"Solite Cheat")},
                {xorstr_(L"2025/04/18:13:12:57"), xorstr_(L"Target Cheat")},
                {xorstr_(L"2025/02/19:14:48:54"), xorstr_(L"88 Cheats")},
                {xorstr_(L"2025/02/22:17:35:36"), xorstr_(L"Signer Cheat")},
                {xorstr_(L"2025/03/04:00:53:27"), xorstr_(L"Revenge Bypass")},
                {xorstr_(L"2025/05/03:17:16:56"), xorstr_(L"Quanta Cheat")},
                {xorstr_(L"2025/05/07:15:09:11"), xorstr_(L"Solite Cheat")},
                {xorstr_(L"2025/02/07:01:16:41"), xorstr_(L"Bypass.fun Cheat")},
                {xorstr_(L"2025/05/14:03:14:14"), xorstr_(L"InimuFiveM Cheat")},
                {xorstr_(L"2025/04/07:16:07:09"), xorstr_(L"HXCheats Cheat")},
                {xorstr_(L"2025/03/02:03:27:56"), xorstr_(L"Anti Echo Cheat")},
                {xorstr_(L"2025/04/28:22:50:29"), xorstr_(L"Binary Driver")},
                {xorstr_(L"2025/05/04:14:35:29"), xorstr_(L"Unique Bypass")},
                {xorstr_(L"2025/05/13:13:29:54"), xorstr_(L"Cocuk Triggerbot Cheat")},
                {xorstr_(L"2025/05/28:15:14:50"), xorstr_(L"Cyber Triggerbot Cheat")},
                {xorstr_(L"2025/05/28:15:10:01"), xorstr_(L"Wraith Cheat")},
                {xorstr_(L"2025/02/08:08:47:19"), xorstr_(L"Mr-cheat Loader")},
                {xorstr_(L"2025/05/07:18:36:37"), xorstr_(L"Ventiq Cheat")},
                {xorstr_(L"2025/01/16:00:19:54"), xorstr_(L"Lethality Cheat")},
                {xorstr_(L"2025/04/27:09:38:40"), xorstr_(L"Red Engine Cheat")},
                {xorstr_(L"2087/02/21:21:14:10"), xorstr_(L"9z Hider")},
                {xorstr_(L"2024/01/14:15:00:43"), xorstr_(L"0xCheats")},
                {xorstr_(L"2024/11/29:00:11:52"), xorstr_(L"1337 Cheat")},
                {xorstr_(L"2024/12/27:17:28:09"), xorstr_(L"Binance ")},
                {xorstr_(L"2024/12/27:13:31:51"), xorstr_(L"Nightfall Cheat")},
                {xorstr_(L"2025/03/08:18:48:22"), xorstr_(L"Ret9fun Cheat")},
                {xorstr_(L"2024/11/07:13:29:48"), xorstr_(L"Unic Cheat")},
                {xorstr_(L"2052/07/19:16:20:38"), xorstr_(L"9z Hider")},
                {xorstr_(L"2025/06/20:11:00:04"), xorstr_(L"9z Cheat")},
                {xorstr_(L"2025/04/30:14:02:38"), xorstr_(L"Private Cheat")},
                {xorstr_(L"2025/04/29:18:20:34"), xorstr_(L"Private Cheat")},
                {xorstr_(L"2025/04/30:17:16:43"), xorstr_(L"Private Cheat")},
                {xorstr_(L"2025/05/17:15:46:57"), xorstr_(L"Private Cheat")},
                {xorstr_(L"2025/04/28:22:50:29"), xorstr_(L"Binary Bypass")},
                {xorstr_(L"2023/05/08:10:26:14"), xorstr_(L"RavenX Bypass")},
                {xorstr_(L"2104/05/27:09:42:06"), xorstr_(L"9z Cleaner")},
                {xorstr_(L"2025/06/15:22:13:10"), xorstr_(L"Ventiq Cheat")},
                {xorstr_(L"2024/03/16:06:03:05"), xorstr_(L"Triggerbot Cheat")},
                {xorstr_(L"2025/06/07:18:16:36"), xorstr_(L"Navigateur Cheat")},
                {xorstr_(L"2025/03/27:20:48:20"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2025/01/10:10:38:23"), xorstr_(L"Keyser Cleaner")},
                {xorstr_(L"2025/06/30:11:04:52"), xorstr_(L"Quanta Cheat")},
                {xorstr_(L"2025/06/10:22:26:38"), xorstr_(L"Dll Bypass Cheat")},
                {xorstr_(L"2025/06/24:16:39:02"), xorstr_(L"Traceless Cheat")},
                {xorstr_(L"2025/06/16:22:10:21"), xorstr_(L"Quantity Cheat")},
                {xorstr_(L"2025/02/07:01:13:46"), xorstr_(L"Veax-free Cheat")},
                {xorstr_(L"2025/07/12:17:31:09"), xorstr_(L"Fresh Bypass")},
                {xorstr_(L"2025/03/29:19:09:29"), xorstr_(L"XIR Cheat")},
                {xorstr_(L"2025/07/19:20:08:27"), xorstr_(L"Erin Bypass")},
                {xorstr_(L"2025/05/29:20:22:08"), xorstr_(L"Erin Bypass")},
                {xorstr_(L"2025/04/29:17:01:28"), xorstr_(L"FTK Bypass")},
                {xorstr_(L"2025/01/14:11:41:43"), xorstr_(L"TZ Cheat")},
                {xorstr_(L"2025/07/15:11:21:04"), xorstr_(L"FTK Bypass")},
                {xorstr_(L"2025/04/27:09:38:40"), xorstr_(L"FTK Bypass")},
                {xorstr_(L"2025/04/07:16:07:09"), xorstr_(L"FTK Bypass")},
                {xorstr_(L"2025/07/18:20:29:13"), xorstr_(L"FTK Bypass")},
                {xorstr_(L"2025/07/14:22:44:49"), xorstr_(L"Elusive Cheat")},
                {xorstr_(L"2025/07/19:23:24:46"), xorstr_(L"Elusive DMA")},
                {xorstr_(L"2024/10/24:17:04:16"), xorstr_(L"Elusive External")},
                {xorstr_(L"2025/07/14:22:22:03"), xorstr_(L"Elusive Internal")},
                {xorstr_(L"2024/05/19:14:41:42"), xorstr_(L"Leechcore Driver")},
                {xorstr_(L"2024/10/09:21:24:16"), xorstr_(L"Leechcore")},
                {xorstr_(L"2052/12/05:03:03:37"), xorstr_(L"420 Bypass")},
                {xorstr_(L"2083/07/22:16:44:22"), xorstr_(L"420 Bypass")},
                {xorstr_(L"2025/07/13:03:47:46"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2025/07/20:12:27:35"), xorstr_(L"Turco Cheat")},
                {xorstr_(L"2025/07/20:14:44:14"), xorstr_(L"XIR Cheat")},
                {xorstr_(L"2024/12/12:11:39:32"), xorstr_(L"0x Cheat")},
                {xorstr_(L"2101/05/03:11:44:50"), xorstr_(L"HWID Spoofer")},
                {xorstr_(L"2025/05/18:19:52:50"), xorstr_(L"Leet Cheat")},
                {xorstr_(L"2025/06/12:18:30:59"), xorstr_(L"Nightfall Cheat")},
                {xorstr_(L"2025/06/01:08:16:25"), xorstr_(L"Ret 9 Cheat")},
                {xorstr_(L"2097/11/06:22:08:45"), xorstr_(L"Slayz Spoofer")},
                {xorstr_(L"2025/07/25:00:26:14"), xorstr_(L"Moose Bypass")},
                {xorstr_(L"1998/12/14:03:37:36"), xorstr_(L"Wexize Bypass")},
                {xorstr_(L"2025/07/27:00:45:49"), xorstr_(L"Quanta Cheat")},
                {xorstr_(L"2025/06/15:21:46:11"), xorstr_(L"Quanity Cheat")},
                {xorstr_(L"2025/07/30:15:54:33"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2025/02/21:04:14:54"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2026/07/01:13:06:42"), xorstr_(L"Spotless Bypass")},
                {xorstr_(L"2025/07/27:22:05:10"), xorstr_(L"Fresh Bypass")},
                {xorstr_(L"2025/07/03:01:27:23"), xorstr_(L"Bypass.fun Cheat")},
                {xorstr_(L"2025/04/07:16:07:09"), xorstr_(L"Hx Cheat")},
                {xorstr_(L"2022/12/15:08:12:50"), xorstr_(L"Hx Bypass")},
                {xorstr_(L"2025/08/03:18:44:48"), xorstr_(L"Fresh Bypass")},
                {xorstr_(L"2025/05/16:15:36:40"), xorstr_(L"XIR Bypass")},
                {xorstr_(L"2025/08/03:21:22:51"), xorstr_(L"FMA Cheat")},
                {xorstr_(L"2025/06/07:18:16:36"), xorstr_(L"RX Cheat")},
                {xorstr_(L"2084/05/23:09:17:02"), xorstr_(L"Uzui Cheat")},
                {xorstr_(L"2025/08/16:13:45:41"), xorstr_(L"Solite Cheat")},
                {xorstr_(L"2024/07/12:20:30:21"), xorstr_(L"Private Triggerbot Cheat")},
                {xorstr_(L"2025/07/22:06:38:24"), xorstr_(L"Aura Cheat")},
                {xorstr_(L"2025/07/07:01:15:13"), xorstr_(L"Slime Cheat")},
                {xorstr_(L"2025/07/29:11:40:03"), xorstr_(L"Macho Cheat")},
                {xorstr_(L"2025/04/15:17:29:11"), xorstr_(L"Kingdom Cheats")},
                {xorstr_(L"2025/06/10:22:26:38"), xorstr_(L"Purge Bypass")},
                {xorstr_(L"2025/07/30:16:00:01"), xorstr_(L"Rancom Cheat")},
                {xorstr_(L"2025/06/05:16:57:17"), xorstr_(L"Rancom Cheat")},
                {xorstr_(L"2025/03/14:16:46:17"), xorstr_(L"Random Cheat")},
                {xorstr_(L"2025/03/23:10:25:09"), xorstr_(L"Randoma Cheat")},
                {xorstr_(L"2025/03/28:13:08:47"), xorstr_(L"Randoma Cheat")},
                {xorstr_(L"2025/07/15:15:39:18"), xorstr_(L"Traceless Bypass")},
                {xorstr_(L"2025/08/05:00:13:13"), xorstr_(L"Traceless Bypass")},
                {xorstr_(L"2038/06/09:01:50:49"), xorstr_(L"9Z Cheat")},
                {xorstr_(L"2025/08/17:18:52:21"), xorstr_(L"9Z Cleaner")},
                {xorstr_(L"2098/12/27:09:29:25"), xorstr_(L"9Z Loader")},
                {xorstr_(L"2025/08/21:02:52:57"), xorstr_(L"9ZX Loader")},
                {xorstr_(L"2025/08/29:15:07:47"), xorstr_(L"AnyTrese Cheat")},
                {xorstr_(L"2025/09/05:19:04:04"), xorstr_(L"Cosmos Cheat")},
                {xorstr_(L"2026/03/03:21:04:59"), xorstr_(L"Cosmos Cheat")},
                {xorstr_(L"2025/08/31:14:44:11"), xorstr_(L"Binary Bypass")},
                {xorstr_(L"2025/09/16:19:58:10"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2025/09/04:21:10:04"), xorstr_(L"Masukkan Cheat")},
                {xorstr_(L"2025/08/17:11:26:12"), xorstr_(L"Masukkan Cheat")},
                {xorstr_(L"2025/08/31:10:08:46"), xorstr_(L"Fresh Bypass")},
                {xorstr_(L"2025/08/24:17:55:58"), xorstr_(L"Bypass.fun Cheat")},
                {xorstr_(L"2025/09/04:01:04:15"), xorstr_(L"Quanta Cheat")},
                {xorstr_(L"2025/10/08:14:30:48"), xorstr_(L"Drip Loader")},
                {xorstr_(L"2025/10/07:14:08:50"), xorstr_(L"Macho Cheat")},
                {xorstr_(L"2024/09/05:00:21:21"), xorstr_(L"Viperx Cheat")},
                {xorstr_(L"2025/07/01:02:58:41"), xorstr_(L"420 Services Free Cheat")},
                {xorstr_(L"2025/07/22:00:35:38"), xorstr_(L"420services Cheat")},
                {xorstr_(L"2025/09/17:00:18:52"), xorstr_(L"Eycheat Cheat")},
                {xorstr_(L"2025/05/27:08:35:00"), xorstr_(L"Quantity Cheat")},
                {xorstr_(L"2025/05/28:09:46:51"), xorstr_(L"Quantityv8 Cheat")},
                {xorstr_(L"2025/04/27:17:12:11"), xorstr_(L"VHook Cheat")},
                {xorstr_(L"2025/09/05:19:04:04"), xorstr_(L"Cosmoc Cheat")},
                {xorstr_(L"2025/05/15:20:12:04"), xorstr_(L"Ace Cheat")},
                {xorstr_(L"2025/03/17:13:46:13"), xorstr_(L"Turkey Cheat")},
                {xorstr_(L"2024/07/17:17:04:38"), xorstr_(L"Svchost FiveM Cheat")},
                {xorstr_(L"2025/10/30:19:34:27"), xorstr_(L"Echo Xir Cheat")},
                {xorstr_(L"2024/11/22:16:13:03"), xorstr_(L"Eulen Cheat")},
                {xorstr_(L"2025/09/24:01:05:56"), xorstr_(L"LAUNCHER Cheat")},
                {xorstr_(L"2025/12/06:00:59:34"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2025/11/18:13:00:01"), xorstr_(L"Flk Cheat")},
                {xorstr_(L"2025/12/16:19:50:56"), xorstr_(L"Flkbypass Cheat")},
                {xorstr_(L"2025/10/22:19:11:50"), xorstr_(L"Safeguard Cheat")},
                {xorstr_(L"2025/08/13:12:43:42"), xorstr_(L"Stealthy Cheat")},
                {xorstr_(L"2024/07/23:15:03:44"), xorstr_(L"Hydrogen Cheat")},
                {xorstr_(L"2025/10/30:13:42:01"), xorstr_(L"Leet Cheat")},
                {xorstr_(L"2025/12/09:17:41:04"), xorstr_(L"Club44 Bypass Cheat")},
                {xorstr_(L"2025/11/04:00:27:27"), xorstr_(L"Purge Bypass Cheat")},
                {xorstr_(L"2025/12/21:02:42:47"), xorstr_(L"UD Bypass Cheat")},
                {xorstr_(L"2025/02/24:23:30:43"), xorstr_(L"Solutions Cheat")},
                {xorstr_(L"2025/11/22:10:04:22"), xorstr_(L"Binary Bypass Cheat")},
                {xorstr_(L"2025/11/30:13:43:48"), xorstr_(L"Vionex Bypass Cheat")},
                {xorstr_(L"2025/04/18:01:28:54"), xorstr_(L"Fizzerina Bypass Cheat")},
                {xorstr_(L"2025/12/23:01:00:46"), xorstr_(L"Club44 Bypass Driver Cheat")},
                {xorstr_(L"2025/12/23:01:02:24"), xorstr_(L"Club44 Setup Cheat")},
                {xorstr_(L"2026/01/04:07:35:48"), xorstr_(L"Cracked Club44 Bypass")},
                {xorstr_(L"2025/12/21:19:31:52"), xorstr_(L"Cracked Club44 Cheat")},
                {xorstr_(L"2026/01/09:18:41:53"), xorstr_(L"Bypass.fun Bypass Cheat")},
                {xorstr_(L"2025/12/31:15:06:28"), xorstr_(L"Fivem Enjoyer Cheat")},
                {xorstr_(L"2091/09/08:07:27:20"), xorstr_(L"Keyser Auth Cheat")},
                {xorstr_(L"2025/12/06:00:59:34"), xorstr_(L"Keyser Loader Cheat")},
                {xorstr_(L"2025/12/18:22:49:11"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2028/08/05:20:03:05"), xorstr_(L"Spotless Public Cheat")},
                {xorstr_(L"2026/01/14:02:37:40"), xorstr_(L"Nines Bypass Cheat")},
                {xorstr_(L"2025/05/24:07:37:50"), xorstr_(L"SirketpdfV3 Cheat Cheat")},
                {xorstr_(L"2025/12/06:02:58:40"), xorstr_(L"VLC Cache Cheat Cheat")},
                {xorstr_(L"2025/08/21:12:57:33"), xorstr_(L"Yeni WinRAR Cheat Cheat")},
                {xorstr_(L"2025/12/23:01:01:46"), xorstr_(L"BraveSetup Cheat")},
                {xorstr_(L"2025/12/23:01:03:03"), xorstr_(L"ChromeSetup Cheat")},
                {xorstr_(L"2025/12/23:01:04:14"), xorstr_(L"MsedgeSetup Cheat")},
                {xorstr_(L"2025/12/24:02:28:59"), xorstr_(L"Club44 Bypass Setup Cheat")},
                {xorstr_(L"2026/01/11:00:47:00"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2026/01/22:01:15:36"), xorstr_(L"Keyser Cheat")},
                {xorstr_(L"2026/06/16:23:39:16"), xorstr_(L"Keyser External Cheat")},
                {xorstr_(L"2026/06/14:21:45:32"), xorstr_(L"Keyser FiveM Cheat")},
                {xorstr_(L"2025/05/04:18:03:19"), xorstr_(L"Anti Echo Cheat")},
                {xorstr_(L"2062/07/25:12:18:00"), xorstr_(L"Engine Control Cheat")},
                {xorstr_(L"2049/07/01:04:22:35"), xorstr_(L"EazyAim Cheat")},
                {xorstr_(L"2026/03/24:19:24:42"), xorstr_(L"Genesis bypass Cheat")},
                {xorstr_(L"2026/03/23:22:19:41"), xorstr_(L"Matrix Bypass Cheat")},
                {xorstr_(L"2026/03/20:13:08:24"), xorstr_(L"Nemesis Bypass Cheat")},
                {xorstr_(L"2026/03/22:20:30:20"), xorstr_(L"South Loader")},
                {xorstr_(L"2026/05/26:16:27:26"), xorstr_(L"South Loader")},
                {xorstr_(L"2073/07/25:06:49:03"), xorstr_(L"Renaissance External")},
                {xorstr_(L"2026/07/18:14:25:18"), xorstr_(L"Wizard V4 Bypass")},
                {xorstr_(L"2026/03/01:21:35:00"), xorstr_(L"Squid Bypass Cheat")},
                {xorstr_(L"2025/12/30:16:38:32"), xorstr_(L"Thorns III Spoofer Cheat")},
                {xorstr_(L"2026/03/18:13:53:33"), xorstr_(L"Wizard v2 Cheat")},
                {xorstr_(L"2026/03/30:18:38:09"), xorstr_(L"Eulen Cheat")},
                {xorstr_(L"2026/06/09:08:35:19"), xorstr_(L"Paragon Cheat")},
                {xorstr_(L"2026/05/30:07:06:21"), xorstr_(L"Memory.win Loader")},
                {xorstr_(L"2026/05/26:21:24:20"), xorstr_(L"Memory.win")},
                {xorstr_(L"2026/06/15:17:03:31"), xorstr_(L"Haze Bypass")},
                {xorstr_(L"2026/06/11:15:36:44"), xorstr_(L"Divus Bypass")},
                {xorstr_(L"2026/05/06:08:25:25"), xorstr_(L"MachoCheats")},
                {xorstr_(L"2026/06/28:20:24:17"), xorstr_(L"RedEngine")},
                {xorstr_(L"2026/06/02:18:20:16"), xorstr_(L"Onyx Cheat")},
                {xorstr_(L"2026/08/05:22:30:57"), xorstr_(L"FLK Bypass")},
                {xorstr_(L"2026/07/20:13:36:43"), xorstr_(L"Rolex Bypass")},
                {xorstr_(L"2026/08/06:00:50:57"), xorstr_(L"Titan Cheat")},
                {xorstr_(L"2026/07/29:01:01:30"), xorstr_(L"Titan Bypass")},
                {xorstr_(L"2026/08/09:22:24:59"), xorstr_(L"Sacred Bypass")},
                {xorstr_(L"2026/05/14:18:58:32"), xorstr_(L"FFPanel Cheat")},
                {xorstr_(L"2026/08/19:22:50:01"), xorstr_(L"redEngine Cheat")},
                {xorstr_(L"2026/08/14:20:44:43"), xorstr_(L"Airwave Cheat")},
                {xorstr_(L"2026/03/27:22:51:07"), xorstr_(L"Bytecode Bypass")},

#elif DETECT_COD
                {xorstr_(L"2025/06/16:03:13:16"), xorstr_(L"Fecurity Cheat")},
                {xorstr_(L"2025/05/30:16:31:55"), xorstr_(L"Fecurity Cheat")},
                {xorstr_(L"2025/06/10:05:43:49"), xorstr_(L"HyperChair Cheat")},
                {xorstr_(L"2025/04/30:09:47:20"), xorstr_(L"LDV3 Cheat")},
                {xorstr_(L"2025/04/30:09:47:19"), xorstr_(L"LDV3 Cheat")},
                {xorstr_(L"2024/10/25:14:16:46"), xorstr_(L"ProGress Cheat")},
                {xorstr_(L"2025/02/13:05:57:38"), xorstr_(L"UA Cheat")},
                {xorstr_(L"2024/03/16:06:03:05"), xorstr_(L"RegOBJ Cheat")},
                {xorstr_(L"2025/06/16:03:25:38"), xorstr_(L"Cst Cheat")},
                {xorstr_(L"2015/01/10:05:27:02"), xorstr_(L"Kernaim Cheat")},
                {xorstr_(L"2025/06/21:20:49:01"), xorstr_(L"LXW Cheat")},
                {xorstr_(L"2025/06/17:17:53:04"), xorstr_(L"Rytek Chair Cheat")},
                {xorstr_(L"2025/06/19:20:47:19"), xorstr_(L"T10 Cheat")},
                {xorstr_(L"2025/02/13:05:57:38"), xorstr_(L"UA Cheat")},
                {xorstr_(L"2025/06/10:08:12:14"), xorstr_(L"Zenith Cheat")},
                {xorstr_(L"2025/06/17:17:53:04"), xorstr_(L"Rytek Chair Cheat")},
                {xorstr_(L"2025/07/01:09:14:54"), xorstr_(L"24H2 Cheat")},
                {xorstr_(L"2025/06/27:15:44:44"), xorstr_(L"Nebula Chair Cheat")},
                {xorstr_(L"2025/06/21:10:00:15"), xorstr_(L"Hyper Cheat")},
                {xorstr_(L"2024/11/07:13:29:48"), xorstr_(L"Hyper Cheat")},
                {xorstr_(L"2025/06/19:20:47:19"), xorstr_(L"Hyper Cheat")},
                {xorstr_(L"2025/07/10:23:12:07"), xorstr_(L"Thunex Cheat")},
                {xorstr_(L"2025/07/10:23:14:23"), xorstr_(L"Thunex Cheat")},
                {xorstr_(L"2025/06/21:10:00:15"), xorstr_(L"Thunex Cheat")},
                {xorstr_(L"2025/02/27:20:03:43"), xorstr_(L"Thunex Cheat")},
                {xorstr_(L"2025/07/10:15:53:55"), xorstr_(L"Infemo X Cheat")},
                {xorstr_(L"2024/12/20:20:14:16"), xorstr_(L"XIM Cheat")},
                {xorstr_(L"2024/05/17:06:58:08"), xorstr_(L"Keyflexor Cheat")},
                {xorstr_(L"2025/07/13:21:16:38"), xorstr_(L"Paradox Cheat")},
                {xorstr_(L"2025/11/23:00:19:58"), xorstr_(L"BO6 Internal Cheat")},
                {xorstr_(L"2025/12/24:20:36:43"), xorstr_(L"BO7 Internal Cheat")},
                {xorstr_(L"2025/12/10:02:02:45"), xorstr_(L"Rsolutions Loader Cheat")},

#elif DETECT_RUST
                {xorstr_(L"2025/05/05:22:09:40"), xorstr_(L"Kill.ac Cheat")},
                {xorstr_(L"2025/05/08:14:49:50"), xorstr_(L"Serenity Cheat")},
                {xorstr_(L"2025/05/22:21:36:19"), xorstr_(L"Ultimate Cheat")},
                {xorstr_(L"2025/05/14:13:29:06"), xorstr_(L"Photon Cheat")},
                {xorstr_(L"2024/01/04:20:34:07"), xorstr_(L"Evilcheats Cheat")},
                {xorstr_(L"2025/12/10:02:02:45"), xorstr_(L"Rsolutions Loader Cheat")},

#elif DETECT_SIEGE
                {xorstr_(L"2015/11/11:11:04:26"), xorstr_(L"ChatSpam Cheat")},
                {xorstr_(L"2077/07/11:21:22:51"), xorstr_(L"External Cheat")},
                {xorstr_(L"2044/11/03:13:50:57"), xorstr_(L"KeyRan Cheat")},
                {xorstr_(L"2022/06/21:19:06:16"), xorstr_(L"NoRecoil Cheat")},
                {xorstr_(L"2024/05/23:08:08:50"), xorstr_(L"UR Cheat")},
                {xorstr_(L"2022/09/17:00:26:26"), xorstr_(L"Crusader Cheat")},
                {xorstr_(L"2076/07/23:20:02:37"), xorstr_(L"Crusader Cheat")},
                {xorstr_(L"2097/11/13:15:33:40"), xorstr_(L"Crusader Cheat")},
                {xorstr_(L"2021/01/02:19:42:52"), xorstr_(L"CheatArmy Cheat")},
                {xorstr_(L"2025/04/11:18:40:28"), xorstr_(L"CheatArmy Cheat")},
                {xorstr_(L"2025/04/14:17:40:27"), xorstr_(L"Ring 1 Cheat")},
                {xorstr_(L"2025/04/14:17:40:27"), xorstr_(L"Ring 1 Cheat")},
                {xorstr_(L"2022/06/21:19:06:16"), xorstr_(L"Unicoil Cheat")},
                {xorstr_(L"2025/01/17:15:38:17"), xorstr_(L"Bameninghong V3 Cheat")},
                {xorstr_(L"2025/03/13:06:55:45"), xorstr_(L"Last Recoil Cheat")},
                {xorstr_(L"2025/04/24:08:42:02"), xorstr_(L"No Recoil Cheat")},
                {xorstr_(L"2024/03/06:23:04:35"), xorstr_(L"Slinky Cheat")},
                {xorstr_(L"2025/03/17:11:43:47"), xorstr_(L"Vega Cheat")},
                {xorstr_(L"2044/11/03:13:50:57"), xorstr_(L"KeyRan Cheat")},
                {xorstr_(L"2024/05/23:08:08:50"), xorstr_(L"No Recoil Cheat")},
                {xorstr_(L"2025/05/27:00:28:49"), xorstr_(L"Perc Cheat")},
                {xorstr_(L"2087/08/19:22:45:55"), xorstr_(L"Lethal Cheat")},
                {xorstr_(L"2025/06/18:21:50:39"), xorstr_(L"Perc Cheat")},
                {xorstr_(L"2083/12/24:07:32:52"), xorstr_(L"Crusader Cheat")},
                {xorstr_(L"2025/05/23:02:27:35"), xorstr_(L"Unlock-all Cheat")},
                {xorstr_(L"2083/12/24:07:32:52"), xorstr_(L"Crusader R6 Cheat")},
                {xorstr_(L"2022/09/17:00:26:26"), xorstr_(L"Dapper Cheat")},
                {xorstr_(L"2019/08/29:16:15:30"), xorstr_(L"Diamond No Recoil")},
                {xorstr_(L"2025/10/01:16:07:14"), xorstr_(L"Calamari Cheat")},
                {xorstr_(L"2024/12/06:15:26:53"), xorstr_(L"Calamari Boot Cheat")},
                {xorstr_(L"2025/07/15:07:10:15"), xorstr_(L"Perc Cheat")},
                {xorstr_(L"2026/07/05:13:10:07"), xorstr_(L"Aptitude Cheat")},

#elif DETECT_ROBLOX
                {xorstr_(L"2026/08/19:13:02:19"), xorstr_(L"Gain External Cheat")},
                {xorstr_(L"2026/07/07:04:31:33"), xorstr_(L"Userworld External Cheat")},
                {xorstr_(L"2026/05/20:18:40:00"), xorstr_(L"Userworld Executor Cheat")},
                {xorstr_(L"2052/09/14:03:29:25"), xorstr_(L"Emberly Executor Cheat")},
                {xorstr_(L"2026/08/28:06:40:39"), xorstr_(L"Pablo External Cheat")},
                {xorstr_(L"2026/08/17:18:58:03"), xorstr_(L"Real Executor Cheat")},
                {xorstr_(L"2026/08/07:09:29:19"), xorstr_(L"Desync External Cheat")},
                {xorstr_(L"2026/08/13:22:14:23"), xorstr_(L"Horizon External Cheat")},
                {xorstr_(L"2054/02/20:09:07:44"), xorstr_(L"Solara Cheat")},
                {xorstr_(L"2024/10/24:20:38:03"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2024/10/24:20:37:47"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2024/08/25:18:46:50"), xorstr_(L"Matcha Loader")},
                {xorstr_(L"2024/11/30:12:51:23"), xorstr_(L"Matcha Mapper")},
                {xorstr_(L"2024/12/24:18:45:25"), xorstr_(L"Matcha Cheat")},
                {xorstr_(L"2025/01/06:18:50:29"), xorstr_(L"Nihon Cheat")},
                {xorstr_(L"2024/10/03:05:56:40"), xorstr_(L"Nihon Spoofer Cheat")},
                {xorstr_(L"2025/01/15:22:09:39"), xorstr_(L"Nihon-Module Cheat")},
                {xorstr_(L"2024/12/30:19:26:46"), xorstr_(L"Nihon-Interface Cheat")},
                {xorstr_(L"2025/01/17:21:54:08"), xorstr_(L"Horizon Cheat")},
                {xorstr_(L"2024/09/11:18:00:38"), xorstr_(L"Wave Cheat")},
                {xorstr_(L"2091/09/22:13:39:03"), xorstr_(L"Lunar Cheat")},
                {xorstr_(L"2025/01/07:04:43:10"), xorstr_(L"Mooze Cheat")},
                {xorstr_(L"2024/12/10:12:25:55"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2024/12/10:05:36:20"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2025/01/22:22:48:55"), xorstr_(L"Mooze Cheat")},
                {xorstr_(L"2050/10/07:14:28:31"), xorstr_(L"Servere Upgrade")},
                {xorstr_(L"2025/01/14:23:34:54"), xorstr_(L"Servere Cheat")},
                {xorstr_(L"2025/03/28:16:40:11"), xorstr_(L"Swift Cheat")},
                {xorstr_(L"2025/03/27:05:39:44"), xorstr_(L"Mooze Cheat")},
                {xorstr_(L"2025/04/17:20:05:13"), xorstr_(L"Rihno Cheat")},
                {xorstr_(L"2025/07/03:10:35:25"), xorstr_(L"Bhess Bypass")},
                {xorstr_(L"2025/07/02:14:43:18"), xorstr_(L"Bhess Cheat")},
                {xorstr_(L"2025/07/16:09:31:47"), xorstr_(L"dx9 Cheat")},
                {xorstr_(L"2025/07/07:17:27:50"), xorstr_(L"dx91 Cheat")},
                {xorstr_(L"2025/02/12:13:56:03"), xorstr_(L"dx92 Cheat")},
                {xorstr_(L"2025/07/14:09:30:56"), xorstr_(L"Matcha Cheat")},
                {xorstr_(L"2026/06/10:01:39:11"), xorstr_(L"Matcha Cheat")},
                {xorstr_(L"2024/07/27:01:03:47"), xorstr_(L"Dx9 External Cheat")},
                {xorstr_(L"2025/07/17:11:42:51"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2025/07/24:10:30:07"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2079/11/20:14:29:14"), xorstr_(L"Servere Updater")},
                {xorstr_(L"2025/07/09:23:50:32"), xorstr_(L"Servere Cheat")},
                {xorstr_(L"2025/08/06:20:40:32"), xorstr_(L"Valex Cheat")},
                {xorstr_(L"2024/05/17:06:58:08"), xorstr_(L"Polar AI Cheat")},
                {xorstr_(L"2026/07/05:16:03:16"), xorstr_(L"Vanilla Bypass")},
                {xorstr_(L"2026/07/13:15:27:00"), xorstr_(L"Matrix Cheat")},
                {xorstr_(L"2026/05/17:17:09:32"), xorstr_(L"Dx9 External Cheat")},
                {xorstr_(L"2026/07/25:15:54:08"), xorstr_(L"Clarity Public")},
                {xorstr_(L"2026/08/25:19:47:19"), xorstr_(L"Clarity Private")},
                {xorstr_(L"2026/01/16:01:11:55"), xorstr_(L"Serotonin External")},
                {xorstr_(L"2025/03/08:23:05:20"), xorstr_(L"Volt Cheat")},
                {xorstr_(L"2026/06/26:20:20:23"), xorstr_(L"Madium Cheat")},
                {xorstr_(L"2026/07/20:05:52:24"), xorstr_(L"Matcha Cheat")},
                {xorstr_(L"2026/04/21:08:08:47"), xorstr_(L"Matcha Mapper")},
                {xorstr_(L"2026/05/11:16:33:26"), xorstr_(L"Matcha Loader")},
                {xorstr_(L"2026/02/13:06:09:39"), xorstr_(L"Severe Cheat")},
                {xorstr_(L"2026/07/02:22:14:20"), xorstr_(L"Schoology Cheat")},
                {xorstr_(L"2026/07/30:23:45:02"), xorstr_(L"PradaCC Bypass")},
                {xorstr_(L"2009/08/16:11:05:47"), xorstr_(L"ExLoader Installer Cheat")},
                {xorstr_(L"2026/06/16:07:34:36"), xorstr_(L"ExLoader Installer Cheat")},
                {xorstr_(L"2026/07/19:10:13:10"), xorstr_(L"ExLoader Cheat")},

#elif DETECT_FORTNITE
                {xorstr_(L"2022/09/26:20:30:57"), xorstr_(L"Excel Loader Cheat")},
                {xorstr_(L"2024/06/13:19:36:35"), xorstr_(L"Nerve Ware Cheat")},
                {xorstr_(L"2013/04/25:18:24:57"), xorstr_(L"Inferno Cheat")},
                {xorstr_(L"2017/05/10:00:11:11"), xorstr_(L"Meta Cheat")},
                {xorstr_(L"2022/09/26:20:30:57"), xorstr_(L"zCheats")},
                {xorstr_(L"2025/01/22:19:21:24"), xorstr_(L"Oracle Cheat")},
                {xorstr_(L"2024/10/16:15:20:30"), xorstr_(L"Arcane Cheat")},
                {xorstr_(L"2024/04/20:21:22:56"), xorstr_(L"Zed Cheat")},
                {xorstr_(L"2024/08/22:13:52:59"), xorstr_(L"Omega Cheat")},
                {xorstr_(L"2023/09/29:18:31:11"), xorstr_(L"KingzCheats Cheat")},
                {xorstr_(L"2017/05/10:00:11:11"), xorstr_(L"Solaris Private Cheat")},
                {xorstr_(L"2025/01/16:17:00:34"), xorstr_(L"Solaris Public Cheat")},
                {xorstr_(L"2014/05/29:04:26:46"), xorstr_(L"Edner Cheat")},
                {xorstr_(L"2013/09/12:11:41:32"), xorstr_(L"Velocc Cheat")},
                {xorstr_(L"2025/04/19:10:33:32"), xorstr_(L"FLK Spoofer")},
                {xorstr_(L"2025/07/22:17:30:57"), xorstr_(L"Softstack Cheat")},
                {xorstr_(L"2025/07/28:16:04:15"), xorstr_(L"Sinful Cheat")},
                {xorstr_(L"2084/05/23:09:17:02"), xorstr_(L"Uzui Cheat")},
                {xorstr_(L"2025/08/18:08:47:07"), xorstr_(L"Titan Spoofer")},
                {xorstr_(L"2025/10/14:16:40:18"), xorstr_(L"Noctra Cheat")},
                {xorstr_(L"2025/10/23:15:23:24"), xorstr_(L"Kiki Cheat")},
                {xorstr_(L"2025/10/08:16:01:40"), xorstr_(L"Fortnite Spoofer Cheat")},
                {xorstr_(L"2025/12/10:02:02:45"), xorstr_(L"Rsolutions Loader Cheat")},

#elif DETECT_FREEFIRE
                {xorstr_(L"2025/02/10:20:14:47"), xorstr_(L"XRC Cheat")},
                {xorstr_(L"2025/02/15:02:26:32"), xorstr_(L"Zimo Private Cheat")},
                {xorstr_(L"2025/01/31:18:14:29"), xorstr_(L"xisfpd Cheat")},
                {xorstr_(L"2025/01/31:18:22:51"), xorstr_(L"Zimo Private Cheat")},
                {xorstr_(L"2025/01/15:00:19:51"), xorstr_(L"xisfpd Cheat")},
                {xorstr_(L"2025/01/15:00:19:51"), xorstr_(L"OBS Cheat")},
                {xorstr_(L"2025/02/10:01:32:37"), xorstr_(L"XRC Cheat")},
                {xorstr_(L"2025/01/30:23:50:10"), xorstr_(L"Drip Cheat")},
                {xorstr_(L"2024/02/04:05:11:26"), xorstr_(L"XRC Cheat")},
                {xorstr_(L"2025/02/14:00:35:56"), xorstr_(L"Cs2 Cheat")},
                {xorstr_(L"2024/12/28:04:25:56"), xorstr_(L"Xrc Cheat")},
                {xorstr_(L"2024/12/24:12:41:19"), xorstr_(L"Voidtools Cheat")},
                {xorstr_(L"2079/05/07:18:15:44"), xorstr_(L"Favela gratis Cheat")},
                {xorstr_(L"2049/05/27:00:49:33"), xorstr_(L"Immortal Cheat")},
                {xorstr_(L"2105/06/03:18:34:23"), xorstr_(L"GX private Cheat")},
                {xorstr_(L"2025/02/23:17:54:25"), xorstr_(L"XRC Cheat")},
                {xorstr_(L"2025/02/13:14:14:04"), xorstr_(L"Riquin Xiters Cheat")},
                {xorstr_(L"2025/02/02:02:09:04"), xorstr_(L"Extacy Cheat")},
                {xorstr_(L"2024/10/01:21:31:19"), xorstr_(L"Combo Trick Cheat")},
                {xorstr_(L"2025/02/27:14:40:46"), xorstr_(L"Aimlock Cheat")},
                {xorstr_(L"2024/12/23:05:47:18"), xorstr_(L"Playboy Basic Cheat")},
                {xorstr_(L"2025/02/27:20:31:39"), xorstr_(L"XRC Private Cheat")},
                {xorstr_(L"2025/02/27:16:36:57"), xorstr_(L"XRC Cheat")},
                {xorstr_(L"2063/07/13:13:56:38"), xorstr_(L"Real Trem Cheat")},
                {xorstr_(L"2025/03/08:21:40:39"), xorstr_(L"Aim Bypass")},
                {xorstr_(L"2077/03/12:13:26:41"), xorstr_(L"Playboy Cheat")},

#elif DETECT_DAYZ
                {xorstr_(L"2019/03/23:15:13:55"), xorstr_(L"NvidiaProfileInspector")},
                {xorstr_(L"2024/12/30:02:32:49"), xorstr_(L"LagSwitch Cheat")},
                {xorstr_(L"2024/09/10:10:16:24"), xorstr_(L"Authority Cheat")},
                {xorstr_(L"2024/12/22:17:03:30"), xorstr_(L"Authority Cheat")},
                {xorstr_(L"2025/02/25:23:04:06"), xorstr_(L"Stugware Cheat")},
                {xorstr_(L"2025/02/14:16:30:11"), xorstr_(L"Covcheg Cheat")},
                {xorstr_(L"2087/08/19:22:45:55"), xorstr_(L"Lethal Cheat")},
                {xorstr_(L"2025/11/26:00:49:54"), xorstr_(L"Nextcheat Cheat")},
                {xorstr_(L"2025/12/10:02:02:45"), xorstr_(L"Rsolutions Loader Cheat")},

#elif DETECT_CS

                {xorstr_(L"2026/07/05:19:58:12"), xorstr_(L"Neverlose Cheat")},
                {xorstr_(L"2026/08/02:16:09:36"), xorstr_(L"Memesense Cheat")},
                {xorstr_(L"2025/12/24:00:21:35"), xorstr_(L"Fatality Cheat")},
                {xorstr_(L"2026/07/04:07:58:12"), xorstr_(L"Nixware Cheat")},
                {xorstr_(L"2026/07/14:08:39:43"), xorstr_(L"Onetap Mapper Cheat")},
                {xorstr_(L"2025/04/13:14:15:07"), xorstr_(L"Pandora Cheat")},
                {xorstr_(L"2026/05/07:07:54:44"), xorstr_(L"Steam Pandora Cheat")},
                {xorstr_(L"2026/05/07:08:23:17"), xorstr_(L"Steam Plague Cheat")},
                {xorstr_(L"2026/04/16:14:01:22"), xorstr_(L"Neverlose Server Cheat")},
                {xorstr_(L"2026/07/14:08:36:48"), xorstr_(L"Onetap Allocator Cheat")},
                {xorstr_(L"2025/12/31:07:24:47"), xorstr_(L"OpenCV World 4130 Cheat")},
                {xorstr_(L"2026/04/05:11:35:43"), xorstr_(L"Boost JSON 1.89 Cheat")},
                {xorstr_(L"2026/04/05:11:28:35"), xorstr_(L"LibCrypto 3 Cheat")},
                {xorstr_(L"2026/04/05:12:31:40"), xorstr_(L"LibPQ Cheat")},
                {xorstr_(L"2026/04/05:11:28:35"), xorstr_(L"LibSSL 3 Cheat")},
                {xorstr_(L"2023/04/04:16:27:22"), xorstr_(L"Monolith Cheat")},
                {xorstr_(L"2026/04/05:13:06:13"), xorstr_(L"Neverlose Injector Cheat")},
                {xorstr_(L"2026/04/16:15:30:40"), xorstr_(L"Neverlose Cheat")},
                {xorstr_(L"2026/05/08:23:14:24"), xorstr_(L"Steam Monolith Cheat")},
                {xorstr_(L"2026/05/28:02:48:54"), xorstr_(L"Gamesense Cheat")},
                {xorstr_(L"2026/05/26:16:48:29"), xorstr_(L"Aimgooner Cheat")},
                {xorstr_(L"2026/02/14:20:24:34"), xorstr_(L"Aventum Mapper Cheat")},
                {xorstr_(L"2026/02/14:20:20:59"), xorstr_(L"Aventum Steam Cheat")},
                {xorstr_(L"2026/03/19:21:55:30"), xorstr_(L"Clarity Cheat")},
                {xorstr_(L"2026/07/27:06:06:53"), xorstr_(L"Enrage v3 Cheat")},
                {xorstr_(L"2018/03/12:21:34:35"), xorstr_(L"Fanta Cheat")},
                {xorstr_(L"2021/10/09:19:15:00"), xorstr_(L"Fatality Legacy Cheat")},
                {xorstr_(L"2066/10/20:07:41:45"), xorstr_(L"Femboylose Neverlose Server Cheat")},
                {xorstr_(L"2018/02/14:18:51:11"), xorstr_(L"Hentaiware Cheat")},
                {xorstr_(L"2023/02/06:07:52:28"), xorstr_(L"Kamidere Cheat")},
                {xorstr_(L"2026/03/12:15:46:38"), xorstr_(L"Peti25 Addon Cheat")},
                {xorstr_(L"2025/06/09:23:48:41"), xorstr_(L"Peti25 Cheat")},
                {xorstr_(L"2026/06/22:15:39:28"), xorstr_(L"SSCS2 Injector Cheat")},
                {xorstr_(L"2026/03/19:22:08:17"), xorstr_(L"Steam Clarity Cheat")},
                {xorstr_(L"2026/06/07:20:25:02"), xorstr_(L"Steam Fatality Legacy18 Cheat")},
                {xorstr_(L"2026/01/05:07:46:30"), xorstr_(L"Steam Pandora Legacy18 Cheat")},
                {xorstr_(L"2025/03/01:13:45:38"), xorstr_(L"Superior v2 Cheat")},
                {xorstr_(L"2026/07/27:18:28:49"), xorstr_(L"Supremacy Cheat")},
                {xorstr_(L"2016/12/07:21:56:46"), xorstr_(L"Video Cheat")},
                {xorstr_(L"2026/07/06:10:13:53"), xorstr_(L"Vortix Cheat")},
                {xorstr_(L"2026/07/29:04:39:12"), xorstr_(L"Archillix Cheat")},
                {xorstr_(L"2026/08/16:10:07:24"), xorstr_(L"Berserk v2 Cheat")},
                {xorstr_(L"2026/07/09:15:43:07"), xorstr_(L"CS2 External ESP Cheat")},
                {xorstr_(L"2012/12/31:00:38:51"), xorstr_(L"Dragonburn Cheat")},
                {xorstr_(L"2025/11/27:07:08:39"), xorstr_(L"Dragonburn Usermode Cheat")},
                {xorstr_(L"2026/08/07:16:14:37"), xorstr_(L"Nerv Cheat")},
                {xorstr_(L"2026/08/04:22:51:50"), xorstr_(L"Strafe Cheat")},
                {xorstr_(L"2026/08/12:23:41:43"), xorstr_(L"Velocity Cheat")},
                {xorstr_(L"2026/08/17:19:44:15"), xorstr_(L"Shook Cheat")},
                {xorstr_(L"2026/07/03:16:31:46"), xorstr_(L"VAC Disabler")},

#endif
                {xorstr_(L"2023/01/12:18:00:49"), xorstr_(L"String Deletor")},
                {xorstr_(L"2018/08/15:13:56:53"), xorstr_(L"Stringcleaner")},
                {xorstr_(L"2022/07/06:20:23:42"), xorstr_(L"Stringcleaner")},
                {xorstr_(L"2020/09/03:19:54:43"), xorstr_(L"Phantom String Cleaner")},
                {xorstr_(L"2083/09/17:08:33:11"), xorstr_(L"Stringless")},
                {xorstr_(L"2050/11/10:11:43:35"), xorstr_(L"Horion Injector")},
                {xorstr_(L"2065/07/24:20:06:40"), xorstr_(L"Night Injector")},
                {xorstr_(L"2011/09/27:03:22:57"), xorstr_(L"Process Hollower Cheat")},
                {xorstr_(L"2025/05/02:01:58:44"), xorstr_(L"Cheat Cleaner")},
                {xorstr_(L"2025/08/16:21:31:33"), xorstr_(L"Snowy Cleaner")},
                {xorstr_(L"2025/11/17:14:33:37"), xorstr_(L"Temp Spoofer Cheat")},
                {xorstr_(L"2025/09/04:20:52:45"), xorstr_(L"Shen Bypass")},
                {xorstr_(L"2026/07/15:18:58:18"), xorstr_(L"Shen Loader")},
            };
        }
        catch (...) {
            return;
        }

        std::set<std::wstring> emitted;

        auto consider = [&](const std::wstring& s) {
            try {
                std::wstring name;
                std::wstring date;
                if (!ParseRecord(s, name, date)) return;
                for (const auto& entry : known) {
                    if (entry.first == date) {
                        std::wstring line = entry.second + xorstr_(L" Ran Since Logon:") + name;
                        if (emitted.insert(line).second) {
                            try {
                                LOG ( DETECTION , xorstr_("N/A")) << WideToUtf8(line);
                            }
                            catch (...) {
                            }
                        }
                    }
                }
            }
            catch (...) {
            }
            };

        for (const auto& s : ascii) consider(Utf8ToWide(s));
        for (const auto& s : wide) consider(s);
    }
    catch (...) {
    }
}

int compilationscan::compilation_scan() noexcept {
    try {
        SetConsoleOutputCP(CP_UTF8);
        EnableDebugPrivilege();

        unsigned long pid = FindDpsPid();
        if (pid == 0) return 0;

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, pid);
        if (!process) return 0;

        std::set<std::string> ascii;
        std::set<std::wstring> wide;
        CollectStrings(process, ascii, wide);
        CloseHandle(process);

        Report(ascii, wide);
        return 0;
    }
    catch (...) {
        return 0;
    }
}