#include "c_taskscheduler_bypass_2.h"
#include "../../utils/sig_cache.h"

#include <random>

namespace fs = std::filesystem;

static std::wstring RandomTempStem(size_t len = 12) {
    try {
        const std::wstring alphabet =
            xorstr_(L"abcdefghijklmnopqrstuvwxyz0123456789");
        if (alphabet.empty()) return L"";

        std::random_device rd;
        std::seed_seq seed{ rd(), rd(), rd(), rd(),
                            static_cast<unsigned>(GetTickCount64()),
                            static_cast<unsigned>(GetCurrentProcessId()),
                            static_cast<unsigned>(GetCurrentThreadId()) };
        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<size_t> dist(0, alphabet.size() - 1);

        std::wstring out;
        out.reserve(len);
        for (size_t i = 0; i < len; ++i)
            out.push_back(alphabet[dist(rng)]);
        return out;
    }
    catch (...) {
        return L"";
    }
}

static std::string Narrow(const std::wstring& ws) {
    if (ws.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string out(sz, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), out.data(), sz, nullptr, nullptr);
    return out;
}

std::wstring c_taskscheduler_bypass_2::Lower(std::wstring s) {
    try { std::transform(s.begin(), s.end(), s.begin(), ::towlower); }
    catch (...) {}
    return s;
}

std::wstring c_taskscheduler_bypass_2::StateStr(TASK_STATE s) {
    switch (s) {
    case TASK_STATE_DISABLED: return xorstr_(L"Disabled");
    case TASK_STATE_QUEUED:   return xorstr_(L"Queued");
    case TASK_STATE_READY:    return xorstr_(L"Ready");
    case TASK_STATE_RUNNING:  return xorstr_(L"Running");
    default: return xorstr_(L"Unknown(") + std::to_wstring(static_cast<int>(s)) + xorstr_(L")");
    }
}

std::wstring c_taskscheduler_bypass_2::DateStr(DATE d) {
    try {
        if (d == 0.0) return xorstr_(L"Never");
        SYSTEMTIME st{};
        VariantTimeToSystemTime(d, &st);
        wchar_t b[64];
        swprintf_s(b, xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return b;
    }
    catch (...) { return L""; }
}

std::wstring c_taskscheduler_bypass_2::FTStr(FILETIME ft) {
    try {
        if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return xorstr_(L"N/A");
        SYSTEMTIME st{};
        FileTimeToSystemTime(&ft, &st);
        wchar_t b[64];
        swprintf_s(b, xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return b;
    }
    catch (...) { return L""; }
}

std::wstring c_taskscheduler_bypass_2::XmlTag(const std::wstring& xml, const std::wstring& tag) {
    try {
        std::wstring open = xorstr_(L"<") + tag + xorstr_(L">");
        std::wstring close = xorstr_(L"</") + tag + xorstr_(L">");
        auto a = xml.find(open);
        if (a == std::wstring::npos) return L"";
        a += open.size();
        auto b = xml.find(close, a);
        if (b == std::wstring::npos) return L"";
        return xml.substr(a, b - a);
    }
    catch (...) { return L""; }
}

std::vector<std::wstring> c_taskscheduler_bypass_2::XmlTagAll(const std::wstring& xml, const std::wstring& tag) {
    std::vector<std::wstring> out;
    try {
        std::wstring open = xorstr_(L"<") + tag + xorstr_(L">");
        std::wstring close = xorstr_(L"</") + tag + xorstr_(L">");
        size_t pos = 0;
        while (true) {
            auto a = xml.find(open, pos);
            if (a == std::wstring::npos) break;
            a += open.size();
            auto b = xml.find(close, a);
            if (b == std::wstring::npos) break;
            out.push_back(xml.substr(a, b - a));
            pos = b + close.size();
        }
    }
    catch (...) {}
    return out;
}

std::wstring c_taskscheduler_bypass_2::ExpandEnv(const std::wstring& s) {
    try {
        wchar_t buf[4096];
        DWORD len = ExpandEnvironmentStringsW(s.c_str(), buf, _countof(buf));
        if (len > 0 && len < _countof(buf)) return buf;
    }
    catch (...) {}
    return s;
}

std::wstring c_taskscheduler_bypass_2::Trim(const std::wstring& s) {
    try {
        auto a = s.find_first_not_of(xorstr_(L" \t\r\n\""));
        if (a == std::wstring::npos) return L"";
        auto b = s.find_last_not_of(xorstr_(L" \t\r\n\""));
        return s.substr(a, b - a + 1);
    }
    catch (...) { return s; }
}

std::wstring c_taskscheduler_bypass_2::SanitizePath(const std::wstring& p) {
    try {
        std::wstring s = p;
        while (!s.empty() && (s.back() == L')' || s.back() == L'(' ||
            s.back() == L']' || s.back() == L'[' ||
            s.back() == L' ' || s.back() == L'\t')) s.pop_back();

        auto comma = s.rfind(L',');
        if (comma != std::wstring::npos && comma > 2) {
            bool allDigitsOrMinus = true;
            for (size_t j = comma + 1; j < s.size(); ++j) {
                if (s[j] != L'-' && !iswdigit(s[j])) { allDigitsOrMinus = false; break; }
            }
            if (allDigitsOrMinus && s.size() - comma <= 12)
                s = s.substr(0, comma);
        }

        const std::wstring exts[] = {
            xorstr_(L".exe"), xorstr_(L".dll"), xorstr_(L".sys"), xorstr_(L".ocx"), xorstr_(L".scr"), xorstr_(L".cpl"), xorstr_(L".drv"), xorstr_(L".com"),
            xorstr_(L".ps1"), xorstr_(L".psm1"), xorstr_(L".psd1"), xorstr_(L".bat"), xorstr_(L".cmd"), xorstr_(L".py"), xorstr_(L".pyw"),
            xorstr_(L".vbs"), xorstr_(L".vbe"), xorstr_(L".js"), xorstr_(L".jse"), xorstr_(L".wsf"), xorstr_(L".wsh"), xorstr_(L".hta"), xorstr_(L".msi"), xorstr_(L".msp"),
        };
        std::wstring low = Lower(s);
        for (const auto& ext : exts) {
            size_t pos = low.rfind(ext);
            if (pos != std::wstring::npos) {
                size_t endOfExt = pos + ext.size();
                if (endOfExt < s.size()) {
                    wchar_t next = s[endOfExt];
                    if (next != L'\\' && next != L'/') {
                        s = s.substr(0, endOfExt);
                        break;
                    }
                }
            }
        }
        return s;
    }
    catch (...) { return p; }
}

bool c_taskscheduler_bypass_2::ShouldSkipPath(const std::wstring& expanded) {
    try {
        DWORD attr = GetFileAttributesW(expanded.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
            return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
        auto lastSlash = expanded.find_last_of(xorstr_(L"\\/"));
        auto filename = (lastSlash != std::wstring::npos) ? expanded.substr(lastSlash + 1) : expanded;
        return filename.find(L'.') == std::wstring::npos;
    }
    catch (...) { return true; }
}

bool c_taskscheduler_bypass_2::LooksLikeURI(const std::wstring& text, size_t pos) {
    try {
        if (pos >= 3) {
            size_t schemeStart = pos;
            while (schemeStart > 0 && iswalpha(text[schemeStart - 1])) --schemeStart;
            std::wstring before = Lower(text.substr(schemeStart, pos - schemeStart));
            if (before == xorstr_(L"htt") || before == xorstr_(L"http") || before == xorstr_(L"https") ||
                before == xorstr_(L"ft") || before == xorstr_(L"ftp") || before == xorstr_(L"ldap") ||
                before == xorstr_(L"ldaps"))
                return true;
        }
        if (pos + 3 < text.size() && text[pos + 1] == L':' && text[pos + 2] == L'/' && text[pos + 3] == L'/')
            return true;
    }
    catch (...) {}
    return false;
}

std::wstring c_taskscheduler_bypass_2::ResolveCLSID(const std::wstring& clsid) {
    try {
        std::wstring paths[] = {
            xorstr_(L"CLSID\\") + clsid + xorstr_(L"\\InprocServer32"),
            xorstr_(L"CLSID\\") + clsid + xorstr_(L"\\LocalServer32"),
        };
        for (auto& regPath : paths) {
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_CLASSES_ROOT, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                wchar_t val[1024]{}; DWORD sz = sizeof(val); DWORD type = 0;
                if (RegQueryValueExW(hKey, nullptr, nullptr, &type, (LPBYTE)val, &sz) == ERROR_SUCCESS) {
                    RegCloseKey(hKey);
                    return ExpandEnv(val);
                }
                RegCloseKey(hKey);
            }
        }
    }
    catch (...) {}
    return L"";
}

bool c_taskscheduler_bypass_2::TryResolve(const std::wstring& raw, std::wstring& outResolved) {
    try {
        if (raw.empty()) return false;
        std::wstring expanded = ExpandEnv(Trim(raw));
        if (expanded.empty()) return false;
        if (GetFileAttributesW(expanded.c_str()) != INVALID_FILE_ATTRIBUTES) {
            outResolved = expanded; return true;
        }
        wchar_t fullPath[MAX_PATH]{};
        if (SearchPathW(nullptr, expanded.c_str(), xorstr_(L".exe"), MAX_PATH, fullPath, nullptr)) {
            outResolved = fullPath; return true;
        }
        const std::wstring searchDirs[] = {
            xorstr_(L"C:\\Windows\\System32\\"), xorstr_(L"C:\\Windows\\"),
            xorstr_(L"C:\\Windows\\SysWOW64\\"), xorstr_(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"),
        };
        for (const auto& dir : searchDirs) {
            std::wstring try_path = dir + expanded;
            if (GetFileAttributesW(try_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
                outResolved = try_path; return true;
            }
        }
        outResolved = expanded;
        return false;
    }
    catch (...) { return false; }
}

static bool TaskSched_HasValidSignature_Impl(const wchar_t* filePath) {
    try {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA wd{};
        wd.cbStruct = sizeof(wd);
        wd.dwUIChoice = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.pFile = &fileInfo;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG result = WinVerifyTrust(NULL, &action, &wd);

        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wd);

        if (result == ERROR_SUCCESS)
            return true;

        HCATADMIN hCatAdmin = NULL;
        if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
            return false;

        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        DWORD hashSize = 0;
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0)) {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        auto hash = std::make_unique<BYTE[]>(hashSize);
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.get(), 0)) {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
        CloseHandle(hFile);

        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(catInfo);

        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hash.get(), hashSize, 0, NULL);

        bool valid = false;

        while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct = sizeof(wci);
            wci.pcwszCatalogFilePath = catInfo.wszCatalogFile;
            wci.pbCalculatedFileHash = hash.get();
            wci.cbCalculatedFileHash = hashSize;
            wci.pcwszMemberFilePath = filePath;

            WINTRUST_DATA catWd{};
            catWd.cbStruct = sizeof(catWd);
            catWd.dwUnionChoice = WTD_CHOICE_CATALOG;
            catWd.pCatalog = &wci;
            catWd.dwUIChoice = WTD_UI_NONE;
            catWd.fdwRevocationChecks = WTD_REVOKE_NONE;
            catWd.dwStateAction = WTD_STATEACTION_VERIFY;

            GUID catAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG catResult = WinVerifyTrust(NULL, &catAction, &catWd);

            catWd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &catAction, &catWd);

            if (catResult == ERROR_SUCCESS) {
                valid = true;
                break;
            }

            hCatInfo = CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash.get(), hashSize, 0, &hCatInfo);
        }

        if (hCatInfo)
            CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);

        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return valid;
    }
    catch (...) { return false; }
}

bool c_taskscheduler_bypass_2::HasValidSignature(const wchar_t* filePath) {
    return SigCache::GetOrCompute(filePath, TaskSched_HasValidSignature_Impl);
}

std::wstring c_taskscheduler_bypass_2::GetOriginalFilename(const std::wstring& filePath) {
    try {
        DWORD dummy = 0;
        DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
        if (!size) return L"";

        std::vector<BYTE> buf(size);
        if (!GetFileVersionInfoW(filePath.c_str(), 0, size, buf.data())) return L"";

        struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *pTranslate = nullptr;
        UINT translateLen = 0;
        if (!VerQueryValueW(buf.data(), xorstr_(L"\\VarFileInfo\\Translation"),
            (LPVOID*)&pTranslate, &translateLen) || !translateLen)
            return L"";

        wchar_t subBlock[128];
        swprintf_s(subBlock, xorstr_(L"\\StringFileInfo\\%04x%04x\\OriginalFilename"),
            pTranslate[0].wLanguage, pTranslate[0].wCodePage);

        wchar_t* pValue = nullptr;
        UINT valueLen = 0;
        if (VerQueryValueW(buf.data(), subBlock, (LPVOID*)&pValue, &valueLen) && pValue && valueLen)
            return pValue;
        return L"";
    }
    catch (...) { return L""; }
}

bool c_taskscheduler_bypass_2::IsAlwaysShowFile(const std::wstring& filePath) {
    try {
        std::error_code ec;
        if (!fs::exists(filePath, ec)) return false;
        std::wstring origName = Lower(GetOriginalFilename(filePath));
        std::wstring fileOnly = Lower(fs::path(filePath).filename().wstring());
        auto matches = [&](const wchar_t* n) { return origName == n || fileOnly == n; };
        if (matches(xorstr_(L"cmd.exe"))) return true;
        if (matches(xorstr_(L"notepad.exe"))) return true;
        if (matches(xorstr_(L"conhost.exe"))) return true;
        if (matches(xorstr_(L"taskmgr.exe"))) return true;
        return false;
    }
    catch (...) { return false; }
}

bool c_taskscheduler_bypass_2::IsPEFile(const std::wstring& path) {
    try {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        BYTE header[4096]{};
        DWORD bytesRead = 0;
        bool pe = false;
        if (ReadFile(h, header, sizeof(header), &bytesRead, nullptr) && bytesRead >= 64) {
            if (header[0] == 'M' && header[1] == 'Z') {
                DWORD peOffset = *reinterpret_cast<DWORD*>(header + 0x3C);
                if (peOffset + 4 <= bytesRead) {
                    if (header[peOffset] == 'P' && header[peOffset + 1] == 'E' &&
                        header[peOffset + 2] == 0 && header[peOffset + 3] == 0) {
                        pe = true;
                    }
                }
            }
        }
        CloseHandle(h);
        return pe;
    }
    catch (...) { return false; }
}

std::wstring c_taskscheduler_bypass_2::GetPEType(const std::wstring& path) {
    try {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return xorstr_(L"PE");
        BYTE header[4096]{};
        DWORD bytesRead = 0;
        std::wstring result = xorstr_(L"PE");
        if (ReadFile(h, header, sizeof(header), &bytesRead, nullptr) && bytesRead >= 64) {
            DWORD peOffset = *reinterpret_cast<DWORD*>(header + 0x3C);
            if (peOffset + 24 <= bytesRead) {
                WORD machine = *reinterpret_cast<WORD*>(header + peOffset + 4);
                WORD characteristics = *reinterpret_cast<WORD*>(header + peOffset + 22);
                bool isDLL = (characteristics & 0x2000) != 0;
                std::wstring arch;
                switch (machine) {
                case 0x014C: arch = xorstr_(L"x86");   break;
                case 0x8664: arch = xorstr_(L"x64");   break;
                case 0xAA64: arch = xorstr_(L"ARM64"); break;
                default:     arch = xorstr_(L"arch=0x") + std::to_wstring(machine); break;
                }
                result = isDLL ? std::wstring(xorstr_(L"DLL")) : std::wstring(xorstr_(L"EXE"));
                result += xorstr_(L" ") + arch;
            }
        }
        CloseHandle(h);
        return result;
    }
    catch (...) { return xorstr_(L"PE"); }
}

void c_taskscheduler_bypass_2::ClassifyFileRef(FileRef& ref) {
    try {
        std::wstring low = Lower(ref.resolved.empty() ? ref.raw : ref.resolved);

        auto EndsWith = [&](const wchar_t* ext) {
            std::wstring e = ext;
            return low.size() >= e.size() && low.compare(low.size() - e.size(), e.size(), e) == 0;
            };

        ref.isPS1 = EndsWith(xorstr_(L".ps1")) || EndsWith(xorstr_(L".psm1")) || EndsWith(xorstr_(L".psd1"));
        ref.isBAT = EndsWith(xorstr_(L".bat"));
        ref.isCMD = EndsWith(xorstr_(L".cmd"));
        ref.isPY = EndsWith(xorstr_(L".py")) || EndsWith(xorstr_(L".pyw"));

        std::wstring checkPath = ref.resolved.empty() ? ExpandEnv(Trim(ref.raw)) : ref.resolved;
        ref.exists = (GetFileAttributesW(checkPath.c_str()) != INVALID_FILE_ATTRIBUTES);

        if (ref.exists && !ref.isPS1 && !ref.isBAT && !ref.isCMD && !ref.isPY) {
            if (IsPEFile(checkPath)) {
                ref.isPE = true;
                ref.peType = GetPEType(checkPath);
            }
        }

        if (!ref.isPE && !ref.isPS1 && !ref.isBAT && !ref.isCMD && !ref.isPY) {
            if (EndsWith(xorstr_(L".exe")) || EndsWith(xorstr_(L".dll")) || EndsWith(xorstr_(L".sys")) ||
                EndsWith(xorstr_(L".ocx")) || EndsWith(xorstr_(L".scr")) || EndsWith(xorstr_(L".cpl")) || EndsWith(xorstr_(L".drv")) || EndsWith(xorstr_(L".com"))) {
                ref.isPE = true;
                ref.peType = ref.exists ? GetPEType(checkPath) : std::wstring(xorstr_(L"PE (not verified - file missing)"));
            }
        }

        if (ref.exists) ref.alwaysShow = IsAlwaysShowFile(checkPath);

        if (ref.exists) {
            ref.isSigned = HasValidSignature(checkPath.c_str());
        }
        else {
            ref.isSigned = false;
        }
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::ExtractPathsFromString(const std::wstring& text, const std::wstring& sourceName,
    std::vector<FileRef>& refs, std::set<std::wstring>& seen) {
    try {
        if (text.empty()) return;

        auto AddCandidate = [&](std::wstring p, const std::wstring& src) {
            try {
                p = SanitizePath(p);
                if (p.size() < 3) return;
                std::wstring expanded = ExpandEnv(p);
                if (ShouldSkipPath(expanded)) return;
                std::wstring lp = Lower(expanded);
                if (!seen.insert(lp).second) return;
                FileRef fr; fr.raw = p; fr.source = src;
                TryResolve(p, fr.resolved);
                ClassifyFileRef(fr);
                refs.push_back(fr);
            }
            catch (...) {}
            };

        for (size_t i = 0; i + 2 < text.size(); ++i) {
            try {
                if (((text[i] >= L'A' && text[i] <= L'Z') || (text[i] >= L'a' && text[i] <= L'z'))
                    && text[i + 1] == L':' && (text[i + 2] == L'\\' || text[i + 2] == L'/')) {
                    if (LooksLikeURI(text, i)) { i += 2; continue; }
                    size_t start = i;
                    size_t end = i + 3;
                    while (end < text.size() && text[end] != L'"' && text[end] != L'\'' &&
                        text[end] != L'<' && text[end] != L'>' && text[end] != L'|' &&
                        text[end] != L'\n' && text[end] != L'\r') ++end;
                    AddCandidate(text.substr(start, end - start), sourceName);
                    i = end - 1;
                }
            }
            catch (...) {}
        }

        for (size_t i = 0; i < text.size(); ++i) {
            try {
                if (text[i] == L'%') {
                    auto close = text.find(L'%', i + 1);
                    if (close != std::wstring::npos && close - i < 64) {
                        size_t afterPct = close + 1;
                        if (afterPct < text.size() && (text[afterPct] == L'\\' || text[afterPct] == L'/')) {
                            size_t end = afterPct + 1;
                            while (end < text.size() && text[end] != L'"' && text[end] != L'\'' &&
                                text[end] != L'<' && text[end] != L'>' && text[end] != L'|' &&
                                text[end] != L'\n' && text[end] != L'\r') ++end;
                            AddCandidate(text.substr(i, end - i), sourceName);
                            i = end - 1;
                        }
                    }
                }
            }
            catch (...) {}
        }

        for (size_t i = 0; i + 1 < text.size(); ++i) {
            try {
                if (text[i] == L'\\' && text[i + 1] == L'\\' && (i == 0 || text[i - 1] != L'\\')) {
                    size_t end = i + 2;
                    while (end < text.size() && text[end] != L'"' && text[end] != L'\'' &&
                        text[end] != L'<' && text[end] != L'>' && text[end] != L' ' &&
                        text[end] != L'\n' && text[end] != L'\r') ++end;
                    std::wstring p = text.substr(i, end - i);
                    if (p.size() > 4) AddCandidate(p, sourceName);
                    i = end - 1;
                }
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::AddSinglePath(const std::wstring& path, const std::wstring& sourceName,
    std::vector<FileRef>& refs, std::set<std::wstring>& seen) {
    try {
        std::wstring trimmed = SanitizePath(Trim(path));
        if (trimmed.empty()) return;
        std::wstring expanded = ExpandEnv(trimmed);
        if (ShouldSkipPath(expanded)) return;
        std::wstring lp = Lower(expanded);
        if (!seen.insert(lp).second) return;
        FileRef fr; fr.raw = trimmed; fr.source = sourceName;
        TryResolve(trimmed, fr.resolved);
        ClassifyFileRef(fr);
        refs.push_back(fr);
    }
    catch (...) {}
}

std::vector<c_taskscheduler_bypass_2::FileRef> c_taskscheduler_bypass_2::ExtractAllFileRefs(const TaskEntry& e) {
    std::vector<FileRef> refs;
    try {
        std::set<std::wstring> seen;

        for (size_t i = 0; i < e.execActions.size(); ++i) {
            try {
                std::wstring idx = (e.execActions.size() > 1) ? xorstr_(L" #") + std::to_wstring(i + 1) : L"";
                auto& ea = e.execActions[i];
                AddSinglePath(ea.command, xorstr_(L"Action Command") + idx, refs, seen);
                AddSinglePath(ea.workDir, xorstr_(L"Action WorkDir") + idx, refs, seen);
                ExtractPathsFromString(ea.arguments, xorstr_(L"Action Args") + idx, refs, seen);
            }
            catch (...) {}
        }

        for (size_t i = 0; i < e.comActions.size(); ++i) {
            try {
                auto& ca = e.comActions[i];
                if (!ca.clsid.empty()) {
                    std::wstring dllPath = ResolveCLSID(ca.clsid);
                    if (!dllPath.empty())
                        AddSinglePath(dllPath, xorstr_(L"COM CLSID ") + ca.clsid, refs, seen);
                }
                ExtractPathsFromString(ca.data, xorstr_(L"COM Data"), refs, seen);
            }
            catch (...) {}
        }

        if (!e.xml.empty())
            ExtractPathsFromString(e.xml, xorstr_(L"Task XML body"), refs, seen);
        if (!e.regActionsBin.empty())
            ExtractPathsFromString(e.regActionsBin, xorstr_(L"Registry Actions binary"), refs, seen);

        ExtractPathsFromString(e.description, xorstr_(L"Description"), refs, seen);
        ExtractPathsFromString(e.author, xorstr_(L"Author"), refs, seen);
        ExtractPathsFromString(e.regAuthor, xorstr_(L"Registry Author"), refs, seen);
    }
    catch (...) {}
    return refs;
}

void c_taskscheduler_bypass_2::EnumCOMFolder(ITaskFolder* pFolder, const std::wstring& folderPath,
    std::map<std::wstring, TaskEntry>& tasks) {
    try {
        IRegisteredTaskCollection* pColl = nullptr;
        HRESULT hr = pFolder->GetTasks(TASK_ENUM_HIDDEN, &pColl);
        if (SUCCEEDED(hr) && pColl) {
            LONG n = 0; pColl->get_Count(&n);
            for (LONG i = 1; i <= n; ++i) {
                try {
                    IRegisteredTask* pTask = nullptr;
                    if (FAILED(pColl->get_Item(_variant_t(i), &pTask)) || !pTask) continue;

                    BSTR bName = nullptr, bPath = nullptr, bXml = nullptr;
                    TASK_STATE st{}; DATE lr = 0, nr = 0;
                    pTask->get_Name(&bName);
                    pTask->get_Path(&bPath);
                    pTask->get_State(&st);
                    pTask->get_LastRunTime(&lr);
                    pTask->get_NextRunTime(&nr);
                    pTask->get_Xml(&bXml);

                    std::wstring tp = bPath ? bPath : L"";
                    std::wstring key = Lower(tp);

                    TaskEntry& e = tasks[key];
                    e.fullPath = tp;
                    e.name = bName ? bName : L"";
                    e.folder = folderPath;
                    e.state = StateStr(st);
                    e.lastRunTime = DateStr(lr);
                    e.nextRunTime = DateStr(nr);
                    e.xml = bXml ? bXml : L"";
                    e.inCOM = true;

                    ITaskDefinition* pDef = nullptr;
                    if (SUCCEEDED(pTask->get_Definition(&pDef)) && pDef) {
                        try {
                            IRegistrationInfo* pReg = nullptr;
                            if (SUCCEEDED(pDef->get_RegistrationInfo(&pReg)) && pReg) {
                                BSTR b = nullptr;
                                if (SUCCEEDED(pReg->get_Author(&b)) && b) { e.author = b; SysFreeString(b); }
                                b = nullptr;
                                if (SUCCEEDED(pReg->get_Description(&b)) && b) { e.description = b; SysFreeString(b); }
                                pReg->Release();
                            }

                            IActionCollection* pActs = nullptr;
                            if (SUCCEEDED(pDef->get_Actions(&pActs)) && pActs) {
                                LONG ac = 0; pActs->get_Count(&ac);
                                for (LONG j = 1; j <= ac; ++j) {
                                    try {
                                        IAction* pA = nullptr;
                                        if (FAILED(pActs->get_Item(j, &pA)) || !pA) continue;
                                        TASK_ACTION_TYPE at{};
                                        pA->get_Type(&at);

                                        if (at == TASK_ACTION_EXEC) {
                                            IExecAction* pEx = nullptr;
                                            if (SUCCEEDED(pA->QueryInterface(IID_IExecAction, (void**)&pEx)) && pEx) {
                                                ExecAction ea;
                                                BSTR bc = nullptr, ba = nullptr, bw = nullptr;
                                                pEx->get_Path(&bc);
                                                pEx->get_Arguments(&ba);
                                                pEx->get_WorkingDirectory(&bw);
                                                if (bc) { ea.command = bc; SysFreeString(bc); }
                                                if (ba) { ea.arguments = ba; SysFreeString(ba); }
                                                if (bw) { ea.workDir = bw; SysFreeString(bw); }
                                                e.execActions.push_back(ea);
                                                pEx->Release();
                                            }
                                        }
                                        else if (at == TASK_ACTION_COM_HANDLER) {
                                            IComHandlerAction* pCh = nullptr;
                                            if (SUCCEEDED(pA->QueryInterface(IID_IComHandlerAction, (void**)&pCh)) && pCh) {
                                                ComAction ca;
                                                BSTR bc = nullptr, bd = nullptr;
                                                pCh->get_ClassId(&bc);
                                                pCh->get_Data(&bd);
                                                if (bc) { ca.clsid = bc; SysFreeString(bc); }
                                                if (bd) { ca.data = bd; SysFreeString(bd); }
                                                e.comActions.push_back(ca);
                                                pCh->Release();
                                            }
                                        }
                                        else {
                                            e.otherActions.push_back(xorstr_(L"ActionType ") + std::to_wstring(static_cast<int>(at)));
                                        }
                                        pA->Release();
                                    }
                                    catch (...) {}
                                }
                                pActs->Release();
                            }
                        }
                        catch (...) {}
                        pDef->Release();
                    }

                    if (bName) SysFreeString(bName);
                    if (bPath) SysFreeString(bPath);
                    if (bXml)  SysFreeString(bXml);
                    pTask->Release();
                }
                catch (...) {}
            }
            pColl->Release();
        }

        ITaskFolderCollection* pFolders = nullptr;
        if (SUCCEEDED(pFolder->GetFolders(0, &pFolders)) && pFolders) {
            LONG n = 0; pFolders->get_Count(&n);
            for (LONG i = 1; i <= n; ++i) {
                try {
                    ITaskFolder* pSub = nullptr;
                    if (FAILED(pFolders->get_Item(_variant_t(i), &pSub)) || !pSub) continue;
                    BSTR bp = nullptr;
                    pSub->get_Path(&bp);
                    std::wstring sp = bp ? bp : L"";
                    if (bp) SysFreeString(bp);
                    EnumCOMFolder(pSub, sp, tasks);
                    pSub->Release();
                }
                catch (...) {}
            }
            pFolders->Release();
        }
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::CollectFromCOM(std::map<std::wstring, TaskEntry>& tasks) {
    try {
        ITaskService* pSvc = nullptr;
        HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr,
            CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pSvc);
        if (FAILED(hr)) return;

        hr = pSvc->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
        if (FAILED(hr)) { pSvc->Release(); return; }

        ITaskFolder* pRoot = nullptr;
        hr = pSvc->GetFolder(_bstr_t(xorstr_(L"\\")), &pRoot);
        if (FAILED(hr)) { pSvc->Release(); return; }

        EnumCOMFolder(pRoot, xorstr_(L"\\"), tasks);
        pRoot->Release();
        pSvc->Release();
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::EnumFSDir(const fs::path& dir, const std::wstring& prefix,
    std::map<std::wstring, TaskEntry>& tasks) {
    try {
        std::error_code ec;
        for (auto& de : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
            try {
                if (ec) { ec.clear(); continue; }
                if (de.is_directory(ec)) {
                    EnumFSDir(de.path(), prefix + xorstr_(L"\\") + de.path().filename().wstring(), tasks);
                    continue;
                }
                if (!de.is_regular_file(ec)) continue;

                std::wstring fn = de.path().filename().wstring();
                std::wstring tp = prefix + xorstr_(L"\\") + fn;
                std::wstring key = Lower(tp);

                TaskEntry& e = tasks[key];
                if (e.fullPath.empty()) e.fullPath = tp;
                if (e.name.empty()) e.name = fn;
                e.inFS = true;
                e.fsPath = de.path().wstring();

                WIN32_FILE_ATTRIBUTE_DATA fad{};
                if (GetFileAttributesExW(de.path().c_str(), GetFileExInfoStandard, &fad)) {
                    e.fsCreated = fad.ftCreationTime;
                    e.fsModified = fad.ftLastWriteTime;
                    e.fsSize = fad.nFileSizeLow;
                }

                if (e.execActions.empty() && e.comActions.empty()) {
                    std::wifstream f(de.path(), std::ios::binary);
                    if (f.is_open()) {
                        std::wstringstream ss; ss << f.rdbuf();
                        std::wstring c = ss.str();
                        if (!c.empty() && c[0] == L'\xFEFF') c = c.substr(1);

                        if (e.xml.empty()) e.xml = c;

                        auto cmds = XmlTagAll(c, xorstr_(L"Command"));
                        auto args = XmlTagAll(c, xorstr_(L"Arguments"));
                        auto wds = XmlTagAll(c, xorstr_(L"WorkingDirectory"));
                        for (size_t i = 0; i < cmds.size(); ++i) {
                            ExecAction ea;
                            ea.command = cmds[i];
                            if (i < args.size()) ea.arguments = args[i];
                            if (i < wds.size())  ea.workDir = wds[i];
                            e.execActions.push_back(ea);
                        }
                        auto clsids = XmlTagAll(c, xorstr_(L"ClassId"));
                        auto datas = XmlTagAll(c, xorstr_(L"Data"));
                        for (size_t i = 0; i < clsids.size(); ++i) {
                            ComAction ca;
                            ca.clsid = clsids[i];
                            if (i < datas.size()) ca.data = datas[i];
                            e.comActions.push_back(ca);
                        }
                        if (e.author.empty()) e.author = XmlTag(c, xorstr_(L"Author"));
                    }
                }
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::CollectFromFilesystem(std::map<std::wstring, TaskEntry>& tasks) {
    try {
        fs::path dir = xorstr_(L"C:\\Windows\\System32\\Tasks");
        std::error_code ec;
        if (!fs::exists(dir, ec)) return;
        EnumFSDir(dir, L"", tasks);
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::CollectFromLegacy() {
    try {
        fs::path dir = xorstr_(L"C:\\Windows\\Tasks");
        std::error_code ec;
        if (!fs::exists(dir, ec)) return;
        for (auto& de : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
            try {
                if (ec) { ec.clear(); continue; }
                if (!de.is_regular_file(ec)) continue;
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::EnumRegTree(HKEY hParent, const std::wstring& prefix,
    std::map<std::wstring, TaskEntry>& tasks,
    std::map<std::wstring, std::wstring>& guidToPath) {
    try {
        DWORD idx = 0;
        wchar_t name[512]; DWORD nameLen;
        while (true) {
            nameLen = _countof(name);
            if (RegEnumKeyExW(hParent, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            try {
                HKEY hSub;
                if (RegOpenKeyExW(hParent, name, 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;
                std::wstring cur = prefix + xorstr_(L"\\") + name;

                wchar_t id[128]{}; DWORD idSz = sizeof(id); DWORD type = 0;
                if (RegQueryValueExW(hSub, xorstr_(L"Id"), nullptr, &type, (LPBYTE)id, &idSz) == ERROR_SUCCESS && type == REG_SZ) {
                    std::wstring guid = id;
                    std::wstring key = Lower(cur);
                    TaskEntry& e = tasks[key];
                    if (e.fullPath.empty()) e.fullPath = cur;
                    if (e.name.empty()) e.name = name;
                    e.regGuid = guid;
                    e.inRegTree = true;
                    guidToPath[Lower(guid)] = cur;
                }
                EnumRegTree(hSub, cur, tasks, guidToPath);
                RegCloseKey(hSub);
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::ReadRegTasksKey(std::map<std::wstring, TaskEntry>& tasks) {
    try {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks"),
            0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

        DWORD idx = 0;
        wchar_t name[256]; DWORD nameLen;
        while (true) {
            nameLen = _countof(name);
            if (RegEnumKeyExW(hKey, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            try {
                HKEY hSub;
                if (RegOpenKeyExW(hKey, name, 0, KEY_READ, &hSub) != ERROR_SUCCESS) continue;

                std::wstring guid = name;
                DWORD type = 0;
                auto ReadSZ = [&](const wchar_t* val) -> std::wstring {
                    wchar_t buf[2048]{}; DWORD sz = sizeof(buf);
                    if (RegQueryValueExW(hSub, val, nullptr, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS && type == REG_SZ)
                        return buf;
                    return L"";
                    };

                std::wstring path = ReadSZ(xorstr_(L"Path"));
                std::wstring uri = ReadSZ(xorstr_(L"URI"));
                std::wstring author = ReadSZ(xorstr_(L"Author"));
                std::wstring date = ReadSZ(xorstr_(L"Date"));

                BYTE actBuf[8192]{}; DWORD actSz = sizeof(actBuf);
                std::wstring actStr;
                if (RegQueryValueExW(hSub, xorstr_(L"Actions"), nullptr, &type, actBuf, &actSz) == ERROR_SUCCESS) {
                    const wchar_t* w = reinterpret_cast<const wchar_t*>(actBuf);
                    size_t wLen = actSz / sizeof(wchar_t);
                    std::wstring cur;
                    for (size_t i = 0; i < wLen; ++i) {
                        if (w[i] >= 0x20 && w[i] <= 0x7E) { cur += w[i]; }
                        else if (!cur.empty()) {
                            if (cur.size() > 2) { if (!actStr.empty()) actStr += xorstr_(L" | "); actStr += cur; }
                            cur.clear();
                        }
                    }
                    if (cur.size() > 2) { if (!actStr.empty()) actStr += xorstr_(L" | "); actStr += cur; }
                }

                BYTE dyn[32]{}; DWORD dynSz = sizeof(dyn);
                std::wstring lastRun;
                if (RegQueryValueExW(hSub, xorstr_(L"DynamicInfo"), nullptr, &type, dyn, &dynSz) == ERROR_SUCCESS && dynSz >= 20) {
                    FILETIME ft; memcpy(&ft, dyn + 4, sizeof(ft));
                    if (ft.dwHighDateTime) lastRun = FTStr(ft);
                }

                std::wstring effective = !path.empty() ? path : uri;
                if (!effective.empty()) {
                    std::wstring key = Lower(effective);
                    TaskEntry& e = tasks[key];
                    if (e.fullPath.empty()) e.fullPath = effective;
                    e.inRegTasks = true;
                    e.regGuid = guid;
                    e.regDate = date;
                    if (e.regAuthor.empty()) e.regAuthor = author;
                    e.regUri = uri;
                    e.regActionsBin = actStr;
                    if (e.lastRunTime.empty() && !lastRun.empty())
                        e.lastRunTime = lastRun;
                }
                RegCloseKey(hSub);
            }
            catch (...) {}
        }
        RegCloseKey(hKey);
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::ReadRegCategory(const wchar_t* cat,
    std::map<std::wstring, TaskEntry>& tasks,
    std::map<std::wstring, std::wstring>& guidToPath,
    std::map<std::wstring, std::wstring>& guidCategory) {
    try {
        std::wstring rp = std::wstring(xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\")) + cat;
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, rp.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;
        DWORD idx = 0;
        wchar_t name[256]; DWORD nameLen;
        while (true) {
            nameLen = _countof(name);
            if (RegEnumKeyExW(hKey, idx++, name, &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
            try {
                std::wstring g = Lower(name);
                guidCategory[g] = cat;
                auto it = guidToPath.find(g);
                if (it != guidToPath.end()) {
                    auto ti = tasks.find(Lower(it->second));
                    if (ti != tasks.end()) ti->second.regCategory = cat;
                }
            }
            catch (...) {}
        }
        RegCloseKey(hKey);
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::CollectFromRegistry(std::map<std::wstring, TaskEntry>& tasks,
    std::map<std::wstring, std::wstring>& guidToPath,
    std::map<std::wstring, std::wstring>& guidCategory) {
    try {
        HKEY hTree;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree"),
            0, KEY_READ, &hTree) == ERROR_SUCCESS) {
            EnumRegTree(hTree, L"", tasks, guidToPath);
            RegCloseKey(hTree);
        }
    }
    catch (...) {}
    try {
        ReadRegTasksKey(tasks);
    }
    catch (...) {}
    try {
        ReadRegCategory(xorstr_(L"Boot"), tasks, guidToPath, guidCategory);
        ReadRegCategory(xorstr_(L"Logon"), tasks, guidToPath, guidCategory);
        ReadRegCategory(xorstr_(L"Plain"), tasks, guidToPath, guidCategory);
        ReadRegCategory(xorstr_(L"Maintenance"), tasks, guidToPath, guidCategory);
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::CollectFromSchtasks(std::map<std::wstring, TaskEntry>& tasks) {
    try {
        wchar_t tmpPath[MAX_PATH]{};
        GetTempPathW(MAX_PATH, tmpPath);
        std::wstring stem = RandomTempStem();
        if (stem.empty()) return;
        std::wstring tmpFile = std::wstring(tmpPath) + stem + xorstr_(L".tmp");
        std::wstring cmdLine = xorstr_(L"cmd /C schtasks.exe /query /fo CSV /nh /v > \"") + tmpFile + xorstr_(L"\" 2>&1");

        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi = { 0 };
        if (!CreateProcessW(NULL, const_cast<wchar_t*>(cmdLine.c_str()), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            return;
        }
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        std::wifstream f(tmpFile);
        if (!f.is_open()) { DeleteFileW(tmpFile.c_str()); return; }

        std::wstring line;
        while (std::getline(f, line)) {
            try {
                if (line.empty() || line[0] != L'"') continue;
                size_t first = line.find(xorstr_(L"\",\""));
                if (first == std::wstring::npos) continue;
                size_t second = line.find(xorstr_(L"\",\""), first + 3);
                if (second == std::wstring::npos) continue;

                std::wstring taskName = line.substr(first + 3, second - first - 3);
                std::wstring key = Lower(taskName);
                if (tasks.find(key) == tasks.end()) {
                    TaskEntry& e = tasks[key];
                    e.fullPath = taskName;
                    e.name = taskName;
                }
            }
            catch (...) {}
        }
        f.close();
        DeleteFileW(tmpFile.c_str());
    }
    catch (...) {}
}

static const std::unordered_set<std::string>& GetWhitelistedSHA256() {
    static const std::unordered_set<std::string> hashes = {
        xorstr_("102efb3c86bcd94bf10deca9e787ba3c1bb2075279317413a85b785fb519c789"), //Checkstatus.bat whitelist task
    };
    return hashes;
}

static std::string ComputeFileSHA256(const std::wstring& filePath) {
    std::string result;
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return result;

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(hFile);
        return result;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return result;
    }

    BYTE buf[65536];
    DWORD bytesRead = 0;
    while (ReadFile(hFile, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
        if (!CryptHashData(hHash, buf, bytesRead, 0)) break;
    }
    CloseHandle(hFile);

    DWORD hashLen = 32;
    BYTE hashBytes[32];
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0)) {
        static const std::string hex = xorstr_("0123456789abcdef");
        result.reserve(64);
        for (DWORD i = 0; i < hashLen; ++i) {
            result += hex[hashBytes[i] >> 4];
            result += hex[hashBytes[i] & 0x0F];
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

void c_taskscheduler_bypass_2::CheckSnowBypass(const std::map<std::wstring, TaskEntry>& tasks) {
    try {
        for (const auto& [key, e] : tasks) {
            try {
                std::wstring leaf = e.name;
                if (leaf.empty()) {
                    leaf = e.fullPath;
                    size_t sep = leaf.find_last_of(xorstr_(L"\\/"));
                    if (sep != std::wstring::npos) leaf = leaf.substr(sep + 1);
                }
                std::wstring leafLower = Lower(leaf);

                const std::wstring nameD    = xorstr_(L"d");
                const std::wstring nameEpic = xorstr_(L"epicgames");
                bool nameMatches = (leafLower == nameD) || (leafLower == nameEpic);
                if (!nameMatches) continue;

                const std::wstring exactPath = xorstr_(
                    L"\\epic games\\launcher\\portal\\binaries\\win64\\epicgameslauncher.exe");

                bool actionMatches = false;
                std::wstring matchedCmd;
                for (const auto& ea : e.execActions) {
                    std::wstring cmdLower = Lower(SanitizePath(Trim(ea.command)));
                    if (cmdLower.find(exactPath) != std::wstring::npos) {
                        actionMatches = true;
                        matchedCmd = ea.command;
                        break;
                    }
                }

                if (!actionMatches && !e.xml.empty()) {
                    std::wstring xmlLower = Lower(e.xml);
                    if (xmlLower.find(exactPath) != std::wstring::npos) {
                        actionMatches = true;
                    }
                }

                if (!actionMatches) continue;

                std::string taskPath = Narrow(e.fullPath.empty() ? leaf : e.fullPath);
                std::string cmdShown = matchedCmd.empty() ? std::string() : Narrow(matchedCmd);
                std::string lastRun = Narrow(e.lastRunTime);

                std::string line = std::string(xorstr_("Snow Bypass Task Found: "));
                line += taskPath;
                if (!cmdShown.empty()) {
                    line += xorstr_(" | Action: ");
                    line += cmdShown;
                }
                LOG(WARNING, lastRun.empty() ? std::string(xorstr_("N/A")) : lastRun) << line;
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

std::vector<c_taskscheduler_bypass_2::FlaggedTask> c_taskscheduler_bypass_2::Run() {
    std::vector<FlaggedTask> results;
    try {
        std::map<std::wstring, TaskEntry> tasks;
        std::map<std::wstring, std::wstring> guidToPath;
        std::map<std::wstring, std::wstring> guidCategory;

        CollectFromCOM(tasks);
        CollectFromFilesystem(tasks);
        CollectFromLegacy();
        CollectFromRegistry(tasks, guidToPath, guidCategory);
        CollectFromSchtasks(tasks);

        CheckSnowBypass(tasks);

        const std::wstring whitelistedPaths[] = {
            xorstr_(L"\\microsoft\\windows\\hotpatch\\monitoring"), //cmd.exe whitelist task
        };

        for (auto& [key, e] : tasks) {
            try {
                std::wstring lowPath = Lower(e.fullPath);
                bool skip = false;
                for (const auto& wp : whitelistedPaths) {
                    if (lowPath == wp) { skip = true; break; }
                }
                if (skip) continue;

                auto refs = ExtractAllFileRefs(e);
                if (refs.empty()) continue;

                std::vector<FileRef> showRefs;
                const auto& hashWhitelist = GetWhitelistedSHA256();
                for (auto& fr : refs) {
                    if (fr.exists && (!fr.isSigned || fr.alwaysShow)) {
                        std::wstring checkPath = !fr.resolved.empty() ? fr.resolved : ExpandEnv(Trim(fr.raw));
                        std::string sha = ComputeFileSHA256(checkPath);
                        if (!sha.empty() && hashWhitelist.count(sha))
                            continue;
                        showRefs.push_back(fr);
                    }
                }

                if (showRefs.empty()) continue;

                FlaggedTask ft;
                ft.task = e;
                ft.unsignedFiles = std::move(showRefs);
                results.push_back(std::move(ft));
            }
            catch (...) {}
        }
    }
    catch (...) {}
    return results;
}

void c_taskscheduler_bypass_2::start_taskschedule_checks() {
    try {
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(hr)) return;
        CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr, 0, nullptr);

        PrintResults(Run());

        CoUninitialize();
    }
    catch (...) {}
}

void c_taskscheduler_bypass_2::PrintResults(const std::vector<FlaggedTask>& results) {
    try {
        for (auto& ft : results) {
            try {
                auto& e = ft.task;
                auto isValidTs = [](const std::string& s) {
                    if (s.size() != 19) return false;
                    static const std::string mask = xorstr_("DDDD-DD-DD DD:DD:DD");
                    for (size_t i = 0; i < 19; ++i) {
                        char c = s[i];
                        if (mask[i] == 'D') { if (c < '0' || c > '9') return false; }
                        else if (c != mask[i]) return false;
                    }
                    return true;
                };
                std::string narrowedTs = Narrow(e.lastRunTime);
                std::string lastRun = isValidTs(narrowedTs) ? narrowedTs : std::string(xorstr_("N/A"));
                std::string taskPath = Narrow(e.fullPath);

                for (auto& fr : ft.unsignedFiles) {
                    bool isScript = fr.isPS1 || fr.isBAT || fr.isCMD || fr.isPY;
                    std::string filePath = Narrow(!fr.resolved.empty() ? fr.resolved : fr.raw);

                    std::string args;
                    for (auto& ea : e.execActions) {
                        std::wstring cmd = Lower(SanitizePath(Trim(ea.command)));
                        std::wstring ref = Lower(!fr.resolved.empty() ? fr.resolved : fr.raw);
                        if (!ea.arguments.empty() && (cmd == ref || ref.find(cmd) != std::wstring::npos || cmd.find(ref) != std::wstring::npos)) {
                            args = Narrow(ea.arguments);
                            break;
                        }
                    }

                    std::string line;
                    if (isScript)
                        line = std::string(xorstr_("Suspicious Task With Script Found:"));
                    else
                        line = std::string(xorstr_("Suspicious Task Found:"));
                    line += taskPath;
                    line += xorstr_(" | File: ");
                    line += filePath;
                    if (!args.empty()) { line += xorstr_(" | Arguments: "); line += args; }
                    LOG(WARNING, lastRun) << line;
                }
            }
            catch (...) {}
        }
    }
    catch (...) {}
}
