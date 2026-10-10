#include "c_autoruns_detection.h"

static std::atomic<long> g_scanIndex{0};

std::wstring AutorunsScanner::TrimWS(const std::wstring& s)
{
    try {
        size_t a = s.find_first_not_of(xorstr_(L" \t\r\n"));
        if (a == std::wstring::npos) return std::wstring();
        size_t b = s.find_last_not_of(xorstr_(L" \t\r\n"));
        return s.substr(a, b - a + 1);
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::StripWrappingQuotes(const std::wstring& s)
{
    try {
        std::wstring t = TrimWS(s);
        if (t.size() >= 2 && t.front() == L'"' && t.back() == L'"')
            return t.substr(1, t.size() - 2);
        return t;
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::LowerCopy(const std::wstring& s)
{
    try {
        std::wstring r(s);
        for (auto& c : r) c = static_cast<wchar_t>(std::towlower(c));
        return r;
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::ExpandEnv(const std::wstring& s)
{
    try {
        if (s.empty() || s.find(L'%') == std::wstring::npos) return s;
        wchar_t buf[MAX_PATH * 4]{};
        DWORD n = ::ExpandEnvironmentStringsW(s.c_str(), buf, _countof(buf));
        if (n == 0 || n > _countof(buf)) return s;
        return std::wstring(buf);
    } catch (...) {
        return s;
    }
}

bool AutorunsScanner::StartsWithI(const std::wstring& s, const wchar_t* prefix)
{
    try {
        size_t n = wcslen(prefix);
        return s.size() >= n && _wcsnicmp(s.c_str(), prefix, n) == 0;
    } catch (...) {
        return false;
    }
}

std::wstring AutorunsScanner::GetSysDir()
{
    try {
        wchar_t buf[MAX_PATH * 2]{};
        if (::GetSystemDirectoryW(buf, _countof(buf))) return buf;
        return std::wstring();
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::GetWinDir()
{
    try {
        wchar_t buf[MAX_PATH * 2]{};
        if (::GetWindowsDirectoryW(buf, _countof(buf))) return buf;
        return std::wstring();
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::GetWow64Dir()
{
    try {
        std::wstring win = GetWinDir();
        return win.empty() ? std::wstring() : (win + xorstr_(L"\\SysWOW64"));
    } catch (...) {
        return std::wstring();
    }
}

bool AutorunsScanner::IsAbsolutePath(const std::wstring& p)
{
    try {
        if (p.size() >= 2 && p[1] == L':') return true;
        if (p.size() >= 2 && p[0] == L'\\' && p[1] == L'\\') return true;
        return false;
    } catch (...) {
        return false;
    }
}

std::wstring AutorunsScanner::NormalizeImagePath(const std::wstring& raw)
{
    try {
        if (raw.empty()) return std::wstring();
        std::wstring p = StripWrappingQuotes(TrimWS(raw));
        if (p.empty()) return std::wstring();

        p = ExpandEnv(p);

        if (StartsWithI(p, xorstr_(L"\\??\\")))        p = p.substr(4);
        else if (StartsWithI(p, xorstr_(L"\\\\?\\")))  p = p.substr(4);

        if (StartsWithI(p, xorstr_(L"\\SystemRoot\\")))
            p = GetWinDir() + xorstr_(L"\\") + p.substr(wcslen(xorstr_(L"\\SystemRoot\\")));
        else if (StartsWithI(p, xorstr_(L"SystemRoot\\")))
            p = GetWinDir() + xorstr_(L"\\") + p.substr(wcslen(xorstr_(L"SystemRoot\\")));

        p = ExpandEnv(p);

        if (::PathFileExistsW(p.c_str())) return p;
        if (IsAbsolutePath(p)) return p;

        if (StartsWithI(p, xorstr_(L"system32\\"))) {
            std::wstring s = GetSysDir() + xorstr_(L"\\") + p.substr(wcslen(xorstr_(L"system32\\")));
            if (::PathFileExistsW(s.c_str())) return s;
            p = s;
        } else if (StartsWithI(p, xorstr_(L"drivers\\"))) {
            std::wstring s = GetSysDir() + xorstr_(L"\\drivers\\") + p.substr(wcslen(xorstr_(L"drivers\\")));
            if (::PathFileExistsW(s.c_str())) return s;
            p = s;
        } else if (StartsWithI(p, xorstr_(L"syswow64\\"))) {
            std::wstring s = GetWow64Dir() + xorstr_(L"\\") + p.substr(wcslen(xorstr_(L"syswow64\\")));
            if (::PathFileExistsW(s.c_str())) return s;
            p = s;
        }
        if (::PathFileExistsW(p.c_str())) return p;
        if (IsAbsolutePath(p)) return p;

        wchar_t resolved[MAX_PATH * 2]{};
        if (::SearchPathW(nullptr, p.c_str(), nullptr, _countof(resolved), resolved, nullptr) > 0)
            return resolved;

        std::wstring sys = GetSysDir();
        std::wstring win = GetWinDir();
        std::wstring sw  = GetWow64Dir();

        auto tryExact = [&](const std::wstring& dir) -> std::wstring {
            if (dir.empty()) return std::wstring();
            std::wstring f = dir + xorstr_(L"\\") + p;
            if (::PathFileExistsW(f.c_str())) return f;
            return std::wstring();
        };
        auto tryWithExts = [&](const std::wstring& dir) -> std::wstring {
            if (dir.empty()) return std::wstring();
            size_t dot = p.find_last_of(L'.');
            size_t sep = p.find_last_of(xorstr_(L"\\/"));
            bool hasExt = (dot != std::wstring::npos) && (sep == std::wstring::npos || dot > sep);
            if (hasExt) return std::wstring();
            const std::wstring exts[] = {
                xorstr_(L".dll"), xorstr_(L".exe"), xorstr_(L".sys"),
                xorstr_(L".cpl"), xorstr_(L".ocx"), xorstr_(L".drv"),
            };
            for (const std::wstring& ext : exts) {
                std::wstring f = dir + xorstr_(L"\\") + p + ext;
                if (::PathFileExistsW(f.c_str())) return f;
            }
            return std::wstring();
        };

        for (const std::wstring* d : { &sys, &win, &sw }) {
            if (auto f = tryExact(*d);    !f.empty()) return f;
            if (auto f = tryWithExts(*d); !f.empty()) return f;
        }
        if (!sys.empty()) {
            std::wstring driversDir = sys + xorstr_(L"\\drivers");
            if (auto f = tryExact(driversDir);    !f.empty()) return f;
            if (auto f = tryWithExts(driversDir); !f.empty()) return f;
        }

        return p;
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::ExtractRundll32Target(const std::wstring& cmd)
{
    try {
        std::wstring low = LowerCopy(cmd);
        const std::wstring kRundll32 = xorstr_(L"rundll32");
        const std::wstring kDotExe   = xorstr_(L".exe");
        size_t pos = low.find(kRundll32);
        if (pos == std::wstring::npos) return std::wstring();
        size_t end = low.find(kDotExe, pos);
        if (end == std::wstring::npos) end = pos + kRundll32.size();
        else                            end += kDotExe.size();
        std::wstring rest = TrimWS(cmd.substr(end));
        rest = StripWrappingQuotes(rest);
        size_t comma = rest.find(L',');
        if (comma != std::wstring::npos) rest = rest.substr(0, comma);
        return TrimWS(StripWrappingQuotes(rest));
    } catch (...) {
        return std::wstring();
    }
}

std::wstring AutorunsScanner::ResolveImagePath(const std::wstring& rawCommand)
{
    try {
        if (rawCommand.empty()) return std::wstring();

        std::wstring cmd = TrimWS(rawCommand);

        {
            std::wstring low = LowerCopy(cmd);
            if (low.find(xorstr_(L"rundll32")) != std::wstring::npos) {
                std::wstring tgt = ExtractRundll32Target(cmd);
                if (!tgt.empty())
                    return NormalizeImagePath(tgt);
            }
        }

        if (!cmd.empty() && cmd.front() == L'"') {
            size_t close = cmd.find(L'"', 1);
            if (close != std::wstring::npos)
                return NormalizeImagePath(cmd.substr(1, close - 1));
        }

        std::wstring expanded = ExpandEnv(cmd);
        if (::PathFileExistsW(expanded.c_str())) return expanded;

        size_t pos = expanded.size();
        while ((pos = expanded.find_last_of(L' ', pos - 1)) != std::wstring::npos) {
            std::wstring candidate = TrimWS(expanded.substr(0, pos));
            if (!candidate.empty() && ::PathFileExistsW(candidate.c_str()))
                return candidate;
            if (pos == 0) break;
        }

        size_t sp = expanded.find_first_of(xorstr_(L" \t"));
        std::wstring exe = (sp == std::wstring::npos) ? expanded : expanded.substr(0, sp);
        return NormalizeImagePath(exe);
    } catch (...) {
        return std::wstring();
    }
}

bool AutorunsScanner::FileExistsOnDisk(const std::wstring& path)
{
    try {
        if (path.empty()) return false;
        std::wstring norm = NormalizeImagePath(path);
        return ::PathFileExistsW(norm.c_str()) ? true : false;
    } catch (...) {
        return false;
    }
}

bool AutorunsScanner::IsDirectoryOnDisk(const std::wstring& path)
{
    try {
        if (path.empty()) return false;
        std::wstring norm = NormalizeImagePath(path);
        if (norm.empty()) return false;
        DWORD attrs = ::GetFileAttributesW(norm.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) return false;
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0;
    } catch (...) {
        return false;
    }
}

bool AutorunsScanner::HasValidSignature(const wchar_t* filePath)
{
    try {
        if (!filePath || !*filePath) return false;
        std::wstring normalized = NormalizeImagePath(filePath);
        if (normalized.empty()) return false;
        filePath = normalized.c_str();

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct      = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA wd{};
        wd.cbStruct            = sizeof(wd);
        wd.dwUIChoice          = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice       = WTD_CHOICE_FILE;
        wd.pFile               = &fileInfo;
        wd.dwStateAction       = WTD_STATEACTION_VERIFY;

        LONG result = ::WinVerifyTrust(NULL, &action, &wd);
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(NULL, &action, &wd);

        if (result == ERROR_SUCCESS) return true;

        HCATADMIN hCatAdmin = NULL;
        if (!::CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
            return false;

        HANDLE hFile = ::CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            ::CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }

        DWORD hashSize = 0;
        if (!::CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, NULL, 0)) {
            ::CloseHandle(hFile);
            ::CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
        std::vector<BYTE> hash(hashSize);
        if (!::CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
            ::CloseHandle(hFile);
            ::CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
        ::CloseHandle(hFile);

        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(catInfo);
        HCATINFO hCatInfo = ::CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hash.data(), hashSize, 0, NULL);

        bool valid = false;
        while (hCatInfo && ::CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            WINTRUST_CATALOG_INFO wci{};
            wci.cbStruct              = sizeof(wci);
            wci.pcwszCatalogFilePath  = catInfo.wszCatalogFile;
            wci.pbCalculatedFileHash  = hash.data();
            wci.cbCalculatedFileHash  = hashSize;
            wci.pcwszMemberFilePath   = filePath;

            WINTRUST_DATA catWd{};
            catWd.cbStruct            = sizeof(catWd);
            catWd.dwUnionChoice       = WTD_CHOICE_CATALOG;
            catWd.pCatalog            = &wci;
            catWd.dwUIChoice          = WTD_UI_NONE;
            catWd.fdwRevocationChecks = WTD_REVOKE_NONE;
            catWd.dwStateAction       = WTD_STATEACTION_VERIFY;

            GUID catAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG catResult = ::WinVerifyTrust(NULL, &catAction, &catWd);
            catWd.dwStateAction = WTD_STATEACTION_CLOSE;
            ::WinVerifyTrust(NULL, &catAction, &catWd);

            if (catResult == ERROR_SUCCESS) {
                valid = true;
                break;
            }

            hCatInfo = ::CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash.data(), hashSize, 0, &hCatInfo);
        }

        if (hCatInfo)
            ::CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        ::CryptCATAdminReleaseContext(hCatAdmin, 0);

        return valid;
    } catch (...) {
        return false;
    }
}

std::wstring AutorunsScanner::GetOriginalFilename(const std::wstring& filePath)
{
    try {
        if (filePath.empty()) return std::wstring();
        DWORD dummy = 0;
        DWORD size = ::GetFileVersionInfoSizeW(filePath.c_str(), &dummy);
        if (!size) return std::wstring();

        std::vector<BYTE> buf(size);
        if (!::GetFileVersionInfoW(filePath.c_str(), 0, size, buf.data()))
            return std::wstring();

        struct LANGANDCODEPAGE { WORD wLanguage; WORD wCodePage; } *pTranslate = nullptr;
        UINT translateLen = 0;
        if (!::VerQueryValueW(buf.data(), xorstr_(L"\\VarFileInfo\\Translation"),
                reinterpret_cast<LPVOID*>(&pTranslate), &translateLen) || !translateLen)
            return std::wstring();

        wchar_t subBlock[128];
        _snwprintf_s(subBlock, _countof(subBlock), _TRUNCATE,
            xorstr_(L"\\StringFileInfo\\%04x%04x\\OriginalFilename"),
            pTranslate[0].wLanguage, pTranslate[0].wCodePage);

        wchar_t* pValue = nullptr;
        UINT valueLen = 0;
        if (::VerQueryValueW(buf.data(), subBlock,
                reinterpret_cast<LPVOID*>(&pValue), &valueLen) && pValue && valueLen)
            return std::wstring(pValue);
        return std::wstring();
    } catch (...) {
        return std::wstring();
    }
}

bool AutorunsScanner::IsAlwaysShowFile(const std::wstring& filePath)
{
    try {
        if (filePath.empty()) return false;
        if (!FileExistsOnDisk(filePath)) return false;

        std::wstring origName = LowerCopy(GetOriginalFilename(filePath));

        std::wstring fileOnly = filePath;
        size_t slash = fileOnly.find_last_of(xorstr_(L"\\/"));
        if (slash != std::wstring::npos) fileOnly = fileOnly.substr(slash + 1);
        fileOnly = LowerCopy(fileOnly);

        auto matches = [&](const wchar_t* n) {
            return origName == n || fileOnly == n;
        };
        if (matches(xorstr_(L"cmd.exe")))     return true;
        if (matches(xorstr_(L"notepad.exe"))) return true;
        if (matches(xorstr_(L"conhost.exe"))) return true;
        if (matches(xorstr_(L"taskmgr.exe"))) return true;
        return false;
    } catch (...) {
        return false;
    }
}

bool AutorunsScanner::ReadRegString(HKEY root, const wchar_t* sub, const wchar_t* name,
                                    std::wstring& out, REGSAM extra)
{
    try {
        HKEY hk;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ | extra, &hk) != ERROR_SUCCESS)
            return false;
        DWORD type = 0, size = 0;
        if (::RegQueryValueExW(hk, name, nullptr, &type, nullptr, &size) != ERROR_SUCCESS || size == 0) {
            ::RegCloseKey(hk);
            return false;
        }
        std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
        if (::RegQueryValueExW(hk, name, nullptr, &type,
                reinterpret_cast<LPBYTE>(buf.data()), &size) != ERROR_SUCCESS) {
            ::RegCloseKey(hk);
            return false;
        }
        ::RegCloseKey(hk);
        while (!buf.empty() && buf.back() == L'\0') buf.pop_back();
        out = buf;
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<std::wstring> AutorunsScanner::ReadRegMultiSz(HKEY root, const wchar_t* sub,
                                                          const wchar_t* name, REGSAM extra)
{
    std::vector<std::wstring> out;
    try {
        HKEY hk;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ | extra, &hk) != ERROR_SUCCESS)
            return out;
        DWORD type = 0, size = 0;
        if (::RegQueryValueExW(hk, name, nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size > 0) {
            std::wstring buf(size / sizeof(wchar_t) + 1, L'\0');
            if (::RegQueryValueExW(hk, name, nullptr, &type,
                    reinterpret_cast<LPBYTE>(buf.data()), &size) == ERROR_SUCCESS) {
                const wchar_t* p = buf.c_str();
                const wchar_t* end = p + (size / sizeof(wchar_t));
                while (p < end && *p) {
                    std::wstring s = p;
                    if (!s.empty()) out.push_back(std::move(s));
                    p += wcslen(p) + 1;
                }
            }
        }
        ::RegCloseKey(hk);
        return out;
    } catch (...) {
        return out;
    }
}

FILETIME AutorunsScanner::GetKeyTime(HKEY root, const wchar_t* sub, REGSAM extra)
{
    FILETIME ft{};
    try {
        HKEY hk;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ | extra, &hk) != ERROR_SUCCESS)
            return ft;
        ::RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, &ft);
        ::RegCloseKey(hk);
        return ft;
    } catch (...) {
        return ft;
    }
}

ULONGLONG AutorunsScanner::FileTimeToU64(const FILETIME& ft)
{
    try {
        return (static_cast<ULONGLONG>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
    } catch (...) {
        return 0;
    }
}

std::wstring AutorunsScanner::ResolveClsidPath(const std::wstring& clsid)
{
    try {
        if (clsid.empty()) return std::wstring();
        auto tryKey = [&](const wchar_t* prefix, const wchar_t* tail) -> std::wstring {
            std::wstring sub = std::wstring(prefix) + clsid + tail;
            std::wstring v;
            if (ReadRegString(HKEY_CLASSES_ROOT, sub.c_str(), L"", v, 0) && !v.empty())
                return NormalizeImagePath(v);
            return std::wstring();
        };
        std::wstring r;
        if (r = tryKey(xorstr_(L"CLSID\\"),              xorstr_(L"\\InprocServer32")); !r.empty()) return r;
        if (r = tryKey(xorstr_(L"CLSID\\"),              xorstr_(L"\\LocalServer32"));  !r.empty()) return r;
        if (r = tryKey(xorstr_(L"Wow6432Node\\CLSID\\"), xorstr_(L"\\InprocServer32")); !r.empty()) return r;
        if (r = tryKey(xorstr_(L"Wow6432Node\\CLSID\\"), xorstr_(L"\\LocalServer32"));  !r.empty()) return r;
        return std::wstring();
    } catch (...) {
        return std::wstring();
    }
}

void AutorunsScanner::EnumRunStyleKey(HKEY root, const wchar_t* sub,
                                       std::vector<AutorunEntry>& out, REGSAM extra)
{
    try {
        HKEY hk;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ | extra, &hk) != ERROR_SUCCESS)
            return;
        FILETIME keyTime{};
        ::RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, &keyTime);

        DWORD idx = 0;
        wchar_t  nameBuf[512];
        std::vector<BYTE> dataBuf(8192);
        for (;;) {
            DWORD nameLen = _countof(nameBuf);
            DWORD dataLen = static_cast<DWORD>(dataBuf.size());
            DWORD type    = 0;
            LONG r = ::RegEnumValueW(hk, idx++, nameBuf, &nameLen,
                nullptr, &type, dataBuf.data(), &dataLen);
            if (r == ERROR_MORE_DATA) {
                dataBuf.resize(dataLen);
                --idx;
                continue;
            }
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

            std::wstring cmd(reinterpret_cast<wchar_t*>(dataBuf.data()), dataLen / sizeof(wchar_t));
            while (!cmd.empty() && cmd.back() == L'\0') cmd.pop_back();
            if (cmd.empty()) continue;

            AutorunEntry e;
            e.imagePath    = ResolveImagePath(cmd);
            e.rawTimestamp = FileTimeToU64(keyTime);
            out.push_back(std::move(e));
        }
        ::RegCloseKey(hk);
    } catch (...) {
    }
}

std::wstring AutorunsScanner::ResolveLnkTarget(const std::wstring& lnkPath)
{
    try {
        IShellLinkW* psl = nullptr;
        if (FAILED(::CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER,
                IID_IShellLinkW, reinterpret_cast<void**>(&psl))) || !psl)
            return std::wstring();

        std::wstring target;
        IPersistFile* ppf = nullptr;
        if (SUCCEEDED(psl->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&ppf))) && ppf) {
            if (SUCCEEDED(ppf->Load(lnkPath.c_str(), STGM_READ))) {
                psl->Resolve(nullptr, SLR_NO_UI | SLR_NOSEARCH | SLR_NOTRACK | SLR_NOLINKINFO);
                wchar_t pathBuf[MAX_PATH * 2]{};
                WIN32_FIND_DATAW wfd{};
                if (SUCCEEDED(psl->GetPath(pathBuf, _countof(pathBuf), &wfd, SLGP_RAWPATH)) && pathBuf[0])
                    target = pathBuf;
            }
            ppf->Release();
        }
        psl->Release();
        return target;
    } catch (...) {
        return std::wstring();
    }
}

void AutorunsScanner::EnumStartupFolder(int csidl, std::vector<AutorunEntry>& out)
{
    try {
        wchar_t folder[MAX_PATH * 2]{};
        if (!SUCCEEDED(::SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, folder)) || !folder[0])
            return;

        std::wstring pattern = std::wstring(folder) + xorstr_(L"\\*");
        WIN32_FIND_DATAW wfd{};
        HANDLE h = ::FindFirstFileW(pattern.c_str(), &wfd);
        if (h == INVALID_HANDLE_VALUE) return;
        do {
            if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring name = wfd.cFileName;
            if (name == xorstr_(L".") || name == xorstr_(L"..")) continue;
            if (name == xorstr_(L"desktop.ini")) continue;

            std::wstring full = std::wstring(folder) + xorstr_(L"\\") + name;
            std::wstring image = full;

            std::wstring low(name);
            for (auto& c : low) c = static_cast<wchar_t>(std::towlower(c));
            if (low.size() >= 4 && low.compare(low.size() - 4, 4, xorstr_(L".lnk")) == 0) {
                std::wstring tgt = ResolveLnkTarget(full);
                if (!tgt.empty()) image = tgt;
            }

            AutorunEntry e;
            e.imagePath    = image;
            e.rawTimestamp = FileTimeToU64(wfd.ftLastWriteTime);
            out.push_back(std::move(e));
        } while (::FindNextFileW(h, &wfd));
        ::FindClose(h);
    } catch (...) {
    }
}

void AutorunsScanner::EnumClsidSubkeys(HKEY root, const wchar_t* sub, std::vector<AutorunEntry>& out)
{
    try {
        HKEY hk;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
        DWORD i = 0;
        wchar_t name[256];
        for (;;) {
            DWORD len = _countof(name);
            FILETIME ft{};
            LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;

            std::wstring clsid = name;
            AutorunEntry e;
            e.imagePath    = ResolveClsidPath(clsid);
            e.rawTimestamp = FileTimeToU64(ft);
            out.push_back(std::move(e));
        }
        ::RegCloseKey(hk);
    } catch (...) {
    }
}

void AutorunsScanner::EnumClsidValueNames(HKEY root, const wchar_t* sub, std::vector<AutorunEntry>& out)
{
    try {
        HKEY hk;
        if (::RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
        FILETIME ft{};
        ::RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, &ft);

        DWORD i = 0;
        wchar_t name[256];
        for (;;) {
            DWORD len = _countof(name);
            LONG r = ::RegEnumValueW(hk, i++, name, &len, nullptr, nullptr, nullptr, nullptr);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (!name[0]) continue;
            std::wstring clsid = name;
            AutorunEntry e;
            e.imagePath    = ResolveClsidPath(clsid);
            e.rawTimestamp = FileTimeToU64(ft);
            out.push_back(std::move(e));
        }
        ::RegCloseKey(hk);
    } catch (...) {
    }
}

void AutorunsScanner::ScanLogon(std::vector<AutorunEntry>& out)
{
    try {
        struct RunKey { HKEY root; std::wstring sub; REGSAM extra; };
        const RunKey runKeys[] = {
            { HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),          0 },
            { HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),      0 },
            { HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"),    0 },
            { HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"),     0 },
            { HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"), 0 },
            { HKEY_CURRENT_USER,  xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),          0 },
            { HKEY_CURRENT_USER,  xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),      0 },
            { HKEY_LOCAL_MACHINE, xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"), 0 },
            { HKEY_CURRENT_USER,  xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"), 0 },
        };
        for (const auto& k : runKeys)
            EnumRunStyleKey(k.root, k.sub.c_str(), out, k.extra);

        const std::wstring winlogon = xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        FILETIME wt = GetKeyTime(HKEY_LOCAL_MACHINE, winlogon.c_str(), 0);
        const std::wstring names[] = { xorstr_(L"Userinit"), xorstr_(L"Shell") };
        for (const std::wstring& n : names) {
            std::wstring v;
            if (ReadRegString(HKEY_LOCAL_MACHINE, winlogon.c_str(), n.c_str(), v, 0) && !v.empty()) {
                std::wstring first = v;
                if (size_t c = first.find(L','); c != std::wstring::npos)
                    first = first.substr(0, c);
                AutorunEntry e;
                e.imagePath    = ResolveImagePath(first);
                e.rawTimestamp = FileTimeToU64(wt);
                out.push_back(std::move(e));
            }
        }

        EnumStartupFolder(CSIDL_STARTUP,        out);
        EnumStartupFolder(CSIDL_COMMON_STARTUP, out);

        static const std::wstring asKey = xorstr_(L"Software\\Microsoft\\Active Setup\\Installed Components");
        HKEY hkAS;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, asKey.c_str(), 0, KEY_READ, &hkAS) == ERROR_SUCCESS) {
            DWORD i = 0;
            wchar_t subName[256];
            for (;;) {
                DWORD len = _countof(subName);
                FILETIME ft{};
                LONG r = ::RegEnumKeyExW(hkAS, i++, subName, &len, nullptr, nullptr, nullptr, &ft);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                std::wstring sub = asKey + xorstr_(L"\\") + subName;
                std::wstring stub;
                if (!ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"StubPath"), stub, 0) || stub.empty())
                    continue;
                AutorunEntry e;
                e.imagePath    = ResolveImagePath(stub);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
            ::RegCloseKey(hkAS);
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanExplorer(std::vector<AutorunEntry>& out)
{
    try {
        EnumClsidValueNames(HKEY_LOCAL_MACHINE,
            xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"), out);
        EnumClsidValueNames(HKEY_LOCAL_MACHINE,
            xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellExecuteHooks"), out);

        EnumClsidSubkeys(HKEY_LOCAL_MACHINE,
            xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"), out);
        EnumClsidSubkeys(HKEY_LOCAL_MACHINE,
            xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects"), out);

        EnumClsidSubkeys(HKEY_LOCAL_MACHINE,
            xorstr_(L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers"), out);

        static const std::wstring ctxRoots[] = {
            xorstr_(L"*\\ShellEx\\ContextMenuHandlers"),
            xorstr_(L"AllFilesystemObjects\\ShellEx\\ContextMenuHandlers"),
            xorstr_(L"Directory\\ShellEx\\ContextMenuHandlers"),
            xorstr_(L"Directory\\Background\\ShellEx\\ContextMenuHandlers"),
            xorstr_(L"Folder\\ShellEx\\ContextMenuHandlers"),
            xorstr_(L"Drive\\ShellEx\\ContextMenuHandlers"),
        };
        for (const std::wstring& sub : ctxRoots) {
            HKEY hk;
            if (::RegOpenKeyExW(HKEY_CLASSES_ROOT, sub.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
            DWORD i = 0;
            wchar_t name[256];
            for (;;) {
                DWORD len = _countof(name);
                FILETIME ft{};
                LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;

                std::wstring keySub = sub + xorstr_(L"\\") + name;
                std::wstring defVal;
                ReadRegString(HKEY_CLASSES_ROOT, keySub.c_str(), L"", defVal, 0);
                std::wstring clsid;
                if (!defVal.empty() && defVal.front() == L'{')
                    clsid = defVal;
                else
                    clsid = name;
                AutorunEntry e;
                e.imagePath    = ResolveClsidPath(clsid);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
            ::RegCloseKey(hk);
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanInternetExplorer(std::vector<AutorunEntry>& out)
{
    try {
        HKEY hk;
        static const std::wstring tbKey = xorstr_(L"Software\\Microsoft\\Internet Explorer\\Toolbar");
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, tbKey.c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            FILETIME ft{};
            ::RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, &ft);
            DWORD i = 0;
            wchar_t name[256];
            for (;;) {
                DWORD len = _countof(name);
                LONG r = ::RegEnumValueW(hk, i++, name, &len, nullptr, nullptr, nullptr, nullptr);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                if (!name[0]) continue;
                std::wstring clsid = name;
                AutorunEntry e;
                e.imagePath    = ResolveClsidPath(clsid);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
            ::RegCloseKey(hk);
        }

        static const std::wstring extKey = xorstr_(L"Software\\Microsoft\\Internet Explorer\\Extensions");
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, extKey.c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            DWORD i = 0;
            wchar_t name[256];
            for (;;) {
                DWORD len = _countof(name);
                FILETIME ft{};
                LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                std::wstring sub = extKey + xorstr_(L"\\") + name;
                std::wstring exec;
                if (!ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"Exec"), exec, 0)) {
                    ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"Script"), exec, 0);
                }
                std::wstring clsidStr = name;
                AutorunEntry e;
                e.imagePath    = exec.empty() ? ResolveClsidPath(clsidStr) : ResolveImagePath(exec);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
            ::RegCloseKey(hk);
        }
    } catch (...) {
    }
}

void AutorunsScanner::EnumTaskFolder(void* folderPtr, std::vector<AutorunEntry>& out)
{
    try {
        ITaskFolder* folder = reinterpret_cast<ITaskFolder*>(folderPtr);
        if (!folder) return;
        IRegisteredTaskCollection* tasks = nullptr;
        if (SUCCEEDED(folder->GetTasks(TASK_ENUM_HIDDEN, &tasks)) && tasks) {
            LONG cnt = 0;
            tasks->get_Count(&cnt);
            for (LONG i = 1; i <= cnt; i++) {
                IRegisteredTask* task = nullptr;
                VARIANT vIdx;
                vIdx.vt = VT_I4;
                vIdx.lVal = i;
                if (FAILED(tasks->get_Item(vIdx, &task)) || !task) continue;

                DATE   lastRunVar = 0; task->get_LastRunTime(&lastRunVar);

                BSTR taskPath = nullptr;
                task->get_Path(&taskPath);

                ITaskDefinition* def = nullptr;
                BSTR exePath = nullptr;
                BSTR exeArgs = nullptr;
                if (SUCCEEDED(task->get_Definition(&def)) && def) {
                    IActionCollection* actions = nullptr;
                    if (SUCCEEDED(def->get_Actions(&actions)) && actions) {
                        LONG aCnt = 0;
                        actions->get_Count(&aCnt);
                        for (LONG j = 1; j <= aCnt; j++) {
                            IAction* a = nullptr;
                            if (FAILED(actions->get_Item(j, &a)) || !a) continue;
                            TASK_ACTION_TYPE ty;
                            a->get_Type(&ty);
                            if (ty == TASK_ACTION_EXEC) {
                                IExecAction* ex = nullptr;
                                if (SUCCEEDED(a->QueryInterface(IID_IExecAction,
                                        reinterpret_cast<void**>(&ex))) && ex) {
                                    if (!exePath) ex->get_Path(&exePath);
                                    if (!exeArgs) ex->get_Arguments(&exeArgs);
                                    ex->Release();
                                }
                            }
                            a->Release();
                            if (exePath) break;
                        }
                        actions->Release();
                    }
                    def->Release();
                }

                AutorunEntry e;
                e.imagePath = exePath ? ResolveImagePath(exePath) : std::wstring();
                e.source    = taskPath ? std::wstring(taskPath) : std::wstring();
                if (lastRunVar > 0.0) {
                    SYSTEMTIME st{};
                    if (::VariantTimeToSystemTime(lastRunVar, &st)) {
                        FILETIME ft{};
                        ::SystemTimeToFileTime(&st, &ft);
                        FILETIME utc{};
                        ::LocalFileTimeToFileTime(&ft, &utc);
                        e.rawTimestamp = FileTimeToU64(utc);
                    }
                }
                out.push_back(std::move(e));

                if (taskPath) ::SysFreeString(taskPath);
                if (exePath)  ::SysFreeString(exePath);
                if (exeArgs)  ::SysFreeString(exeArgs);
                task->Release();
            }
            tasks->Release();
        }

        ITaskFolderCollection* subs = nullptr;
        if (SUCCEEDED(folder->GetFolders(0, &subs)) && subs) {
            LONG cnt = 0;
            subs->get_Count(&cnt);
            for (LONG i = 1; i <= cnt; i++) {
                ITaskFolder* sub = nullptr;
                VARIANT vIdx;
                vIdx.vt = VT_I4;
                vIdx.lVal = i;
                if (SUCCEEDED(subs->get_Item(vIdx, &sub)) && sub) {
                    EnumTaskFolder(sub, out);
                    sub->Release();
                }
            }
            subs->Release();
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanScheduledTasks(std::vector<AutorunEntry>& out)
{
    try {
        ITaskService* svc = nullptr;
        if (FAILED(::CoCreateInstance(CLSID_TaskScheduler, nullptr,
                CLSCTX_INPROC_SERVER, IID_ITaskService,
                reinterpret_cast<void**>(&svc))) || !svc)
            return;
        VARIANT v;  ::VariantInit(&v);
        if (SUCCEEDED(svc->Connect(v, v, v, v))) {
            ITaskFolder* root = nullptr;
            BSTR rootPath = ::SysAllocString(xorstr_(L"\\"));
            if (SUCCEEDED(svc->GetFolder(rootPath, &root)) && root) {
                EnumTaskFolder(root, out);
                root->Release();
            }
            if (rootPath) ::SysFreeString(rootPath);
        }
        svc->Release();
    } catch (...) {
    }
}

void AutorunsScanner::ScanServicesAndDrivers(std::vector<AutorunEntry>& out)
{
    try {
        SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr,
            SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
        if (!scm) return;

        auto pull = [&](DWORD typeMask) {
            try {
                DWORD bytesNeeded = 0, servicesReturned = 0, resume = 0;
                ::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, typeMask,
                    SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &servicesReturned,
                    &resume, nullptr);
                if (bytesNeeded == 0) return;
                std::vector<BYTE> buf(bytesNeeded);
                if (!::EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, typeMask,
                        SERVICE_STATE_ALL, buf.data(), bytesNeeded, &bytesNeeded,
                        &servicesReturned, &resume, nullptr))
                    return;
                auto* svcs = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
                for (DWORD i = 0; i < servicesReturned; i++) {
                    SC_HANDLE h = ::OpenServiceW(scm, svcs[i].lpServiceName, SERVICE_QUERY_CONFIG);
                    if (!h) continue;
                    DWORD cfgBytes = 0;
                    ::QueryServiceConfigW(h, nullptr, 0, &cfgBytes);
                    if (cfgBytes == 0) { ::CloseServiceHandle(h); continue; }
                    std::vector<BYTE> cfgBuf(cfgBytes);
                    auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());
                    if (!::QueryServiceConfigW(h, cfg, cfgBytes, &cfgBytes)) {
                        ::CloseServiceHandle(h); continue;
                    }
                    if (cfg->dwStartType != SERVICE_AUTO_START &&
                        cfg->dwStartType != SERVICE_BOOT_START &&
                        cfg->dwStartType != SERVICE_SYSTEM_START) {
                        ::CloseServiceHandle(h);
                        continue;
                    }

                    AutorunEntry e;
                    std::wstring cmd = cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"";
                    e.imagePath   = ResolveImagePath(cmd);
                    FILETIME ft = GetKeyTime(HKEY_LOCAL_MACHINE,
                        (std::wstring(xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\"))
                         + svcs[i].lpServiceName).c_str(), 0);
                    e.rawTimestamp = FileTimeToU64(ft);
                    out.push_back(std::move(e));

                    ::CloseServiceHandle(h);
                }
            } catch (...) {
            }
        };
        pull(SERVICE_WIN32);
        pull(SERVICE_DRIVER);

        ::CloseServiceHandle(scm);
    } catch (...) {
    }
}

void AutorunsScanner::ScanCodecs(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring keys[] = {
            xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32"),
            xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Drivers32"),
        };
        for (const std::wstring& k : keys) {
            HKEY hk;
            if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, k.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
            FILETIME ft{};
            ::RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr,
                nullptr, nullptr, nullptr, nullptr, nullptr, &ft);
            DWORD i = 0;
            wchar_t name[256];
            BYTE   data[2048];
            for (;;) {
                DWORD nameLen = _countof(name);
                DWORD dataLen = sizeof(data);
                DWORD type = 0;
                LONG r = ::RegEnumValueW(hk, i++, name, &nameLen, nullptr, &type, data, &dataLen);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                std::wstring v(reinterpret_cast<wchar_t*>(data), dataLen / sizeof(wchar_t));
                while (!v.empty() && v.back() == 0) v.pop_back();
                AutorunEntry e;
                e.imagePath    = ResolveImagePath(v);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
            ::RegCloseKey(hk);
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanBootExecute(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring sub = xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager");
        auto values = ReadRegMultiSz(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"BootExecute"), 0);
        FILETIME ft = GetKeyTime(HKEY_LOCAL_MACHINE, sub.c_str(), 0);
        for (const auto& v : values) {
            AutorunEntry e;
            e.imagePath    = ResolveImagePath(v);
            e.rawTimestamp = FileTimeToU64(ft);
            out.push_back(std::move(e));
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanImageHijacks(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring roots[] = {
            xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
            xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),
        };
        for (const std::wstring& key : roots) {
            HKEY hk;
            if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
            DWORD i = 0;
            wchar_t name[256];
            for (;;) {
                DWORD len = _countof(name);
                FILETIME ft{};
                LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                std::wstring sub = key + xorstr_(L"\\") + name;
                std::wstring dbg;
                if (ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"Debugger"), dbg, 0) && !dbg.empty()) {
                    AutorunEntry e;
                    e.imagePath     = ResolveImagePath(dbg);
                    e.rawTimestamp  = FileTimeToU64(ft);
                    e.isImageHijack = true;
                    out.push_back(std::move(e));
                }
            }
            ::RegCloseKey(hk);
        }

        static const std::wstring shells[] = {
            xorstr_(L"exefile\\shell\\open\\command"),
            xorstr_(L"comfile\\shell\\open\\command"),
            xorstr_(L"batfile\\shell\\open\\command"),
            xorstr_(L"cmdfile\\shell\\open\\command"),
            xorstr_(L"htmlfile\\shell\\open\\command"),
        };
        for (const std::wstring& k : shells) {
            std::wstring v;
            if (!ReadRegString(HKEY_CLASSES_ROOT, k.c_str(), L"", v, 0) || v.empty()) continue;
            std::wstring low = v;
            for (auto& c : low) c = static_cast<wchar_t>(std::towlower(c));
            if (low.find(xorstr_(L"\"%1\"")) != std::wstring::npos &&
                low.find(xorstr_(L".exe"))   == std::wstring::npos)
                continue;
            AutorunEntry e;
            e.imagePath     = ResolveImagePath(v);
            e.isImageHijack = true;
            out.push_back(std::move(e));
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanAppInitDLLs(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring keys[] = {
            xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
            xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows"),
        };
        for (const std::wstring& key : keys) {
            std::wstring v;
            if (!ReadRegString(HKEY_LOCAL_MACHINE, key.c_str(), xorstr_(L"AppInit_DLLs"), v, 0) || v.empty())
                continue;
            FILETIME ft = GetKeyTime(HKEY_LOCAL_MACHINE, key.c_str(), 0);
            size_t pos = 0;
            while (pos < v.size()) {
                size_t sep = v.find_first_of(xorstr_(L", \t"), pos);
                std::wstring tok = TrimWS(v.substr(pos, sep - pos));
                pos = (sep == std::wstring::npos) ? v.size() : sep + 1;
                if (tok.empty()) continue;
                AutorunEntry e;
                e.imagePath    = ResolveImagePath(tok);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanKnownDLLs(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring sub = xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\KnownDLLs");
        HKEY hk;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
        FILETIME ft{};
        ::RegQueryInfoKeyW(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
            nullptr, nullptr, nullptr, nullptr, &ft);

        DWORD i = 0;
        wchar_t name[256];
        BYTE   data[2048];
        for (;;) {
            DWORD nameLen = _countof(name);
            DWORD dataLen = sizeof(data);
            DWORD type = 0;
            LONG r = ::RegEnumValueW(hk, i++, name, &nameLen, nullptr, &type, data, &dataLen);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
            std::wstring v(reinterpret_cast<wchar_t*>(data), dataLen / sizeof(wchar_t));
            while (!v.empty() && v.back() == 0) v.pop_back();

            AutorunEntry e;
            e.imagePath    = NormalizeImagePath(v);
            e.rawTimestamp = FileTimeToU64(ft);
            out.push_back(std::move(e));
        }
        ::RegCloseKey(hk);
    } catch (...) {
    }
}

void AutorunsScanner::ScanWinlogon(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring notifyKey = xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify");
        HKEY hk;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, notifyKey.c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            DWORD i = 0;
            wchar_t name[256];
            for (;;) {
                DWORD len = _countof(name);
                FILETIME ft{};
                LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                std::wstring sub = notifyKey + xorstr_(L"\\") + name;
                std::wstring dll;
                if (!ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"DllName"), dll, 0) || dll.empty())
                    continue;
                AutorunEntry e;
                e.imagePath    = ResolveImagePath(dll);
                e.rawTimestamp = FileTimeToU64(ft);
                out.push_back(std::move(e));
            }
            ::RegCloseKey(hk);
        }

        static const std::wstring wl = xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon");
        FILETIME wt = GetKeyTime(HKEY_LOCAL_MACHINE, wl.c_str(), 0);
        static const std::wstring wlValues[] = {
            xorstr_(L"GinaDLL"),   xorstr_(L"System"),
            xorstr_(L"Taskman"),   xorstr_(L"VmApplet"),
            xorstr_(L"UIHost"),    xorstr_(L"AutoAdminLogon"),
        };
        for (const std::wstring& n : wlValues) {
            std::wstring v;
            if (!ReadRegString(HKEY_LOCAL_MACHINE, wl.c_str(), n.c_str(), v, 0) || v.empty()) continue;
            AutorunEntry e;
            e.imagePath    = ResolveImagePath(v);
            e.rawTimestamp = FileTimeToU64(wt);
            out.push_back(std::move(e));
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanWinsockProviders(std::vector<AutorunEntry>& out)
{
    try {
        struct Cat { std::wstring key; size_t off; };
        static const Cat cats[] = {
            { xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries"),   372 },
            { xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries64"), 372 },
            { xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries"),   16 },
            { xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\WinSock2\\Parameters\\NameSpace_Catalog5\\Catalog_Entries64"), 16 },
        };
        for (const auto& c : cats) {
            HKEY hk;
            if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, c.key.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
            DWORD i = 0;
            wchar_t name[64];
            for (;;) {
                DWORD len = _countof(name);
                FILETIME ft{};
                LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;

                std::wstring sub = c.key + xorstr_(L"\\") + name;
                HKEY hsub;
                if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.c_str(), 0, KEY_READ, &hsub) != ERROR_SUCCESS) continue;
                DWORD type = 0, size = 0;
                if (::RegQueryValueExW(hsub, xorstr_(L"PackedCatalogItem"), nullptr,
                        &type, nullptr, &size) == ERROR_SUCCESS && size > 0) {
                    std::vector<BYTE> blob(size);
                    if (::RegQueryValueExW(hsub, xorstr_(L"PackedCatalogItem"), nullptr,
                            &type, blob.data(), &size) == ERROR_SUCCESS) {
                        std::wstring image;
                        if (size > c.off) {
                            std::wstring s(reinterpret_cast<const wchar_t*>(blob.data() + c.off));
                            image = s;
                        }
                        AutorunEntry e;
                        e.imagePath    = ResolveImagePath(image);
                        e.rawTimestamp = FileTimeToU64(ft);
                        out.push_back(std::move(e));
                    }
                }
                ::RegCloseKey(hsub);
            }
            ::RegCloseKey(hk);
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanPrintMonitors(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring key = xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors");
        HKEY hk;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
        DWORD i = 0;
        wchar_t name[256];
        for (;;) {
            DWORD len = _countof(name);
            FILETIME ft{};
            LONG r = ::RegEnumKeyExW(hk, i++, name, &len, nullptr, nullptr, nullptr, &ft);
            if (r == ERROR_NO_MORE_ITEMS) break;
            if (r != ERROR_SUCCESS) continue;
            std::wstring sub = key + xorstr_(L"\\") + name;
            std::wstring dll;
            if (!ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"Driver"), dll, 0) || dll.empty())
                continue;
            AutorunEntry e;
            e.imagePath    = NormalizeImagePath(dll);
            e.rawTimestamp = FileTimeToU64(ft);
            out.push_back(std::move(e));
        }
        ::RegCloseKey(hk);
    } catch (...) {
    }
}

void AutorunsScanner::ScanLsaProviders(std::vector<AutorunEntry>& out)
{
    try {
        auto add = [&](const wchar_t* keyName, const wchar_t* valueName) {
            try {
                std::wstring key = std::wstring(xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\")) + keyName;
                auto vals = ReadRegMultiSz(HKEY_LOCAL_MACHINE, key.c_str(), valueName, 0);
                if (vals.empty()) {
                    std::wstring s;
                    if (ReadRegString(HKEY_LOCAL_MACHINE, key.c_str(), valueName, s, 0) && !s.empty())
                        vals.push_back(s);
                }
                FILETIME ft = GetKeyTime(HKEY_LOCAL_MACHINE, key.c_str(), 0);
                for (const auto& v : vals) {
                    std::wstring trimmed = TrimWS(v);
                    if (trimmed.empty()) continue;
                    AutorunEntry e;
                    e.imagePath    = NormalizeImagePath(trimmed);
                    e.rawTimestamp = FileTimeToU64(ft);
                    out.push_back(std::move(e));
                }
            } catch (...) {
            }
        };
        add(xorstr_(L"Lsa"),                 xorstr_(L"Authentication Packages"));
        add(xorstr_(L"Lsa"),                 xorstr_(L"Notification Packages"));
        add(xorstr_(L"Lsa"),                 xorstr_(L"Security Packages"));
        add(xorstr_(L"Lsa\\OSConfig"),       xorstr_(L"Security Packages"));
        add(xorstr_(L"SecurityProviders"),   xorstr_(L"SecurityProviders"));
    } catch (...) {
    }
}

void AutorunsScanner::ScanNetworkProviders(std::vector<AutorunEntry>& out)
{
    try {
        static const std::wstring orderKey = xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\NetworkProvider\\Order");
        std::wstring order;
        if (!ReadRegString(HKEY_LOCAL_MACHINE, orderKey.c_str(), xorstr_(L"ProviderOrder"), order, 0))
            return;
        FILETIME ft = GetKeyTime(HKEY_LOCAL_MACHINE, orderKey.c_str(), 0);
        size_t pos = 0;
        while (pos < order.size()) {
            size_t comma = order.find(L',', pos);
            std::wstring name = TrimWS(order.substr(pos,
                comma == std::wstring::npos ? std::wstring::npos : comma - pos));
            pos = (comma == std::wstring::npos) ? order.size() : comma + 1;
            if (name.empty()) continue;
            std::wstring sub = xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\") + name + xorstr_(L"\\NetworkProvider");
            std::wstring providerPath;
            ReadRegString(HKEY_LOCAL_MACHINE, sub.c_str(), xorstr_(L"ProviderPath"), providerPath, 0);
            AutorunEntry e;
            e.imagePath    = ResolveImagePath(providerPath);
            e.rawTimestamp = FileTimeToU64(ft);
            out.push_back(std::move(e));
        }
    } catch (...) {
    }
}

void AutorunsScanner::ScanWmi(std::vector<AutorunEntry>& out)
{
    try {
        IWbemLocator* loc = nullptr;
        if (FAILED(::CoCreateInstance(CLSID_WbemLocator, nullptr,
                CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                reinterpret_cast<void**>(&loc))) || !loc)
            return;
        IWbemServices* svc = nullptr;
        BSTR ns = ::SysAllocString(xorstr_(L"ROOT\\Subscription"));
        if (FAILED(loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc)) || !svc) {
            if (ns) ::SysFreeString(ns);
            loc->Release();
            return;
        }
        ::SysFreeString(ns);
        ::CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

        auto enumClass = [&](const wchar_t* cls) {
            try {
                BSTR q = ::SysAllocString(
                    (std::wstring(xorstr_(L"SELECT * FROM ")) + cls).c_str());
                BSTR lang = ::SysAllocString(xorstr_(L"WQL"));
                IEnumWbemClassObject* en = nullptr;
                if (SUCCEEDED(svc->ExecQuery(lang, q,
                        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                        nullptr, &en)) && en) {
                    for (;;) {
                        IWbemClassObject* obj = nullptr;
                        ULONG ret = 0;
                        if (en->Next(WBEM_INFINITE, 1, &obj, &ret) != WBEM_S_NO_ERROR || !obj || ret == 0)
                            break;
                        VARIANT vCmd;
                        ::VariantInit(&vCmd);
                        obj->Get(xorstr_(L"CommandLineTemplate"), 0, &vCmd, nullptr, nullptr);
                        if (vCmd.vt != VT_BSTR)
                            obj->Get(xorstr_(L"ExecutablePath"), 0, &vCmd, nullptr, nullptr);
                        std::wstring cmd = (vCmd.vt == VT_BSTR && vCmd.bstrVal)
                            ? std::wstring(vCmd.bstrVal, ::SysStringLen(vCmd.bstrVal))
                            : std::wstring();
                        AutorunEntry e;
                        e.imagePath = ResolveImagePath(cmd);
                        out.push_back(std::move(e));
                        ::VariantClear(&vCmd);
                        obj->Release();
                    }
                    en->Release();
                }
                ::SysFreeString(q);
                ::SysFreeString(lang);
            } catch (...) {
            }
        };
        enumClass(xorstr_(L"CommandLineEventConsumer"));
        enumClass(xorstr_(L"ActiveScriptEventConsumer"));

        svc->Release();
        loc->Release();
    } catch (...) {
    }
}

std::vector<AutorunsScanner::AutorunEntry> AutorunsScanner::ScanAll()
{
    std::vector<AutorunEntry> out;
    try {
        out.reserve(512);

        HRESULT co = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        bool ownCom = SUCCEEDED(co);

        ScanLogon(out);
        ScanExplorer(out);
        ScanInternetExplorer(out);
        ScanScheduledTasks(out);
        ScanServicesAndDrivers(out);
        ScanCodecs(out);
        ScanBootExecute(out);
        ScanImageHijacks(out);
        ScanAppInitDLLs(out);
        ScanKnownDLLs(out);
        ScanWinlogon(out);
        ScanWinsockProviders(out);
        ScanPrintMonitors(out);
        ScanLsaProviders(out);
        ScanNetworkProviders(out);
        ScanWmi(out);

        if (ownCom) ::CoUninitialize();
        return out;
    } catch (...) {
        return out;
    }
}

void AutorunsScanner::ScanEntrySignatures(AutorunEntry& e)
{
    try {
        if (e.scanned) return;

        if (e.imagePath.empty()) {
            e.exists     = false;
            e.signStatus = SignStatus::NotApplicable;
            e.scanned    = true;
            return;
        }

        e.exists = FileExistsOnDisk(e.imagePath);

        if (e.exists) {
            bool ok = HasValidSignature(e.imagePath.c_str());
            e.signStatus = ok ? SignStatus::Signed : SignStatus::Unsigned;
        } else {
            e.signStatus = SignStatus::NotApplicable;
        }

        e.scanned = true;
    } catch (...) {
        e.scanned = true;
    }
}

DWORD WINAPI AutorunsScanner::ScanWorker(LPVOID param)
{
    try {
        auto* entries = static_cast<std::vector<AutorunEntry>*>(param);
        const long total = static_cast<long>(entries->size());
        for (;;) {
            long idx = g_scanIndex.fetch_add(1, std::memory_order_relaxed);
            if (idx >= total) break;
            ScanEntrySignatures((*entries)[idx]);
        }
        return 0;
    } catch (...) {
        return 0;
    }
}

void AutorunsScanner::RunSignatureScan(std::vector<AutorunEntry>& entries)
{
    try {
        g_scanIndex.store(0, std::memory_order_relaxed);

        SYSTEM_INFO si{};
        ::GetSystemInfo(&si);
        int nThreads = static_cast<int>(si.dwNumberOfProcessors);
        if (nThreads < 2)  nThreads = 2;
        if (nThreads > 12) nThreads = 12;

        std::vector<HANDLE> threads(static_cast<size_t>(nThreads));
        for (int i = 0; i < nThreads; i++) {
            threads[static_cast<size_t>(i)] =
                ::CreateThread(nullptr, 0, ScanWorker, &entries, 0, nullptr);
        }
        ::WaitForMultipleObjects(static_cast<DWORD>(threads.size()),
            threads.data(), TRUE, INFINITE);
        for (HANDLE h : threads) {
            if (h) ::CloseHandle(h);
        }
    } catch (...) {
    }
}

bool AutorunsScanner::HasSuspiciousUsnReason(DWORD reason)
{
    try {
        const DWORD mask = USN_REASON_REPARSE_POINT_CHANGE |
                           USN_REASON_FILE_DELETE |
                           USN_REASON_DATA_TRUNCATION;
        return (reason & mask) != 0;
    } catch (...) {
        return false;
    }
}

std::wstring AutorunsScanner::UsnResolveParentDir(HANDLE hVolume, ULONGLONG parentRef,
                                                  std::map<ULONGLONG, std::wstring>& cache)
{
    try {
        auto it = cache.find(parentRef);
        if (it != cache.end()) return it->second;

        FILE_ID_DESCRIPTOR fileIdDesc = {};
        fileIdDesc.dwSize = sizeof(FILE_ID_DESCRIPTOR);
        fileIdDesc.Type = FileIdType;
        fileIdDesc.FileId.QuadPart = parentRef;

        HANDLE hFile = ::OpenFileById(hVolume, &fileIdDesc, 0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, 0);
        if (hFile == INVALID_HANDLE_VALUE) {
            cache[parentRef] = std::wstring();
            return std::wstring();
        }

        wchar_t pathBuf[MAX_PATH];
        DWORD result = ::GetFinalPathNameByHandleW(hFile, pathBuf, MAX_PATH, FILE_NAME_NORMALIZED);
        ::CloseHandle(hFile);

        if (result == 0 || result >= MAX_PATH) {
            cache[parentRef] = std::wstring();
            return std::wstring();
        }

        std::wstring resolved(pathBuf);

        if (resolved.compare(0, 4, xorstr_(L"\\\\?\\")) == 0)
            resolved = resolved.substr(4);

        if (!resolved.empty() && resolved.back() != L'\\')
            resolved += L'\\';

        cache[parentRef] = resolved;
        return resolved;
    } catch (...) {
        return std::wstring();
    }
}

void AutorunsScanner::UsnScanDrive(const wchar_t* volumePath, const NameIndex& nameIndex,
                                    std::vector<std::vector<UsnEntry>>& results)
{
    try {
        HANDLE hVolume = ::CreateFileW(volumePath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVolume == INVALID_HANDLE_VALUE) return;

        USN_JOURNAL_DATA journalData;
        DWORD bytesReturned;
        if (!::DeviceIoControl(hVolume, FSCTL_QUERY_USN_JOURNAL,
            nullptr, 0, &journalData, sizeof(journalData),
            &bytesReturned, nullptr)) {
            ::CloseHandle(hVolume);
            return;
        }

        READ_USN_JOURNAL_DATA_V0 readData = {};
        readData.StartUsn = journalData.FirstUsn;
        readData.ReasonMask = 0xFFFFFFFF;
        readData.UsnJournalID = journalData.UsnJournalID;

        std::vector<BYTE> buffer(65536);
        std::map<ULONGLONG, std::wstring> parentCache;

        while (true) {
            DWORD bytesRead;
            if (!::DeviceIoControl(hVolume, FSCTL_READ_USN_JOURNAL,
                &readData, sizeof(readData),
                buffer.data(), static_cast<DWORD>(buffer.size()),
                &bytesRead, nullptr)) {
                break;
            }

            if (bytesRead <= sizeof(USN)) break;

            USN* nextUsn = reinterpret_cast<USN*>(buffer.data());
            BYTE* ptr = buffer.data() + sizeof(USN);
            BYTE* end = buffer.data() + bytesRead;

            while (ptr < end) {
                USN_RECORD* record = reinterpret_cast<USN_RECORD*>(ptr);
                if (record->RecordLength == 0) break;

                if (!HasSuspiciousUsnReason(record->Reason)) {
                    ptr += record->RecordLength;
                    continue;
                }

                std::wstring fileName(record->FileName, record->FileNameLength / sizeof(WCHAR));

                std::wstring lowerName = fileName;
                for (auto& c : lowerName) c = static_cast<wchar_t>(towlower(c));

                auto nameIt = nameIndex.find(lowerName);
                if (nameIt != nameIndex.end()) {
                    std::wstring parentDir = UsnResolveParentDir(
                        hVolume, record->ParentFileReferenceNumber, parentCache);

                    if (!parentDir.empty()) {
                        std::wstring fullPath = parentDir + fileName;
                        std::wstring lowerFull = fullPath;
                        for (auto& c : lowerFull) c = static_cast<wchar_t>(towlower(c));

                        for (const auto& pi : nameIt->second) {
                            if (pi.lowerPath == lowerFull) {
                                UsnEntry entry;
                                entry.rawReason = record->Reason;
                                results[pi.index].push_back(std::move(entry));
                            }
                        }
                    }
                }

                ptr += record->RecordLength;
            }

            readData.StartUsn = *nextUsn;
        }

        ::CloseHandle(hVolume);
    } catch (...) {
    }
}

std::vector<std::vector<AutorunsScanner::UsnEntry>> AutorunsScanner::UsnScan(
    const std::vector<std::wstring>& filePaths)
{
    std::vector<std::vector<UsnEntry>> results(filePaths.size());
    try {
        NameIndex nameIndex;
        for (size_t i = 0; i < filePaths.size(); i++) {
            std::wstring lower = filePaths[i];
            for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));

            size_t lastSlash = lower.rfind(L'\\');
            std::wstring filename = (lastSlash != std::wstring::npos)
                ? lower.substr(lastSlash + 1) : lower;

            nameIndex[filename].push_back({ i, lower });
        }

        DWORD driveMask = ::GetLogicalDrives();
        for (wchar_t d = L'A'; d <= L'Z'; d++, driveMask >>= 1) {
            if (!(driveMask & 1)) continue;
            wchar_t volumePath[] = { L'\\', L'\\', L'.', L'\\', d, L':', L'\0' };
            UsnScanDrive(volumePath, nameIndex, results);
        }

        return results;
    } catch (...) {
        return results;
    }
}

void AutorunsScanner::AttachUsnResults(std::vector<AutorunEntry>& entries)
{
    try {
        std::vector<std::wstring> paths;
        std::vector<std::vector<int>> ownersByPath;

        for (int i = 0; i < static_cast<int>(entries.size()); i++) {
            const auto& e = entries[static_cast<size_t>(i)];
            if (!e.exists || e.imagePath.empty()) continue;

            std::wstring key = LowerCopy(e.imagePath);

            bool found = false;
            for (size_t k = 0; k < paths.size(); k++) {
                if (LowerCopy(paths[k]) == key) {
                    ownersByPath[k].push_back(i);
                    found = true;
                    break;
                }
            }
            if (!found) {
                paths.push_back(e.imagePath);
                ownersByPath.push_back({ i });
            }
        }

        if (paths.empty()) return;

        std::vector<std::vector<UsnEntry>> results = UsnScan(paths);

        for (size_t k = 0; k < paths.size(); k++) {
            if (results[k].empty()) continue;
            for (int owner : ownersByPath[k])
                entries[static_cast<size_t>(owner)].usnEntries = results[k];
        }
    } catch (...) {
    }
}

ULONGLONG AutorunsScanner::GetUserLogonTime()
{
    try {
        ULONG sessionCount = 0;
        PLUID sessions = nullptr;
        if (::LsaEnumerateLogonSessions(&sessionCount, &sessions) != 0)
            return 0;

        ULONGLONG logonTime = 0;
        for (ULONG i = 0; i < sessionCount; ++i) {
            PSECURITY_LOGON_SESSION_DATA sessionData = nullptr;
            if (::LsaGetLogonSessionData(&sessions[i], &sessionData) == 0 && sessionData != nullptr) {
                if (sessionData->LogonType == Interactive || sessionData->LogonType == RemoteInteractive) {
                    logonTime = static_cast<ULONGLONG>(sessionData->LogonTime.QuadPart);
                    ::LsaFreeReturnBuffer(sessionData);
                    break;
                }
                ::LsaFreeReturnBuffer(sessionData);
            }
        }
        ::LsaFreeReturnBuffer(sessions);
        return logonTime;
    } catch (...) {
        return 0;
    }
}

bool AutorunsScanner::SinceLogon(const AutorunEntry& e, ULONGLONG logonTime)
{
    try {
        if (logonTime == 0) return true;
        return e.rawTimestamp >= logonTime;
    } catch (...) {
        return false;
    }
}

bool AutorunsScanner::IsUnsigned(const AutorunEntry& e)
{
    try {
        if (!e.scanned) return false;
        if (e.signStatus != SignStatus::Unsigned) return false;
        if (e.imagePath.empty()) return false;
        if (!e.exists) return false;
        return true;
    } catch (...) {
        return false;
    }
}

bool AutorunsScanner::HasSuspiciousUsnHits(const AutorunEntry& e)
{
    try {
        return !e.usnEntries.empty();
    } catch (...) {
        return false;
    }
}

void AutorunsScanner::CheckIfeoBootModification()
{
    try {
        const ULONGLONG logonTime = GetUserLogonTime();
        if (logonTime == 0) return;

        struct KeyInfo {
            const wchar_t* sub;
            const char*    view;
        };
        static const KeyInfo keys[] = {
            { xorstr_(L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"),            xorstr_("64-bit") },
            { xorstr_(L"Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"), xorstr_("WoW64")  },
        };

        for (const auto& k : keys) {
            FILETIME ft = GetKeyTime(HKEY_LOCAL_MACHINE, k.sub, 0);
            const ULONGLONG keyTime = FileTimeToU64(ft);
            if (keyTime == 0) continue;
            if (keyTime >= logonTime) {
                LOG(WARNING, FormatTimestamp(keyTime))
                    << xorstr_("Possible Image File Execution Options Bypass: IFEO Key Modified In Boot");
            }
        }
    } catch (...) {
    }
}

std::string AutorunsScanner::FormatTimestamp(ULONGLONG rawFileTime)
{
    try {
        if (rawFileTime == 0) return xorstr_("N/A");

        FILETIME ftUtc{};
        ftUtc.dwLowDateTime  = static_cast<DWORD>(rawFileTime & 0xFFFFFFFFULL);
        ftUtc.dwHighDateTime = static_cast<DWORD>(rawFileTime >> 32);

        FILETIME ftLocal{};
        if (!::FileTimeToLocalFileTime(&ftUtc, &ftLocal)) return xorstr_("N/A");

        SYSTEMTIME st{};
        if (!::FileTimeToSystemTime(&ftLocal, &st)) return xorstr_("N/A");

        char buf[32];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
            xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
        return std::string(buf);
    } catch (...) {
        return xorstr_("N/A");
    }
}

void AutorunsScanner::Run()
{
    try {
        HRESULT hrCo = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        const ULONGLONG logonTime = GetUserLogonTime();

        CheckIfeoBootModification();

        std::vector<AutorunEntry> entries = ScanAll();
        RunSignatureScan(entries);
        AttachUsnResults(entries);

        std::vector<std::wstring> seenSinceLogon;
        std::vector<std::wstring> seenBeforeLogon;
        std::vector<std::wstring> seenCommand;
        std::vector<std::wstring> seenImageHijack;

        auto normLower = [](const std::wstring& p) -> std::wstring {
            std::wstring norm;
            norm.reserve(p.size());
            for (wchar_t c : p) {
                if (c == L'/') c = L'\\';
                norm.push_back(static_cast<wchar_t>(std::towlower(c)));
            }
            return norm;
        };

        auto isWhitelistedTaskCommand = [&](const AutorunEntry& e) -> bool {
            try {
                if (e.source.empty()) return false;
                static const std::vector<std::wstring> whitelistedTaskPaths = {
                    xorstr_(L"\\microsoft\\windows\\hotpatch\\monitoring"),
                };
                std::wstring norm = normLower(e.source);
                for (const auto& p : whitelistedTaskPaths) {
                    if (norm == p) return true;
                }
                return false;
            } catch (...) {
                return false;
            }
        };

        auto isBenignImageHijack = [&](const AutorunEntry& e) -> bool {
            try {
                if (e.imagePath.empty()) return false;
                static const std::vector<std::wstring> benignSignedPaths = {
                    xorstr_(L"c:\\program files\\internet explorer\\iexplore.exe"),
                    xorstr_(L"c:\\program files (x86)\\internet explorer\\iexplore.exe"),
                    xorstr_(L"c:\\windows\\system32\\systray.exe"),
                    xorstr_(L"c:\\windows\\syswow64\\systray.exe"),
                };
                std::wstring norm = normLower(e.imagePath);
                bool pathMatch = false;
                for (const auto& p : benignSignedPaths) {
                    if (norm == p) { pathMatch = true; break; }
                }
                if (!pathMatch) return false;
                return e.scanned && e.exists && e.signStatus == SignStatus::Signed;
            } catch (...) {
                return false;
            }
        };

        auto alreadyListed = [](const std::vector<std::wstring>& seen,
                                const std::wstring& path) -> bool {
            try {
                std::wstring key;
                key.reserve(path.size());
                for (wchar_t c : path) key.push_back(static_cast<wchar_t>(std::towlower(c)));
                for (const auto& s : seen) {
                    std::wstring sk;
                    sk.reserve(s.size());
                    for (wchar_t c : s) sk.push_back(static_cast<wchar_t>(std::towlower(c)));
                    if (sk == key) return true;
                }
                return false;
            } catch (...) {
                return false;
            }
        };

        for (const auto& e : entries) {
            try {
                if (e.isImageHijack && !e.imagePath.empty() && !isBenignImageHijack(e)) {
                    if (!alreadyListed(seenImageHijack, e.imagePath)) {
                        seenImageHijack.push_back(e.imagePath);
                        LOG ( WARNING , FormatTimestamp(e.rawTimestamp)) << xorstr_("Suspicious Autoruns Image Hijack:")
                            << ascii_wstring_to_string(e.imagePath);
                    }
                }

                if (!e.imagePath.empty() && IsAlwaysShowFile(e.imagePath) && !isWhitelistedTaskCommand(e)) {
                    if (!alreadyListed(seenCommand, e.imagePath)) {
                        seenCommand.push_back(e.imagePath);
                        LOG ( WARNING , FormatTimestamp(e.rawTimestamp)) << xorstr_("Suspicious Autoruns Command:")
                            << ascii_wstring_to_string(e.imagePath);
                    }
                }

                if (!e.imagePath.empty() && !IsDirectoryOnDisk(e.imagePath) && IsUnsigned(e)) {
                    if (SinceLogon(e, logonTime)) {
                        if (!alreadyListed(seenSinceLogon, e.imagePath)) {
                            seenSinceLogon.push_back(e.imagePath);
                            LOG ( WARNING , FormatTimestamp(e.rawTimestamp)) << xorstr_("Suspicious Autoruns File Since Logon:")
                                << ascii_wstring_to_string(e.imagePath);
                        }
                    } else {
                        if (!alreadyListed(seenBeforeLogon, e.imagePath)) {
                            seenBeforeLogon.push_back(e.imagePath);
                            LOG ( WARNING , FormatTimestamp(e.rawTimestamp)) << xorstr_("Suspicious Autoruns File Before Logon:")
                                << ascii_wstring_to_string(e.imagePath);
                        }
                    }
                }
            } catch (...) {
            }
        }

        if (hrCo == S_OK || hrCo == S_FALSE) ::CoUninitialize();
    } catch (...) {
    }
}

void c_autoruns_detection::start_autoruns_detection()
{
    try {
        AutorunsScanner::Run();
    } catch (...) {
    }
}
