#include "c_yara_scanner.h"
#include "rule_delivery.h"
#include "yara_compile_util.h"
#include "../../../utils/sig_cache.h"

std::atomic<uint64_t>                 YaraScanner::s_filesScanned{ 0 };
std::atomic<uint64_t>                 YaraScanner::s_filesSkipped{ 0 };
std::atomic<uint64_t>                 YaraScanner::s_detections{ 0 };
std::atomic<uint64_t>                 YaraScanner::s_errors{ 0 };
std::atomic<uint64_t>                 YaraScanner::s_bytesScanned{ 0 };
std::atomic<bool>                     YaraScanner::s_scanDone{ false };
std::atomic<bool>                     YaraScanner::s_abort{ false };
std::mutex                            YaraScanner::s_consoleMtx;
std::chrono::steady_clock::time_point YaraScanner::s_startTime;
YaraScanner::FileQueue                YaraScanner::s_queue;
std::unordered_set<std::wstring>      YaraScanner::s_visitedVolumes;
std::mutex                            YaraScanner::s_visitedVolumesMtx;

static std::unordered_map<std::string, std::string> s_ruleNames;

static bool HasValidSignature_Impl(const wchar_t* filePath)
{
    try {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct       = sizeof(fileInfo);
        fileInfo.pcwszFilePath  = filePath;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA wd{};
        wd.cbStruct            = sizeof(wd);
        wd.dwUIChoice          = WTD_UI_NONE;
        wd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wd.dwUnionChoice       = WTD_CHOICE_FILE;
        wd.pFile               = &fileInfo;
        wd.dwStateAction       = WTD_STATEACTION_VERIFY;

        LONG result = WinVerifyTrust(NULL, &action, &wd);
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wd);

        if (result == ERROR_SUCCESS) {
            WINTRUST_DATA rwd{};
            rwd.cbStruct            = sizeof(rwd);
            rwd.dwUIChoice          = WTD_UI_NONE;
            rwd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
            rwd.dwUnionChoice       = WTD_CHOICE_FILE;
            rwd.pFile               = &fileInfo;
            rwd.dwStateAction       = WTD_STATEACTION_VERIFY;
            rwd.dwProvFlags         = WTD_REVOCATION_CHECK_CHAIN;

            LONG rvr = WinVerifyTrust(NULL, &action, &rwd);
            rwd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &action, &rwd);

            if (rvr == static_cast<LONG>(CERT_E_REVOKED)) return false;
            return true;
        }

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

        std::vector<BYTE> hash(hashSize);
        if (!CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
            CloseHandle(hFile);
            CryptCATAdminReleaseContext(hCatAdmin, 0);
            return false;
        }
        CloseHandle(hFile);

        CATALOG_INFO catInfo{};
        catInfo.cbStruct = sizeof(catInfo);
        HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(
            hCatAdmin, hash.data(), hashSize, 0, NULL);

        bool valid = false;
        while (hCatInfo && CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
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
            LONG catResult = WinVerifyTrust(NULL, &catAction, &catWd);
            catWd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &catAction, &catWd);

            if (catResult == ERROR_SUCCESS) {
                WINTRUST_DATA rcatWd{};
                rcatWd.cbStruct            = sizeof(rcatWd);
                rcatWd.dwUnionChoice       = WTD_CHOICE_CATALOG;
                rcatWd.pCatalog            = &wci;
                rcatWd.dwUIChoice          = WTD_UI_NONE;
                rcatWd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
                rcatWd.dwStateAction       = WTD_STATEACTION_VERIFY;
                rcatWd.dwProvFlags         = WTD_REVOCATION_CHECK_CHAIN;

                LONG rcvr = WinVerifyTrust(NULL, &catAction, &rcatWd);
                rcatWd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust(NULL, &catAction, &rcatWd);

                if (rcvr != static_cast<LONG>(CERT_E_REVOKED)) { valid = true; break; }
            }

            hCatInfo = CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash.data(), hashSize, 0, &hCatInfo);
        }

        if (hCatInfo) CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return valid;
    }
    catch (...) { return false; }
}

static bool HasValidSignature(const wchar_t* filePath)
{
    return SigCache::GetOrCompute(filePath, HasValidSignature_Impl);
}

void YaraScanner::FileQueue::PushBatch(std::vector<FileEntry>& batch)
{
    try
    {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            for (auto& e : batch)
                q_.push(std::move(e));
        }
        cv_.notify_all();
    }
    catch (...) {}
}

bool YaraScanner::FileQueue::Pop(FileEntry& out)
{
    try
    {
        std::unique_lock<std::mutex> lk(mtx_);
        cv_.wait(lk, [&] { return !q_.empty() || done_ || s_abort.load(std::memory_order_relaxed); });
        if (q_.empty() || s_abort.load(std::memory_order_relaxed)) return false;
        out = std::move(q_.front());
        q_.pop();
        return true;
    }
    catch (...) { return false; }
}

void YaraScanner::FileQueue::SetDone()
{
    try
    {
        { std::lock_guard<std::mutex> lk(mtx_); done_ = true; }
        cv_.notify_all();
    }
    catch (...) {}
}

size_t YaraScanner::FileQueue::Size() const
{
    try
    {
        std::lock_guard<std::mutex> lk(mtx_);
        return q_.size();
    }
    catch (...) { return 0; }
}

void YaraScanner::FileQueue::Reset()
{
    try
    {
        std::lock_guard<std::mutex> lk(mtx_);
        std::queue<FileEntry>().swap(q_);
        done_ = false;
    }
    catch (...) {}
}

void YaraScanner::ResetState()
{
    try
    {
        s_filesScanned.store(0);
        s_filesSkipped.store(0);
        s_detections.store(0);
        s_errors.store(0);
        s_bytesScanned.store(0);
        s_scanDone.store(false);
        s_abort.store(false);
        s_ruleNames.clear();
        s_queue.Reset();
        {
            std::lock_guard<std::mutex> lk(s_visitedVolumesMtx);
            s_visitedVolumes.clear();
        }
    }
    catch (...) {}
}

std::vector<std::wstring> YaraScanner::GetAllDrives()
{
    try
    {
        std::vector<std::wstring> drives;

        DWORD mask = GetLogicalDrives();
        std::unordered_set<std::wstring> letteredVolumes;

        for (wchar_t c = L'A'; c <= L'Z'; ++c, mask >>= 1)
        {
            if (!(mask & 1)) continue;
            std::wstring d{ c, L':', L'\\' };
            UINT t = GetDriveTypeW(d.c_str());
            if (t == DRIVE_NO_ROOT_DIR || t == DRIVE_CDROM || t == DRIVE_RAMDISK)
                continue;

            drives.push_back(d);

            wchar_t volName[MAX_PATH] = {};
            if (GetVolumeNameForVolumeMountPointW(d.c_str(), volName, MAX_PATH))
            {
                letteredVolumes.insert(volName);
                std::lock_guard<std::mutex> lk(s_visitedVolumesMtx);
                s_visitedVolumes.insert(volName);
            }
        }

        wchar_t volBuf[MAX_PATH] = {};
        HANDLE hFind = FindFirstVolumeW(volBuf, MAX_PATH);
        if (hFind != INVALID_HANDLE_VALUE)
        {
            do
            {
                std::wstring vol(volBuf);
                if (letteredVolumes.count(vol))
                    continue;

                UINT t = GetDriveTypeW(vol.c_str());
                if (t == DRIVE_NO_ROOT_DIR || t == DRIVE_CDROM || t == DRIVE_RAMDISK)
                    continue;

                wchar_t pathNames[MAX_PATH] = {};
                DWORD returned = 0;
                if (GetVolumePathNamesForVolumeNameW(vol.c_str(), pathNames, MAX_PATH, &returned))
                {
                    if (pathNames[0] != L'\0')
                        continue;
                }

                {
                    std::lock_guard<std::mutex> lk(s_visitedVolumesMtx);
                    s_visitedVolumes.insert(vol);
                }
                drives.push_back(vol);
            } while (FindNextVolumeW(hFind, volBuf, MAX_PATH));

            FindVolumeClose(hFind);
        }

        return drives;
    }
    catch (...) { return {}; }
}

bool YaraScanner::IsExcludedDir(const std::wstring& path)
{
    try
    {
        static const std::wstring exclusions[] = {
            xorstr_(L"\\Windows\\WinSxS"),
            xorstr_(L"\\Program Files"),
            xorstr_(L"\\Windows\\assembly"),
            xorstr_(L"\\Windows\\ServiceProfiles\\"),
        };

        for (const auto& ex : exclusions)
            if (path.find(ex) != std::wstring::npos) return true;
        return false;
    }
    catch (...) { return false; }
}

bool YaraScanner::IsScanExtension(const wchar_t* filename)
{
    try
    {
        const wchar_t* dot = wcsrchr(filename, L'.');
        if (!dot || !dot[1]) return false;
        return _wcsicmp(dot, xorstr_(L".exe")) == 0 || _wcsicmp(dot, xorstr_(L".dll")) == 0 ||
            _wcsicmp(dot, xorstr_(L".mui")) == 0 || _wcsicmp(dot, xorstr_(L".sys")) == 0 ||
            _wcsicmp(dot, xorstr_(L".scr")) == 0 || _wcsicmp(dot, xorstr_(L".mp3")) == 0 ||
            _wcsicmp(dot, xorstr_(L".mp4")) == 0 || _wcsicmp(dot, xorstr_(L".ogg")) == 0 ||
            _wcsicmp(dot, xorstr_(L".drv")) == 0 || _wcsicmp(dot, xorstr_(L".ocx")) == 0 ||
            _wcsicmp(dot, xorstr_(L".cpl")) == 0 || _wcsicmp(dot, xorstr_(L".com")) == 0 ||
            _wcsicmp(dot, xorstr_(L".pif")) == 0 || _wcsicmp(dot, xorstr_(L".bin")) == 0 ||
            _wcsicmp(dot, xorstr_(L".tmp")) == 0 || _wcsicmp(dot, xorstr_(L".detect")) == 0 ||
            _wcsicmp(dot, xorstr_(L".rar")) == 0 || _wcsicmp(dot, xorstr_(L".detectac")) == 0 ||
            _wcsicmp(dot, xorstr_(L".zip")) == 0 || _wcsicmp(dot, xorstr_(L".7z")) == 0 ||
            _wcsicmp(dot, xorstr_(L".rpf")) == 0 || _wcsicmp(dot, xorstr_(L".jar")) == 0 ||
            _wcsicmp(dot, xorstr_(L".java")) == 0 || _wcsicmp(dot, xorstr_(L".ahk")) == 0 ||
            _wcsicmp(dot, xorstr_(L".bat")) == 0 || _wcsicmp(dot, xorstr_(L".cmd")) == 0 ||
            _wcsicmp(dot, xorstr_(L".tpm")) == 0 || _wcsicmp(dot, xorstr_(L".vbs")) == 0 ||
            _wcsicmp(dot, xorstr_(L".ps1")) == 0 || _wcsicmp(dot, xorstr_(L".lua")) == 0 ||
            _wcsicmp(dot, xorstr_(L".reg")) == 0 || _wcsicmp(dot, xorstr_(L".lnk")) == 0 ||
            _wcsicmp(dot, xorstr_(L".js")) == 0  || _wcsicmp(dot, xorstr_(L".nls")) == 0 ||
            _wcsicmp(dot, xorstr_(L".mof")) == 0  || _wcsicmp(dot, xorstr_(L".log")) == 0 ||
            _wcsicmp(dot, xorstr_(L".mov")) == 0  || _wcsicmp(dot, xorstr_(L".pdf")) == 0 ||
            _wcsicmp(dot, xorstr_(L".chk")) == 0;
    }
    catch (...) { return false; }
}

namespace {
bool ResolveVolumeUniqueName(const std::wstring& pathEndsWithBackslash, std::wstring& outUnique)
{
    wchar_t volPath[MAX_PATH] = {};
    if (!GetVolumePathNameW(pathEndsWithBackslash.c_str(), volPath, MAX_PATH))
        return false;
    wchar_t unique[MAX_PATH] = {};
    if (!GetVolumeNameForVolumeMountPointW(volPath, unique, MAX_PATH))
        return false;
    outUnique.assign(unique);
    return true;
}

// OneDrive / cloud-provider placeholder reparse tags follow the pattern
// 0x9000xx1A (IO_REPARSE_TAG_CLOUD .. IO_REPARSE_TAG_CLOUD_F). Masking out
// the provider-id nibble lets a single comparison cover all 16 variants.
bool IsCloudReparseTag(ULONG tag)
{
    return (tag & 0xFFFF0FFFUL) == 0x9000001AUL;
}
}

bool YaraScanner::TryClaimMountedVolume(const std::wstring& parentDir, const std::wstring& mountPointPath)
{
    try
    {
        if (mountPointPath.empty() || mountPointPath.back() != L'\\')
            return false;

        wchar_t mountVol[MAX_PATH] = {};
        if (!GetVolumeNameForVolumeMountPointW(mountPointPath.c_str(), mountVol, MAX_PATH))
            return false;

        std::wstring parentVol;
        if (!ResolveVolumeUniqueName(parentDir, parentVol))
            return false;

        if (_wcsicmp(mountVol, parentVol.c_str()) == 0)
            return false;

        bool inserted;
        {
            std::lock_guard<std::mutex> lk(s_visitedVolumesMtx);
            inserted = s_visitedVolumes.insert(std::wstring(mountVol)).second;
        }

        if (inserted)
        {
            int volLen = WideCharToMultiByte(CP_UTF8, 0, mountVol, -1, nullptr, 0, nullptr, nullptr);
            std::string narrowVol(volLen > 0 ? volLen - 1 : 0, '\0');
            WideCharToMultiByte(CP_UTF8, 0, mountVol, -1, &narrowVol[0], volLen, nullptr, nullptr);

            int pathLen = WideCharToMultiByte(CP_UTF8, 0, mountPointPath.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string narrowPath(pathLen > 0 ? pathLen - 1 : 0, '\0');
            WideCharToMultiByte(CP_UTF8, 0, mountPointPath.c_str(), -1, &narrowPath[0], pathLen, nullptr, nullptr);

            std::lock_guard<std::mutex> lk(s_consoleMtx);
            LOG(WARNING, xorstr_("N/A")) << xorstr_("Folder Mapped To External Drive ") << narrowVol << xorstr_(":") << narrowPath;
        }

        return inserted;
    }
    catch (...) { return false; }
}

bool YaraScanner::HasSuspiciousFilenameChars(const std::wstring& path)
{
    try
    {
        size_t lastSlash = path.find_last_of(xorstr_(L"\\/"));
        const wchar_t* p = (lastSlash != std::wstring::npos) ? path.c_str() + lastSlash + 1 : path.c_str();

        for (; *p; ++p)
        {
            wchar_t wc = *p;
            if (wc < 0x20 || wc > 0x7E)
                return true;
        }
        return false;
    }
    catch (...) { return false; }
}

void YaraScanner::EnumerateFiles(const std::wstring& root)
{
    try
    {
        std::vector<FileEntry> batch;
        batch.reserve(BATCH_SIZE);

        std::vector<std::wstring> dirStack;
        dirStack.push_back(root);

        while (!dirStack.empty() && !s_abort.load(std::memory_order_relaxed))
        {
            std::wstring dir = std::move(dirStack.back());
            dirStack.pop_back();

            WIN32_FIND_DATAW fd;
            HANDLE hFind = FindFirstFileExW(
                (dir + xorstr_(L"*")).c_str(),
                FindExInfoBasic, &fd,
                FindExSearchNameMatch, nullptr,
                FIND_FIRST_EX_LARGE_FETCH);

            if (hFind == INVALID_HANDLE_VALUE) continue;

            do
            {
                if (fd.cFileName[0] == L'.')
                {
                    if (fd.cFileName[1] == L'\0') continue;
                    if (fd.cFileName[1] == L'.' && fd.cFileName[2] == L'\0') continue;
                }

                bool isReparse    = (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
                bool isDirectory  = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)     != 0;
                bool isCloudPh    = isReparse && IsCloudReparseTag(fd.dwReserved0);

                if (isReparse && !isDirectory && !isCloudPh) continue;

                if (isDirectory)
                {
                    std::wstring sub = dir + fd.cFileName + L'\\';

                    if (sub.size() > MAX_PATH_DEPTH_CHARS)
                        continue;

                    if (isReparse && !isCloudPh)
                    {
                        if (!TryClaimMountedVolume(dir, sub))
                            continue;
                    }

                    if (!IsExcludedDir(sub))
                        dirStack.push_back(std::move(sub));
                    continue;
                }

                if (!IsScanExtension(fd.cFileName)) { s_filesSkipped++; continue; }

                ULONGLONG sz = (ULONGLONG(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
                if (sz == 0 || sz > MAX_FILE_SIZE) { s_filesSkipped++; continue; }

                batch.push_back({ dir + fd.cFileName, sz, fd.dwFileAttributes });
                if (batch.size() >= BATCH_SIZE)
                {
                    s_queue.PushBatch(batch);
                    batch.clear();
                }
            } while (FindNextFileW(hFind, &fd));

            FindClose(hFind);
        }

        if (!batch.empty())
            s_queue.PushBatch(batch);
    }
    catch (...) {}
}

static const std::unordered_set<std::string>& GetWhitelistedSHA256()
{
    static const std::unordered_set<std::string> hashes = {
        xorstr_("41b0e5dd2795abeb347f1e85be172e0d8abc08e7538485cb6107b0caf2968287"), //C:\Windows\System32\sedplugins.dll whitelist hash
    };
    return hashes;
}

static bool PathContainsI(const wchar_t* haystack, const wchar_t* needle)
{
    if (!haystack || !needle || !*needle) return false;

    const size_t nlen = wcslen(needle);
    for (const wchar_t* p = haystack; *p; ++p)
        if (_wcsnicmp(p, needle, nlen) == 0) return true;

    return false;
}

static bool IsWhitelistedFileName(const wchar_t* path)
{
    if (!path) return false;

    if (!PathContainsI(path, xorstr_(L"\\Roblox\\Versions\\")))
        return false;

    const wchar_t* slash = wcsrchr(path, L'\\');
    const wchar_t* name = slash ? slash + 1 : path;

    return _wcsicmp(name, xorstr_(L"CameraInput.lua")) == 0 ||
           _wcsicmp(name, xorstr_(L"GameSettings.lua")) == 0 ||
           _wcsicmp(name, xorstr_(L"CameraSensitivityEntry.lua")) == 0;
}

static std::string FetchLOLDriversJson()
{
    try
    {
        std::string result;

        HINTERNET hSession = WinHttpOpen(xorstr_(L"YS/1.0"),
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return result;

        WinHttpSetTimeouts(hSession, 15000, 15000, 15000, 30000);

        HINTERNET hConnect = WinHttpConnect(hSession,
            xorstr_(L"www.loldrivers.io"), INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return result; }

        HINTERNET hRequest = WinHttpOpenRequest(hConnect, xorstr_(L"GET"),
            xorstr_(L"/api/drivers.json"),
            NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }

        constexpr size_t kMaxBody = 64ULL << 20;
        if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(hRequest, NULL))
        {
            result.reserve(16ULL << 20);
            DWORD bytesAvailable = 0;
            while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0)
            {
                if (result.size() + bytesAvailable > kMaxBody) break;
                std::vector<char> buf(bytesAvailable);
                DWORD bytesRead = 0;
                WinHttpReadData(hRequest, buf.data(), bytesAvailable, &bytesRead);
                result.append(buf.data(), bytesRead);
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }
    catch (...) { return {}; }
}

static const std::unordered_set<std::string>& GetLOLDriversHashes()
{
    static std::once_flag onceFlag;
    static std::unordered_set<std::string> hashes;
    std::call_once(onceFlag, [] {
        try
        {
            const std::string json = FetchLOLDriversJson();
            if (json.empty()) return;

            const std::string needle = xorstr_("\"SHA1\"");
            size_t pos = 0;
            while ((pos = json.find(needle, pos)) != std::string::npos)
            {
                pos += needle.size();
                const size_t q1 = json.find('"', pos);
                if (q1 == std::string::npos) break;
                const size_t q2 = json.find('"', q1 + 1);
                if (q2 == std::string::npos) break;

                if (q2 - q1 - 1 == 40)
                {
                    std::string h = json.substr(q1 + 1, 40);
                    bool allHex = true;
                    for (char& c : h)
                    {
                        if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
                        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { allHex = false; break; }
                    }
                    if (allHex) hashes.insert(std::move(h));
                }
                pos = q2 + 1;
            }
        }
        catch (...) {}
    });
    return hashes;
}

static std::string ComputeSHA256(const uint8_t* data, size_t len)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return result;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return result;
    }

    const DWORD chunkSize = 1 << 20;
    size_t offset = 0;
    while (offset < len)
    {
        DWORD toHash = static_cast<DWORD>(std::min(static_cast<size_t>(chunkSize), len - offset));
        if (!CryptHashData(hHash, data + offset, toHash, 0))
        {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return result;
        }
        offset += toHash;
    }

    DWORD hashLen = 32;
    uint8_t hashBytes[32];
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0))
    {
        static const std::string hex = xorstr_("0123456789abcdef");
        result.reserve(64);
        for (DWORD i = 0; i < hashLen; ++i)
        {
            result += hex[hashBytes[i] >> 4];
            result += hex[hashBytes[i] & 0x0F];
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

static std::string ComputeSHA1(const uint8_t* data, size_t len)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string result;

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return result;

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return result;
    }

    const DWORD chunkSize = 1 << 20;
    size_t offset = 0;
    while (offset < len)
    {
        DWORD toHash = static_cast<DWORD>(std::min(static_cast<size_t>(chunkSize), len - offset));
        if (!CryptHashData(hHash, data + offset, toHash, 0))
        {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return result;
        }
        offset += toHash;
    }

    DWORD hashLen = 20;
    uint8_t hashBytes[20];
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0))
    {
        static const std::string hex = xorstr_("0123456789abcdef");
        result.reserve(40);
        for (DWORD i = 0; i < hashLen; ++i)
        {
            result += hex[hashBytes[i] >> 4];
            result += hex[hashBytes[i] & 0x0F];
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

struct ScanCallbackCtx
{
    const wchar_t*  path;
    const uint8_t*  data;
    size_t          dataLen;
    std::string     cachedHash;
    bool            hashComputed = false;
    bool            whitelisted  = false;
};

int YaraScanner::YaraCallback(
    YR_SCAN_CONTEXT*,
    int message,
    void* message_data,
    void* user_data)
{
    try
    {
        if (message == CALLBACK_MSG_RULE_MATCHING)
        {
            auto* rule = static_cast<YR_RULE*>(message_data);
            auto* ctx  = static_cast<ScanCallbackCtx*>(user_data);

            if (IsWhitelistedFileName(ctx->path))
                return CALLBACK_CONTINUE;

            if (!ctx->hashComputed)
            {
                ctx->cachedHash   = ComputeSHA256(ctx->data, ctx->dataLen);
                ctx->whitelisted  = !ctx->cachedHash.empty() &&
                                    GetWhitelistedSHA256().count(ctx->cachedHash) > 0;
                ctx->hashComputed = true;
            }

            if (ctx->whitelisted)
                return CALLBACK_CONTINUE;

            const wchar_t* widePath = ctx->path;
            s_detections++;

            int len = WideCharToMultiByte(CP_UTF8, 0, widePath, -1, nullptr, 0, nullptr, nullptr);
            std::string narrowPath(len > 0 ? len - 1 : 0, '\0');
            WideCharToMultiByte(CP_UTF8, 0, widePath, -1, &narrowPath[0], len, nullptr, nullptr);

            const std::string ruleId(rule->identifier);

            const auto& names = s_ruleNames;
            auto it = names.find(ruleId);

            std::string detectionName;
            bool isWarning = false;
            if (it != names.end())
            {
                detectionName = it->second;
                isWarning = RuleDelivery::StripWarningPrefix(detectionName);
            }

            bool hasSuspiciousFilename = HasSuspiciousFilenameChars(widePath);
            bool isHiddenDrive = narrowPath.size() < 2 ||
                !std::isalpha(static_cast<unsigned char>(narrowPath[0])) || narrowPath[1] != ':';

            if (ruleId == xorstr_("_d_Un_Signed_Driver"))
            {
                const size_t n = narrowPath.size();
                const bool endsSys =
                    n >= 4 &&
                    narrowPath[n - 4] == '.' &&
                    (narrowPath[n - 3] == 's' || narrowPath[n - 3] == 'S') &&
                    (narrowPath[n - 2] == 'y' || narrowPath[n - 2] == 'Y') &&
                    (narrowPath[n - 1] == 's' || narrowPath[n - 1] == 'S');
                if (!endsSys) return CALLBACK_CONTINUE;

                {
                    const auto& lolHashes = GetLOLDriversHashes();
                    if (!lolHashes.empty())
                    {
                        std::string sha1 = ComputeSHA1(ctx->data, ctx->dataLen);
                        if (!sha1.empty() && lolHashes.find(sha1) != lolHashes.end())
                        {
                            std::lock_guard<std::mutex> lk(s_consoleMtx);
                            LOG(WARNING, xorstr_("N/A"))
                                << xorstr_("Vulnerable Driver Found")
                                << (isHiddenDrive ? xorstr_(" On Hidden Drive") : xorstr_(""))
                                << (hasSuspiciousFilename ? xorstr_(" (Suspicious Filename - Hidden Characters)") : xorstr_(""))
                                << xorstr_(":") << narrowPath
                                << xorstr_(" | SHA1=") << sha1;
                        }
                    }
                }

                if (HasValidSignature(widePath)) return CALLBACK_CONTINUE;
            }
            else if (ruleId.rfind(xorstr_("_d_Suspicious_File"), 0) == 0 ||
                     ruleId == xorstr_("_d_Suspicious_PDB_Path"))
            {
                if (HasValidSignature(widePath)) return CALLBACK_CONTINUE;
            }

            std::string sha1Marker;
            if (isHiddenDrive)
            {
                std::string sha1 = ComputeSHA1(ctx->data, ctx->dataLen);
                if (!sha1.empty())
                    sha1Marker = xorstr_(" | SHA1=") + sha1;
            }

            const std::string detectionText = it != names.end()
                ? detectionName + xorstr_(" Found")
                : std::string();

            std::lock_guard<std::mutex> lk(s_consoleMtx);
            if (it != names.end())
            {
                if (isWarning)
                    LOG(WARNING, xorstr_("N/A")) << detectionText
                        << (isHiddenDrive ? xorstr_(" On Hidden Drive") : xorstr_(""))
                        << (hasSuspiciousFilename ? xorstr_(" (Suspicious Filename - Hidden Characters)") : xorstr_(""))
                        << xorstr_(":") << narrowPath << sha1Marker;
                else
                    LOG(DETECTION, xorstr_("N/A")) << detectionText
                        << (isHiddenDrive ? xorstr_(" On Hidden Drive") : xorstr_(""))
                        << (hasSuspiciousFilename ? xorstr_(" (Suspicious Filename - Hidden Characters)") : xorstr_(""))
                        << xorstr_(":") << narrowPath << sha1Marker;
            }
            else
            {
                LOG(WARNING, xorstr_("N/A")) << rule->identifier << xorstr_(" Custom Yara Rule Match")
                    << (isHiddenDrive ? xorstr_(" On Hidden Drive") : xorstr_(""))
                    << (hasSuspiciousFilename ? xorstr_(" (Suspicious Filename - Hidden Characters)") : xorstr_(""))
                    << xorstr_(":") << narrowPath << sha1Marker;
            }
        }
    }
    catch (...) {}
    return CALLBACK_CONTINUE;
}

void YaraScanner::ScanWorker(YR_RULES* rules)
{
    try
    {
        YR_SCANNER* scanner = nullptr;
        if (yr_scanner_create(rules, &scanner) != ERROR_SUCCESS)
            return;

        yr_scanner_set_timeout(scanner, SCAN_TIMEOUT);
        yr_scanner_set_flags(scanner, SCAN_FLAGS_FAST_MODE);

        std::vector<uint8_t> buf(READ_BUF_SIZE);

        FileEntry entry;
        while (s_queue.Pop(entry))
        {
            try
            {
                HANDLE hFile = CreateFileW(
                    entry.path.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING,
                    FILE_FLAG_SEQUENTIAL_SCAN, nullptr);

                if (hFile == INVALID_HANDLE_VALUE) { s_errors++; continue; }

                const size_t fileSize = static_cast<size_t>(entry.size);
                const uint8_t* scanPtr = nullptr;
                size_t         scanLen = 0;
                HANDLE         hMap = nullptr;

                if (fileSize <= READ_BUF_SIZE)
                {
                    DWORD bytesRead = 0;
                    if (!ReadFile(hFile, buf.data(), (DWORD)fileSize, &bytesRead, nullptr))
                    {
                        CloseHandle(hFile);
                        s_errors++;
                        continue;
                    }
                    CloseHandle(hFile);
                    scanPtr = buf.data();
                    scanLen = bytesRead;
                }
                else
                {
                    LARGE_INTEGER li;
                    if (!GetFileSizeEx(hFile, &li) || li.QuadPart == 0)
                    {
                        CloseHandle(hFile);
                        s_filesSkipped++;
                        continue;
                    }

                    hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
                    if (!hMap)
                    {
                        CloseHandle(hFile);
                        s_errors++;
                        continue;
                    }

                    scanPtr = static_cast<const uint8_t*>(
                        MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0));
                    if (!scanPtr)
                    {
                        CloseHandle(hMap);
                        CloseHandle(hFile);
                        s_errors++;
                        continue;
                    }
                    scanLen = static_cast<size_t>(li.QuadPart);
                }

                int narrowLen = WideCharToMultiByte(CP_UTF8, 0, entry.path.c_str(), -1, nullptr, 0, nullptr, nullptr);
                std::string narrowPath(narrowLen > 0 ? narrowLen - 1 : 0, '\0');
                WideCharToMultiByte(CP_UTF8, 0, entry.path.c_str(), -1, &narrowPath[0], narrowLen, nullptr, nullptr);
                yr_scanner_define_string_variable(scanner, xorstr_("filename"), narrowPath.c_str());
                yr_scanner_define_boolean_variable(scanner, xorstr_("is_hidden"),
                    (entry.attrs & FILE_ATTRIBUTE_HIDDEN) != 0 ? 1 : 0);

                ScanCallbackCtx ctx{ entry.path.c_str(), scanPtr, scanLen };
                yr_scanner_set_callback(scanner, YaraCallback, &ctx);
                yr_scanner_scan_mem(scanner, scanPtr, scanLen);

                if (hMap)
                {
                    UnmapViewOfFile(scanPtr);
                    CloseHandle(hMap);
                    CloseHandle(hFile);
                }

                s_bytesScanned += scanLen;
                s_filesScanned++;
            }
            catch (...)
            {
                s_errors++;
            }
        }

        yr_scanner_destroy(scanner);
    }
    catch (...) {}
}

void YaraScanner::ProgressThread()
{
    try
    {
        using clk = std::chrono::steady_clock;

        while (!s_scanDone.load(std::memory_order_relaxed))
        {
            std::this_thread::sleep_for(std::chrono::seconds(5));

            auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                clk::now() - s_startTime).count();

            if (sec >= MAX_SCAN_SECS && !s_abort.load(std::memory_order_relaxed))
            {
                s_abort.store(true);
                s_queue.SetDone();
            }
        }
    }
    catch (...) {}
}

ScanResult YaraScanner::yara_Scanner()
{
    try
    {
        ResetState();

        if (yr_initialize() != ERROR_SUCCESS)
            return {};

        RuleDelivery::FetchResult delivery = RuleDelivery::FetchRules(detect.pin);

        if (!delivery.ok || delivery.rulesLength == 0)
        {
            yr_finalize();
            return {};
        }

        try { (void)GetLOLDriversHashes(); } catch (...) {}

        const int64_t scanEpoch = static_cast<int64_t>(std::time(nullptr));

        YR_RULES* rules = nullptr;
        {
            std::string source(reinterpret_cast<const char*>(delivery.plaintext.data()),
                               delivery.rulesLength);
            s_ruleNames = RuleDelivery::ParseNameTable(source.data(), source.size());
            rules = YaraCompile::CompileAll(source, scanEpoch);
            CrashShield::SecureWipe(&source[0], source.size());
        }

        delivery.plaintext.wipe();

        if (!rules)
        {
            yr_finalize();
            return {};
        }

        unsigned hw = std::thread::hardware_concurrency();
        unsigned workers = std::clamp(hw * 2, 4u, 32u);
        auto     drives = GetAllDrives();

        s_startTime = std::chrono::steady_clock::now();

        std::thread progress(ProgressThread);

        std::vector<std::thread> pool;
        pool.reserve(workers);
        for (unsigned i = 0; i < workers; ++i)
            pool.emplace_back(ScanWorker, rules);

        std::vector<std::thread> enumerators;
        enumerators.reserve(drives.size());
        for (auto& d : drives)
            enumerators.emplace_back(EnumerateFiles, d);

        for (auto& t : enumerators) t.join();
        s_queue.SetDone();
        for (auto& t : pool) t.join();
        s_scanDone.store(true);
        progress.join();

        auto sec = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - s_startTime).count();

        yr_rules_destroy(rules);
        yr_finalize();

        return {
            s_filesScanned.load(),
            s_filesSkipped.load(),
            s_detections.load(),
            s_errors.load(),
            s_bytesScanned.load(),
            sec,
            s_abort.load()
        };
    }
    catch (...) { return {}; }
}

void YaraScanner::start_yara_scan()
{
    try
    {
        YaraScanner::yara_Scanner();
    }
    catch (...) { return; }
}
