#include "c_executed_files_detection.h"

std::vector<BAMEntry> BAMParser::entries;

bool BAMParser::CompareExecutionTime(const BAMEntry& entry1, const BAMEntry& entry2) {
    try{
    FILETIME ft1 = BAMParser::StringToFileTimeUTC(entry1.executionTime);
    FILETIME ft2 = BAMParser::StringToFileTimeUTC(entry2.executionTime);
    return CompareFileTime(&ft1, &ft2) < 0;
    }
    catch (...) { return false; }
}


std::vector<LogonSessionInfo> BAMParser::GetInteractiveLogonSessions() {
    try{
    std::vector<LogonSessionInfo> sessions;
    ULONG logonSessionCount = 0;
    PLUID logonSessionList = NULL;

    NTSTATUS status = LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
    if (status != STATUS_SUCCESS || !logonSessionList) {
        return sessions;
    }

    for (ULONG i = 0; i < logonSessionCount; i++) {
        PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
        status = LsaGetLogonSessionData(&logonSessionList[i], &sessionData);
        if (status == STATUS_SUCCESS && sessionData != NULL) {
            if (sessionData->LogonType == Interactive ||
                sessionData->LogonType == RemoteInteractive) {
                LogonSessionInfo info;

                FILETIME utcLogonTime;
                utcLogonTime.dwLowDateTime = sessionData->LogonTime.LowPart;
                utcLogonTime.dwHighDateTime = sessionData->LogonTime.HighPart;

                info.logonTime = utcLogonTime;
                info.sessionId = sessionData->Session;
                info.isInteractive = true;
                sessions.push_back(info);
            }
            LsaFreeReturnBuffer(sessionData);
        }
    }

    if (logonSessionList) {
        LsaFreeReturnBuffer(logonSessionList);
    }
    return sessions;
}
catch (...) { return {}; }
}


bool BAMParser::VerifyFileViaCatalog(LPCWSTR filePath) {
    try{
    HANDLE hCatAdmin = NULL;
    if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0)) {
        return false;
    }

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    DWORD dwHashSize = 0;
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, NULL, 0) || dwHashSize == 0) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    std::vector<BYTE> pbHash(dwHashSize);
    if (!CryptCATAdminCalcHashFromFileHandle(hFile, &dwHashSize, pbHash.data(), 0)) {
        CloseHandle(hFile);
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        return false;
    }

    CloseHandle(hFile);

    HANDLE hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash.data(), dwHashSize, 0, NULL);
    bool isCatalogSigned = false;

    while (hCatInfo) {
        CATALOG_INFO catInfo = { sizeof(catInfo) };
        if (!CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
            break;
        }

        WINTRUST_CATALOG_INFO wtc = {};
        wtc.cbStruct = sizeof(wtc);
        wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
        wtc.pbCalculatedFileHash = pbHash.data();
        wtc.cbCalculatedFileHash = dwHashSize;
        wtc.pcwszMemberFilePath = filePath;

        WINTRUST_DATA wtd = {};
        wtd.cbStruct = sizeof(wtd);
        wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
        wtd.pCatalog = &wtc;
        wtd.dwUIChoice = WTD_UI_NONE;
        wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
        wtd.dwProvFlags = 0;
        wtd.dwStateAction = WTD_STATEACTION_VERIFY;

        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG res = WinVerifyTrust(NULL, &action, &wtd);

        wtd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &action, &wtd);

        if (res == ERROR_SUCCESS) {
            isCatalogSigned = true;
            break;
        }
        hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, pbHash.data(), dwHashSize, 0, &hCatInfo);
    }

    if (hCatInfo) {
        CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    }
    CryptCATAdminReleaseContext(hCatAdmin, 0);

    return isCatalogSigned;
    }
    catch (...) { return false; }
}

std::wstring BAMParser::CheckDigitalSignature(const std::wstring& filePath) {
    try{
    static std::unordered_map<std::wstring, std::wstring> sig_cache;
    auto cached = sig_cache.find(filePath);
    if (cached != sig_cache.end()) return cached->second;

    auto cache_and_return = [&](const std::wstring& result) -> std::wstring {
        sig_cache[filePath] = result;
        return result;
    };

    if (!PathFileExistsW(filePath.c_str())) {
        return cache_and_return(xorstr_(L"Not Found"));
    }

    WINTRUST_FILE_INFO fileInfo;
    ZeroMemory(&fileInfo, sizeof(fileInfo));
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath.c_str();

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    ZeroMemory(&winTrustData, sizeof(winTrustData));
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    winTrustData.pFile = &fileInfo;

    LONG lStatus = WinVerifyTrust(NULL, &guidAction, &winTrustData);
    std::wstring result = xorstr_(L"Not signed");

    if (lStatus == ERROR_SUCCESS) {
        result = xorstr_(L"Signed");
        CRYPT_PROVIDER_DATA const* psProvData = WTHelperProvDataFromStateData(winTrustData.hWVTStateData);
        if (psProvData) {
            CRYPT_PROVIDER_DATA* nonConstProvData = const_cast<CRYPT_PROVIDER_DATA*>(psProvData);
            CRYPT_PROVIDER_SGNR* pProvSigner = WTHelperGetProvSignerFromChain(nonConstProvData, 0, FALSE, 0);
            if (pProvSigner) {
                CRYPT_PROVIDER_CERT* pProvCert = WTHelperGetProvCertFromChain(pProvSigner, 0);
                if (pProvCert && pProvCert->pCert) {
                    {
                        char subjectName[256];
                        CertNameToStrA(pProvCert->pCert->dwCertEncodingType,
                            &pProvCert->pCert->pCertInfo->Subject,
                            CERT_X500_NAME_STR,
                            subjectName,
                            sizeof(subjectName));
                        std::string subject(subjectName);
                        std::transform(subject.begin(), subject.end(), subject.begin(), ::tolower);
                        if (subject.find(xorstr_("manthe industries, llc")) != std::string::npos ||
                            subject.find(xorstr_("slinkware")) != std::string::npos) {
                            result = xorstr_(L"Cheat Signature");
                        }
                    }
                    PCCERT_CONTEXT pCert = pProvCert->pCert;

                    DWORD hashSize = 0;
                    if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, nullptr, &hashSize)) {
                        std::vector<BYTE> hash(hashSize);
                        if (CertGetCertificateContextProperty(pCert, CERT_SHA1_HASH_PROP_ID, hash.data(), &hashSize)) {
                            CRYPT_HASH_BLOB hashBlob;
                            hashBlob.cbData = hashSize;
                            hashBlob.pbData = hash.data();

                            HCERTSTORE hStore = CertOpenStore(
                                CERT_STORE_PROV_SYSTEM_W,
                                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                NULL,
                                CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_OPEN_EXISTING_FLAG,
                                xorstr_(L"Root")
                            );

                            if (hStore) {
                                PCCERT_CONTEXT foundCert = CertFindCertificateInStore(
                                    hStore,
                                    pCert->dwCertEncodingType,
                                    0,
                                    CERT_FIND_SHA1_HASH,
                                    &hashBlob,
                                    NULL
                                );

                                if (foundCert) {
                                    result = xorstr_(L"Fake Signature");
                                    CertFreeCertificateContext(foundCert);
                                }

                                CertCloseStore(hStore, 0);
                            }
                        }
                    }
                }
            }
        }
    }
    else {
        if (VerifyFileViaCatalog(filePath.c_str())) {
            return cache_and_return(xorstr_(L"Signed"));
        }
    }

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guidAction, &winTrustData);

    return cache_and_return(result);
    }
    catch (...) { return {}; }
}

bool BAMParser::IsValidTimeFormat(const std::wstring& timeStr) {
    try{
        if (timeStr.length() != 19) return false;
    std::wistringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, xorstr_(L"%Y-%m-%d %H:%M:%S"));
    return !ss.fail();
}
catch (...) { return false; }
}

FILETIME BAMParser::StringToFileTimeUTC(const std::wstring& timeStr) {
    try{
    std::wistringstream ss(timeStr);
    std::tm tm = {};
    ss >> std::get_time(&tm, xorstr_(L"%Y-%m-%d %H:%M:%S"));

    SYSTEMTIME localSt = {
        (WORD)(tm.tm_year + 1900),
        (WORD)(tm.tm_mon + 1),
        (WORD)tm.tm_wday,
        (WORD)tm.tm_mday,
        (WORD)tm.tm_hour,
        (WORD)tm.tm_min,
        (WORD)tm.tm_sec,
        0
    };

    SYSTEMTIME utcSt;
    TzSpecificLocalTimeToSystemTime(NULL, &localSt, &utcSt);

    FILETIME ftUTC;
    SystemTimeToFileTime(&utcSt, &ftUTC);
    return ftUTC;
    }
    catch (...) { return {}; }
}

std::wstring BAMParser::FileTimeToStringLocal(const FILETIME& ft) {
    try{
    FILETIME localFt;
    FileTimeToLocalFileTime(&ft, &localFt);
    SYSTEMTIME st;
    FileTimeToSystemTime(&localFt, &st);

    std::wostringstream oss;
    oss << std::setfill(L'0')
        << st.wYear << xorstr_(L"-")
        << std::setw(2) << st.wMonth << xorstr_(L"-")
        << std::setw(2) << st.wDay << xorstr_(L" ")
        << std::setw(2) << st.wHour << xorstr_(L":")
        << std::setw(2) << st.wMinute << xorstr_(L":")
        << std::setw(2) << st.wSecond;
    return oss.str();
    }
    catch (...) { return {}; }
}

bool BAMParser::IsInCurrentInstance(const std::wstring& execTime) {
    try{
    if (!IsValidTimeFormat(execTime)) {
        return false;
    }

    auto sessions = GetInteractiveLogonSessions();
    if (sessions.empty()) {
        return false;
    }

    const LogonSessionInfo& firstSession = sessions.front();

    SYSTEMTIME utcCurrentSysTime;
    GetSystemTime(&utcCurrentSysTime);
    FILETIME currentTime;
    SystemTimeToFileTime(&utcCurrentSysTime, &currentTime);

    FILETIME execFt = StringToFileTimeUTC(execTime);

    return (CompareFileTime(&execFt, &firstSession.logonTime) >= 0 &&
        CompareFileTime(&execFt, &currentTime) <= 0);
    }
    catch (...) { return false; }
}


std::wstring BAMParser::ConvertHardDiskVolumeToLetter(const std::wstring& path) {
    try{
    wchar_t drives[MAX_PATH];
    if (GetLogicalDriveStringsW(MAX_PATH, drives)) {
        wchar_t volumeName[MAX_PATH];
        std::wstring driveLetter = xorstr_(L" :");

        for (wchar_t* drive = drives; *drive; drive += 4) {
            driveLetter[0] = drive[0];
            if (QueryDosDeviceW(driveLetter.c_str(), volumeName, MAX_PATH)) {
                std::wstring volPath = path;
                std::wstring volName = volumeName;

                if (volPath.find(volName) == 0) {
                    return std::wstring(1, drive[0]) + xorstr_(L":");
                }

                std::wstring globalRootPrefix = xorstr_(L"\\\\?\\GLOBALROOT");
                if (volPath.find(globalRootPrefix) == 0) {
                    volPath = volPath.substr(globalRootPrefix.length());
                    if (volPath.find(volName) == 0) {
                        return std::wstring(1, drive[0]) + xorstr_(L":");
                    }
                }
            }
        }
    }
    return xorstr_(L"?:");
    }
    catch (...) { return {}; }
}

void BAMParser::Parse() {
    try{
    HKEY hKey;
    const wchar_t* keyPath = xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings");

    entries.clear();

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return;
    }

    DWORD subKeyCount = 0;
    if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &subKeyCount, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return;
    }

    auto sessions = GetInteractiveLogonSessions();
    if (sessions.empty()) {
        RegCloseKey(hKey);
        return;
    }

    const LogonSessionInfo& firstSession = sessions.front();

    for (DWORD i = 0; i < subKeyCount; i++) {
        wchar_t subKeyName[256];
        DWORD subKeyNameSize = 256;

        if (RegEnumKeyExW(hKey, i, subKeyName, &subKeyNameSize, nullptr, nullptr,
            nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY hSubKey;
            std::wstring fullSubKeyPath = std::wstring(keyPath) + xorstr_(L"\\") + subKeyName;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, fullSubKeyPath.c_str(), 0,
                KEY_READ, &hSubKey) == ERROR_SUCCESS) {
                DWORD valueCount = 0;
                if (RegQueryInfoKeyW(hSubKey, nullptr, nullptr, nullptr, nullptr, nullptr,
                    nullptr, &valueCount, nullptr, nullptr, nullptr,
                    nullptr) == ERROR_SUCCESS) {

                    std::vector<wchar_t> valueName(32768);
                    std::vector<BYTE> valueData(1024);
                    for (DWORD j = 0; j < valueCount; j++) {
                        DWORD valueNameSize = 32768;
                        DWORD valueDataSize = 1024;
                        DWORD valueType;

                        if (RegEnumValueW(hSubKey, j, valueName.data(), &valueNameSize, nullptr,
                            &valueType, valueData.data(), &valueDataSize) == ERROR_SUCCESS) {
                            if (valueType == REG_BINARY && valueDataSize >= sizeof(FILETIME)) {
                                std::wstring path = valueName.data();
                                if (path.find(L'\\') != std::wstring::npos) {
                                    size_t hdvPos = path.find(xorstr_(L"HarddiskVolume"));
                                    if (hdvPos != std::wstring::npos) {
                                        std::wstring driveLetter = ConvertHardDiskVolumeToLetter(path);
                                        size_t pathStart = path.find(L'\\', hdvPos);
                                        if (pathStart != std::wstring::npos) {
                                            path = driveLetter + path.substr(pathStart);
                                        }
                                    }

                                    FILETIME* ft = reinterpret_cast<FILETIME*>(valueData.data());

                                    std::wstring execLocalStr = FileTimeToStringLocal(*ft);

                                    BAMEntry entry;
                                    entry.path = path;
                                    entry.executionTime = execLocalStr;
                                    entry.signatureStatus = CheckDigitalSignature(path);

                                    entry.isInCurrentInstance = IsInCurrentInstance(entry.executionTime);

                                    if (entry.isInCurrentInstance) {
                                        entries.push_back(entry);
                                    }
                                }
                            }
                        }
                    }
                }
                RegCloseKey(hSubKey);
            }
        }
    }

    std::sort(entries.begin(), entries.end(),
        [](const BAMEntry& entry1, const BAMEntry& entry2) {
            return BAMParser::CompareExecutionTime(entry2, entry1);
        });

    RegCloseKey(hKey);
    }
    catch (...) {}
}


std::string sanitize_string(const std::string& input) {
    try{
    std::string output;
    for (char c : input) {
        if (c >= 32 && c <= 126) {
            output += c;
        }
        else {
            output += '?';
        }
    }
    return output;
    }
    catch (...) { return {}; }
}

std::string wstringToString(const std::wstring& wstr) {
    try{
    if (wstr.empty()) {
        return std::string();
    }

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(),
        nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        return std::string();
    }

    std::string str(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), (int)wstr.size(),
        &str[0], size_needed, nullptr, nullptr);

    return sanitize_string(str);
    }
    catch (...) { return {}; }
}


void BAMParser::start_executed_file_checks() {
    try{
    BAMParser::Parse();
    const std::vector<BAMEntry>& entries = BAMParser::GetEntries();

    for (const auto& entry : entries) {
        std::string sanitizedTime = sanitize_string(utils->convert_wstring_to_string(entry.executionTime));
        std::string sanitizedPath = sanitize_string(utils->convert_wstring_to_string(entry.path));

        if (entry.signatureStatus == xorstr_(L"Cheat Signature")) {
            LOG(DETECTION, sanitizedTime) << xorstr_("Cheat Signed File Executed:") << sanitizedPath;
        }
        else if (entry.signatureStatus == xorstr_(L"Not signed")) {
            LOG(WARNING, sanitizedTime) << xorstr_("Not Signed File Executed:") << sanitizedPath;
        }
        else if (entry.signatureStatus == xorstr_(L"Fake Signature")) {
            LOG(DETECTION, sanitizedTime) << xorstr_("Fake Signed File Executed:") << sanitizedPath;
        }
        else if (entry.signatureStatus == xorstr_(L"Not Found")) {
            //LOG(WARNING, sanitizedTime) << "Not Found File Executed:" << sanitizedPath;
        }
    }
    }
    catch (...) {}
}