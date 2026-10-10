#include "trust.h"
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <wincrypt.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace atlas {
namespace {

std::map<std::wstring, SigInfo> g_sigCache;
std::map<std::wstring, std::pair<Trust, std::string>> g_trustCache;

const std::string* GetTrustedPublishers(size_t* countOut) {
    static const std::string kTrustedPublishers[] = {
        xorstr_("Microsoft Corporation"),
        xorstr_("Microsoft Windows"),
        xorstr_("Oracle America"),
        xorstr_("Oracle Corporation"),
        xorstr_("Azul Systems"),
        xorstr_("Eclipse Foundation"),
        xorstr_("Eclipse Adoptium"),
        xorstr_("Amazon.com Services"),
        xorstr_("Amazon Web Services"),
        xorstr_("BellSoft"),
        xorstr_("SAP SE"),
        xorstr_("Red Hat"),
        xorstr_("IBM"),
        xorstr_("JetBrains"),
        xorstr_("NVIDIA Corporation"),
        xorstr_("Advanced Micro Devices"),
        xorstr_("Intel Corporation"),
        xorstr_("Realtek Semiconductor"),
        xorstr_("Mojang"),
        xorstr_("Microsoft Studios"),
        xorstr_("Moonsworth"),
        xorstr_("Badlion"),
        xorstr_("Feather Client"),
        xorstr_("InPvP"),
        xorstr_("Overwolf"),
        xorstr_("Discord Inc"),
        xorstr_("Valve Corp"),
        xorstr_("Epic Games"),
        xorstr_("OBS Project"),
        xorstr_("Logitech"),
        xorstr_("Razer"),
        xorstr_("SteelSeries"),
        xorstr_("Corsair Memory"),
        xorstr_("Google LLC"),
        xorstr_("Mozilla Corporation"),
        xorstr_("Riot Games"),
        xorstr_("Elgato Systems"),
        xorstr_("Micro-Star INT"),
        xorstr_("Unwinder"),
        xorstr_("TechPowerUp"),
        xorstr_("Bitdefender"), xorstr_("ESET"), xorstr_("Avast"), xorstr_("AVG Technologies"), xorstr_("Malwarebytes"),
        xorstr_("Kaspersky"), xorstr_("McAfee"), xorstr_("Sophos"), xorstr_("Trend Micro"), xorstr_("CrowdStrike"),
        xorstr_("SentinelOne"), xorstr_("Symantec"), xorstr_("NortonLifeLock"), xorstr_("Gen Digital"), xorstr_("Webroot"),
        xorstr_("Cisco Systems"),
        xorstr_("VMware"),
        xorstr_("Citrix"),
        xorstr_("Dell Technologies"), xorstr_("HP Inc"), xorstr_("Lenovo"), xorstr_("ASUSTeK"), xorstr_("Gigabyte Technology"), xorstr_("Acer Incorporated"),
    };
    *countOut = sizeof(kTrustedPublishers) / sizeof(kTrustedPublishers[0]);
    return kTrustedPublishers;
}

const std::wstring* GetExpectedNativeNames(size_t* countOut) {
    static const std::wstring kExpectedNativeNames[] = {
        xorstr_(L"lwjgl.dll"), xorstr_(L"lwjgl64.dll"), xorstr_(L"lwjgl_opengl.dll"), xorstr_(L"lwjgl_stb.dll"),
        xorstr_(L"lwjgl_tinyfd.dll"), xorstr_(L"lwjgl_remotery.dll"), xorstr_(L"lwjgl_opengles.dll"),
        xorstr_(L"openal.dll"), xorstr_(L"openal32.dll"), xorstr_(L"openal64.dll"), xorstr_(L"soft_oal.dll"),
        xorstr_(L"jinput-dx8.dll"), xorstr_(L"jinput-dx8_64.dll"), xorstr_(L"jinput-raw.dll"), xorstr_(L"jinput-raw_64.dll"),
        xorstr_(L"jinput-wintab.dll"),
        xorstr_(L"glfw.dll"), xorstr_(L"glfw3.dll"),
        xorstr_(L"texture_packer.dll"),
        xorstr_(L"twitch-platform.dll"), xorstr_(L"twitchsdk.dll"),
        xorstr_(L"liblwjgl.dll"),
    };
    *countOut = sizeof(kExpectedNativeNames) / sizeof(kExpectedNativeNames[0]);
    return kExpectedNativeNames;
}

bool InTrustedDirectory(const std::wstring& lower) {
    static const std::wstring kDirs[] = {
        xorstr_(L"\\windows\\system32\\"),
        xorstr_(L"\\windows\\syswow64\\"),
        xorstr_(L"\\windows\\winsxs\\"),
    };
    for (const auto& d : kDirs) if (lower.find(d) != std::wstring::npos) return true;
    return false;
}

bool LooksLikeJreDirectory(const std::wstring& lower) {
    static const std::wstring kMarkers[] = {
        xorstr_(L"\\jre\\bin\\"), xorstr_(L"\\jdk\\bin\\"), xorstr_(L"\\bin\\server\\"), xorstr_(L"\\bin\\client\\"),
        xorstr_(L"\\java\\"), xorstr_(L"\\jre-"), xorstr_(L"\\jdk-"), xorstr_(L"\\zulu"), xorstr_(L"\\corretto"), xorstr_(L"\\temurin"),
        xorstr_(L"\\runtime\\"), xorstr_(L"\\jbr\\bin\\"),
    };
    for (const auto& m : kMarkers) if (lower.find(m) != std::wstring::npos) return true;
    return false;
}

bool LooksLikeNativesDirectory(const std::wstring& lower) {
    static const std::wstring kMarkers[] = {
        xorstr_(L"-natives-"), xorstr_(L"\\natives\\"), xorstr_(L"\\natives-"), xorstr_(L"\\bin\\natives"),
        xorstr_(L"\\.minecraft\\"), xorstr_(L"\\lunarclient\\"), xorstr_(L"\\badlion"), xorstr_(L"\\.feather\\"),
        xorstr_(L"\\prismlauncher\\"), xorstr_(L"\\multimc\\"), xorstr_(L"\\modrinthapp\\"),
        xorstr_(L"\\.lunarclient\\"), xorstr_(L"\\lunar client\\"), xorstr_(L"\\blclient\\"),
        xorstr_(L"\\offline\\multiver\\"), xorstr_(L"\\native-modules\\"), xorstr_(L"\\labymod"),
        xorstr_(L"\\temp\\lwjgl"),
    };
    for (const auto& m : kMarkers) if (lower.find(m) != std::wstring::npos) return true;
    return false;
}

bool MatchesTempExtractPattern(const std::wstring& name) {
    static const std::wstring kStems[] = {
        xorstr_(L"jna"), xorstr_(L"liblz4-java-"), xorstr_(L"lz4-java-"), xorstr_(L"jansi-"), xorstr_(L"jline-"),
        xorstr_(L"sqlite-"), xorstr_(L"netty_"), xorstr_(L"netty-"), xorstr_(L"jnativehook"),
    };
    for (const auto& stem : kStems) {
        size_t n = stem.size();
        if (name.size() <= n || name.compare(0, n, stem) != 0) continue;
        size_t i = n, digits = 0;
        while (i < name.size() && iswdigit(name[i])) { ++i; ++digits; }
        if (digits < 4) continue;
        std::wstring ext = name.substr(i);
        if (ext == xorstr_(L".dll") || ext == xorstr_(L".so")) return true;
    }
    return false;
}

SigInfo VerifyCatalog(const std::wstring& path) {
    SigInfo si;
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) { si.status = xorstr_("open failed"); return si; }

    HCATADMIN admin = nullptr;
    GUID action = DRIVER_ACTION_VERIFY;
    if (!CryptCATAdminAcquireContext(&admin, &action, 0)) {
        CloseHandle(hFile);
        si.status = xorstr_("catalog ctx failed");
        return si;
    }

    DWORD hashLen = 0;
    CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, nullptr, 0);
    std::vector<BYTE> hash(hashLen ? hashLen : 32);
    if (hashLen && CryptCATAdminCalcHashFromFileHandle(hFile, &hashLen, hash.data(), 0)) {
        HCATINFO cat = CryptCATAdminEnumCatalogFromHash(admin, hash.data(), hashLen, 0, nullptr);
        if (cat) {
            CATALOG_INFO ci{};
            ci.cbStruct = sizeof(ci);
            if (CryptCATCatalogInfoFromContext(cat, &ci, 0)) {
                std::wstring memberTag;
                memberTag.reserve((size_t)hashLen * 2);
                for (DWORD i = 0; i < hashLen; ++i) {
                    wchar_t b[3];
                    swprintf_s(b, xorstr_(L"%02X"), hash[i]);
                    memberTag += b;
                }
                WINTRUST_CATALOG_INFO wci{};
                wci.cbStruct = sizeof(wci);
                wci.pcwszCatalogFilePath = ci.wszCatalogFile;
                wci.pcwszMemberFilePath  = path.c_str();
                wci.pcwszMemberTag       = memberTag.c_str();
                wci.hMemberFile          = hFile;
                wci.pbCalculatedFileHash = hash.data();
                wci.cbCalculatedFileHash = hashLen;

                WINTRUST_DATA wd{};
                wd.cbStruct         = sizeof(wd);
                wd.dwUIChoice       = WTD_UI_NONE;
                wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wd.dwUnionChoice    = WTD_CHOICE_CATALOG;
                wd.pCatalog         = &wci;
                wd.dwStateAction    = WTD_STATEACTION_VERIFY;
                wd.dwProvFlags      = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

                GUID pol = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                LONG rc = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &pol, &wd);
                si.present = true;
                si.valid   = (rc == ERROR_SUCCESS);
                if (si.valid) si.subject = xorstr_("Microsoft Windows (catalog)");
                else          si.status  = xorstr_("e");

                wd.dwStateAction = WTD_STATEACTION_CLOSE;
                WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &pol, &wd);
            }
            CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        } else {
            si.status = xorstr_("no catalog entry");
        }
    }
    CryptCATAdminReleaseContext(admin, 0);
    CloseHandle(hFile);
    return si;
}

std::string SubjectOfEmbedded(const std::wstring& path) {
    DWORD encoding = 0, contentType = 0, formatType = 0;
    HCERTSTORE store = nullptr;
    HCRYPTMSG msg = nullptr;
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                          &encoding, &contentType, &formatType, &store, &msg, nullptr)) {
        return std::string();
    }
    std::string subject;
    DWORD siLen = 0;
    if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &siLen) && siLen) {
        std::vector<BYTE> buf(siLen);
        if (CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &siLen)) {
            CMSG_SIGNER_INFO* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());
            CERT_INFO ci{};
            ci.Issuer       = si->Issuer;
            ci.SerialNumber = si->SerialNumber;
            PCCERT_CONTEXT cert = CertFindCertificateInStore(
                store, encoding, 0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);
            if (cert) {
                DWORD n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0,
                                             nullptr, nullptr, 0);
                if (n > 1) {
                    std::wstring name(n, L'\0');
                    CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr,
                                       name.data(), n);
                    name.resize(wcslen(name.c_str()));
                    subject = WideToUtf8(name);
                }
                CertFreeCertificateContext(cert);
            }
        }
    }
    if (msg) CryptMsgClose(msg);
    if (store) CertCloseStore(store, 0);
    return subject;
}

}

const char* TrustName(Trust t) {
    static const std::string kUnknown       = xorstr_("untrusted");
    static const std::string kPathTrusted   = xorstr_("expected-unsigned");
    static const std::string kSigned        = xorstr_("signed");
    static const std::string kTrustedVendor = xorstr_("trusted-vendor");
    static const std::string kFallback      = xorstr_("?");
    switch (t) {
        case Trust::Unknown:       return kUnknown.c_str();
        case Trust::PathTrusted:   return kPathTrusted.c_str();
        case Trust::Signed:        return kSigned.c_str();
        case Trust::TrustedVendor: return kTrustedVendor.c_str();
    }
    return kFallback.c_str();
}

SigInfo VerifyFile(const std::wstring& path) {
    if (path.empty()) return SigInfo();
    std::wstring key = ToLowerW(path);
    std::map<std::wstring, SigInfo>::iterator it = g_sigCache.find(key);
    if (it != g_sigCache.end()) return it->second;

    SigInfo si;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct  = sizeof(fi);
    fi.pcwszFilePath = path.c_str();

    WINTRUST_DATA wd{};
    wd.cbStruct     = sizeof(wd);
    wd.dwUIChoice   = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile        = &fi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags  = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;

    GUID pol = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG rc = WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &pol, &wd);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust((HWND)INVALID_HANDLE_VALUE, &pol, &wd);

    if (rc == ERROR_SUCCESS) {
        si.present = true;
        si.valid   = true;
        si.subject = SubjectOfEmbedded(path);
    } else if ((DWORD)rc == (DWORD)TRUST_E_NOSIGNATURE ||
               (DWORD)rc == (DWORD)TRUST_E_SUBJECT_FORM_UNKNOWN ||
               (DWORD)rc == (DWORD)TRUST_E_PROVIDER_UNKNOWN) {
        si = VerifyCatalog(path);
        if (!si.valid && si.status.empty()) si.status = xorstr_("unsigned");
    } else {
        si.present = true;
        si.valid   = false;
        si.status  = xorstr_("e");
        si.subject = SubjectOfEmbedded(path);
    }
    g_sigCache[key] = si;
    return si;
}

bool IsTrustedPublisher(const std::string& subject) {
    if (subject.empty()) return false;
    size_t count = 0;
    const std::string* pubs = GetTrustedPublishers(&count);
    for (size_t i = 0; i < count; ++i)
        if (IContains(subject, pubs[i])) return true;
    return false;
}

bool IsExpectedUnsignedNative(const std::wstring& path) {
    std::wstring lower = ToLowerW(path);
    std::wstring name  = FileNameOfW(lower);
    size_t count = 0;
    const std::wstring* names = GetExpectedNativeNames(&count);
    bool nameKnown = false;
    for (size_t i = 0; i < count; ++i)
        if (name == names[i]) { nameKnown = true; break; }
    if (!nameKnown) return false;
    return LooksLikeNativesDirectory(lower) || LooksLikeJreDirectory(lower);
}

bool IsLauncherOwnedPath(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring lower = ToLowerW(path);
    return LooksLikeNativesDirectory(lower) || LooksLikeJreDirectory(lower);
}

bool IsKnownTempExtractedNative(const std::wstring& path) {
    if (path.empty()) return false;
    std::wstring lower = ToLowerW(path);
    std::wstring name  = FileNameOfW(lower);

    bool inTemp = lower.find(xorstr_(L"\\appdata\\local\\temp\\")) != std::wstring::npos ||
                  lower.find(xorstr_(L"\\windows\\temp\\")) != std::wstring::npos;
    if (!inTemp) return false;

    if (MatchesTempExtractPattern(name)) return true;

    static const std::wstring kFixed[] = {
        xorstr_(L"jemalloc.dll"), xorstr_(L"webp-imageio.dll"), xorstr_(L"webp-imageio64.dll"),
        xorstr_(L"lz4-java.dll"), xorstr_(L"jansi.dll"), xorstr_(L"sqlitejdbc.dll"), xorstr_(L"odinwrapper.dll"),
    };
    for (const auto& f : kFixed) if (name == f) return true;
    return false;
}

Trust ClassifyModule(const std::wstring& path, std::string* signerOut) {
    if (path.empty()) { if (signerOut) signerOut->clear(); return Trust::Unknown; }
    std::wstring key = ToLowerW(path);
    std::map<std::wstring, std::pair<Trust, std::string> >::iterator it = g_trustCache.find(key);
    if (it != g_trustCache.end()) {
        if (signerOut) *signerOut = it->second.second;
        return it->second.first;
    }

    Trust t = Trust::Unknown;
    SigInfo si = VerifyFile(path);
    std::string signer = si.subject;

    if (si.valid) {
        t = IsTrustedPublisher(si.subject) ? Trust::TrustedVendor : Trust::Signed;
    } else if (InTrustedDirectory(key)) {
        t = Trust::PathTrusted;
        if (signer.empty()) signer = xorstr_("(system directory)");
    } else if (IsExpectedUnsignedNative(path)) {
        t = Trust::PathTrusted;
        if (signer.empty()) signer = xorstr_("(expected native)");
    } else if (IsKnownTempExtractedNative(path)) {
        t = Trust::PathTrusted;
        if (signer.empty()) signer = xorstr_("(temp-extracted native)");
    } else if (IsLauncherOwnedPath(path)) {
        t = Trust::PathTrusted;
        if (signer.empty()) signer = xorstr_("(launcher directory)");
    } else if (LooksLikeJreDirectory(key) && si.status == xorstr_("unsigned")) {
        t = Trust::PathTrusted;
        if (signer.empty()) signer = xorstr_("(JRE directory)");
    }

    g_trustCache[key] = std::make_pair(t, signer);
    if (signerOut) *signerOut = signer;
    return t;
}

void ClearTrustCache() {
    g_sigCache.clear();
    g_trustCache.clear();
}

}
