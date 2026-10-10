#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <ncrypt.h>
#include <bcrypt.h>
#include <wbemidl.h>
#include <winioctl.h>

#include "../crypt/cng_crypto.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "ncrypt.lib")

namespace hardware_trust
{

constexpr uint32_t bit_tpm_present            = 1u << 0;
constexpr uint32_t bit_tpm_quote_ok           = 1u << 1;
constexpr uint32_t bit_secure_boot_enabled    = 1u << 2;
constexpr uint32_t bit_hvci_enabled           = 1u << 3;
constexpr uint32_t bit_defender_enabled       = 1u << 4;
constexpr uint32_t bit_bitlocker_active       = 1u << 5;
constexpr uint32_t bit_boot_time_disagreement = 1u << 6;
constexpr uint32_t bit_install_disagreement   = 1u << 7;
constexpr uint32_t bit_hostname_disagreement  = 1u << 8;
constexpr uint32_t bit_fingerprint_ok         = 1u << 9;
constexpr uint32_t bit_tpm_probe_failed       = 1u << 10;
constexpr uint32_t bit_vm_indicators          = 1u << 11;
constexpr uint32_t bit_test_mode              = 1u << 12;

constexpr size_t max_tpm_pubkey_bytes = 1024;
constexpr size_t max_tpm_sig_bytes    = 512;

struct posture
{
    uint32_t             bits                = 0;
    uint8_t              fingerprint[32]     = {};
    uint64_t             boot_time_registry  = 0;
    uint64_t             boot_time_perf      = 0;
    uint64_t             install_time        = 0;
    std::vector<uint8_t> tpm_pub_key_blob;
    std::vector<uint8_t> tpm_quote;
};

inline auto reg_read_qword(HKEY root, const wchar_t* subkey, const wchar_t* name) noexcept -> uint64_t
{
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return 0;
    DWORD type = 0;
    uint64_t v = 0;
    DWORD sz = sizeof(v);
    LSTATUS r = RegQueryValueExW(h, name, nullptr, &type, reinterpret_cast<LPBYTE>(&v), &sz);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS) return 0;
    return v;
}

inline auto reg_read_dword(HKEY root, const wchar_t* subkey, const wchar_t* name) noexcept -> uint32_t
{
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return 0;
    DWORD type = 0;
    DWORD v = 0;
    DWORD sz = sizeof(v);
    LSTATUS r = RegQueryValueExW(h, name, nullptr, &type, reinterpret_cast<LPBYTE>(&v), &sz);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS) return 0;
    return v;
}

inline auto reg_read_string(HKEY root, const wchar_t* subkey, const wchar_t* name) noexcept -> std::wstring
{
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return {};
    DWORD type = 0;
    wchar_t buf[512];
    DWORD sz = sizeof(buf);
    LSTATUS r = RegQueryValueExW(h, name, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &sz);
    RegCloseKey(h);
    if (r != ERROR_SUCCESS) return {};
    return std::wstring(buf, sz / sizeof(wchar_t));
}

inline auto probe_secure_boot() noexcept -> bool
{
    const uint32_t v = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"),
        xorstr_(L"UEFISecureBootEnabled"));
    return v == 1;
}

inline auto probe_hvci() noexcept -> bool
{
    const uint32_t v = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"),
        xorstr_(L"Enabled"));
    return v == 1;
}

inline auto probe_test_mode() noexcept -> bool
{
    const uint32_t v = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\CI\\Config"),
        xorstr_(L"VulnerableDriverBlocklistEnable"));
    (void)v;
    const uint32_t testsign = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\CI"),
        xorstr_(L"TESTSIGNING"));
    return testsign == 1;
}

inline auto probe_defender_enabled() noexcept -> bool
{
    const uint32_t disabled = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SOFTWARE\\Microsoft\\Windows Defender"),
        xorstr_(L"DisableAntiSpyware"));
    if (disabled == 1) return false;
    const uint32_t rt = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection"),
        xorstr_(L"DisableRealtimeMonitoring"));
    return rt == 0;
}

inline auto probe_bitlocker_active() noexcept -> bool
{
    HKEY h;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\BitLocker"), 0, KEY_READ, &h) != ERROR_SUCCESS)
        return false;
    RegCloseKey(h);
    return true;
}

inline auto probe_boot_time_registry() noexcept -> uint64_t
{
    const uint32_t v = reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Windows"),
        xorstr_(L"ShutdownTime"));
    (void)v;
    ULONGLONG uptime_ms = GetTickCount64();
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER now;
    now.LowPart  = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;
    const uint64_t now_unix = (now.QuadPart / 10000000ULL) - 11644473600ULL;
    return now_unix - (uptime_ms / 1000ULL);
}

inline auto probe_boot_time_perf() noexcept -> uint64_t
{
    LARGE_INTEGER freq, counter;
    if (!QueryPerformanceFrequency(&freq) || !QueryPerformanceCounter(&counter)) return 0;
    if (freq.QuadPart == 0) return 0;
    const uint64_t uptime_s = uint64_t(counter.QuadPart) / uint64_t(freq.QuadPart);
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER now;
    now.LowPart  = ft.dwLowDateTime;
    now.HighPart = ft.dwHighDateTime;
    const uint64_t now_unix = (now.QuadPart / 10000000ULL) - 11644473600ULL;
    return now_unix - uptime_s;
}

inline auto probe_install_time_registry() noexcept -> uint64_t
{
    return uint64_t(reg_read_dword(HKEY_LOCAL_MACHINE,
        xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"),
        xorstr_(L"InstallDate")));
}

inline auto sha256_hash(const uint8_t* data, size_t len, uint8_t out[32]) noexcept -> bool
{
    return Cng::Sha256Once(data, len, out);
}

inline auto smbios_uuid() noexcept -> std::vector<uint8_t>
{
    UINT need = GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
    if (need == 0) return {};
    std::vector<uint8_t> buf(need, 0);
    UINT got = GetSystemFirmwareTable('RSMB', 0, buf.data(), need);
    if (got != need) return {};
    return buf;
}

inline auto disk_serial_hash(uint8_t out[32]) noexcept -> bool
{
    HANDLE h = CreateFileW(xorstr_(L"\\\\.\\PhysicalDrive0"), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceProperty;
    q.QueryType  = PropertyStandardQuery;

    uint8_t buf[2048] = {};
    DWORD ret = 0;
    const BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                                     &q, sizeof(q), buf, sizeof(buf), &ret, nullptr);
    CloseHandle(h);
    if (!ok || ret < sizeof(STORAGE_DEVICE_DESCRIPTOR)) return false;

    auto* d = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(buf);
    if (d->SerialNumberOffset == 0 || d->SerialNumberOffset >= ret) return false;
    const char* serial = reinterpret_cast<const char*>(buf) + d->SerialNumberOffset;
    const size_t max_len = ret - d->SerialNumberOffset;
    size_t slen = 0;
    while (slen < max_len && serial[slen] != '\0') ++slen;
    if (slen == 0) return false;

    return Cng::Sha256Once(reinterpret_cast<const uint8_t*>(serial), slen, out);
}

struct rtl_osversion_local
{
    ULONG dwOSVersionInfoSize;
    ULONG dwMajorVersion;
    ULONG dwMinorVersion;
    ULONG dwBuildNumber;
    ULONG dwPlatformId;
    WCHAR szCSDVersion[128];
};

inline auto os_build_info(uint32_t& major, uint32_t& minor, uint32_t& build) noexcept -> void
{
    major = 0; minor = 0; build = 0;
    HMODULE nt = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!nt) return;
    using RtlGetVersionFn = LONG (WINAPI*)(rtl_osversion_local*);
    auto rtl = reinterpret_cast<RtlGetVersionFn>(GetProcAddress(nt, xorstr_("RtlGetVersion")));
    if (!rtl) return;
    rtl_osversion_local v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (rtl(&v) != 0) return;
    major = v.dwMajorVersion;
    minor = v.dwMinorVersion;
    build = v.dwBuildNumber;
}

inline auto machine_fingerprint(uint8_t out[32]) noexcept -> bool
{
    Cng::AlgHandle sha;
    if (!Cng::OpenAlg(sha, BCRYPT_SHA256_ALGORITHM)) return false;
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(sha.h, &hh, nullptr, 0, nullptr, 0, 0) != STATUS_SUCCESS) return false;

    const auto rsmb = smbios_uuid();
    if (!rsmb.empty()) BCryptHashData(hh, const_cast<PUCHAR>(rsmb.data()), ULONG(rsmb.size()), 0);

    wchar_t host[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD hlen = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(host, &hlen))
        BCryptHashData(hh, reinterpret_cast<PUCHAR>(host), hlen * sizeof(wchar_t), 0);

    std::wstring product_id = reg_read_string(HKEY_LOCAL_MACHINE,
        xorstr_(L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"), xorstr_(L"ProductId"));
    if (!product_id.empty())
        BCryptHashData(hh, reinterpret_cast<PUCHAR>(product_id.data()),
                       ULONG(product_id.size() * sizeof(wchar_t)), 0);

    std::wstring machine_guid = reg_read_string(HKEY_LOCAL_MACHINE,
        xorstr_(L"SOFTWARE\\Microsoft\\Cryptography"), xorstr_(L"MachineGuid"));
    if (!machine_guid.empty())
        BCryptHashData(hh, reinterpret_cast<PUCHAR>(machine_guid.data()),
                       ULONG(machine_guid.size() * sizeof(wchar_t)), 0);

    uint8_t disk[32] = {};
    if (disk_serial_hash(disk))
        BCryptHashData(hh, disk, 32, 0);

    uint32_t vmaj = 0, vmin = 0, vbuild = 0;
    os_build_info(vmaj, vmin, vbuild);
    uint32_t triple[3] = { vmaj, vmin, vbuild };
    BCryptHashData(hh, reinterpret_cast<PUCHAR>(triple), sizeof(triple), 0);

    BCryptFinishHash(hh, out, 32, 0);
    BCryptDestroyHash(hh);
    return true;
}

inline auto probe_vm_indicators() noexcept -> bool
{
    const std::wstring sys_manufacturer = reg_read_string(HKEY_LOCAL_MACHINE,
        xorstr_(L"HARDWARE\\DESCRIPTION\\System\\BIOS"), xorstr_(L"SystemManufacturer"));
    const std::wstring sys_product = reg_read_string(HKEY_LOCAL_MACHINE,
        xorstr_(L"HARDWARE\\DESCRIPTION\\System\\BIOS"), xorstr_(L"SystemProductName"));
    auto contains_ci = [](const std::wstring& s, const wchar_t* needle) {
        std::wstring low; low.reserve(s.size());
        for (wchar_t c : s) low.push_back((c >= L'A' && c <= L'Z') ? wchar_t(c + 32) : c);
        std::wstring n; n.reserve(wcslen(needle));
        for (const wchar_t* p = needle; *p; ++p) n.push_back((*p >= L'A' && *p <= L'Z') ? wchar_t(*p + 32) : *p);
        return low.find(n) != std::wstring::npos;
    };
    static const std::wstring vmm[] = { xorstr_(L"vmware"), xorstr_(L"virtualbox"), xorstr_(L"qemu"), xorstr_(L"kvm"), xorstr_(L"xen"), xorstr_(L"parallels"), xorstr_(L"hyper-v"), xorstr_(L"innotek") };
    for (const auto& n : vmm)
    {
        if (contains_ci(sys_manufacturer, n.c_str()) || contains_ci(sys_product, n.c_str())) return true;
    }
    return false;
}

inline auto tpm_sign(const uint8_t challenge[32],
                    std::vector<uint8_t>& out_pubkey_blob,
                    std::vector<uint8_t>& out_signature,
                    uint32_t& out_bits) noexcept -> bool
{
    NCRYPT_PROV_HANDLE prov = 0;
    if (NCryptOpenStorageProvider(&prov, MS_PLATFORM_CRYPTO_PROVIDER, 0) != ERROR_SUCCESS)
    {
        out_bits |= bit_tpm_probe_failed;
        return false;
    }
    out_bits |= bit_tpm_present;

    NCRYPT_KEY_HANDLE key = 0;
    std::wstring key_name = xorstr_(L"detect-ss-attest-v1");

    SECURITY_STATUS ss = NCryptOpenKey(prov, &key, key_name.c_str(), 0, 0);
    if (ss != ERROR_SUCCESS)
    {
        ss = NCryptCreatePersistedKey(prov, &key, BCRYPT_RSA_ALGORITHM, key_name.c_str(), 0, 0);
        if (ss != ERROR_SUCCESS) { NCryptFreeObject(prov); return false; }
        DWORD keylen = 2048;
        NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, reinterpret_cast<PBYTE>(&keylen), sizeof(keylen), 0);
        DWORD ex_pol = NCRYPT_ALLOW_SIGNING_FLAG;
        NCryptSetProperty(key, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&ex_pol), sizeof(ex_pol), 0);
        if (NCryptFinalizeKey(key, 0) != ERROR_SUCCESS)
        {
            NCryptFreeObject(key); NCryptFreeObject(prov); return false;
        }
    }

    DWORD needed = 0;
    if (NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, nullptr, 0, &needed, 0) != ERROR_SUCCESS ||
        needed == 0 || needed > max_tpm_pubkey_bytes)
    {
        NCryptFreeObject(key); NCryptFreeObject(prov); return false;
    }
    out_pubkey_blob.assign(needed, 0);
    DWORD out_size = 0;
    if (NCryptExportKey(key, 0, BCRYPT_RSAPUBLIC_BLOB, nullptr, out_pubkey_blob.data(),
                        needed, &out_size, 0) != ERROR_SUCCESS)
    {
        out_pubkey_blob.clear();
        NCryptFreeObject(key); NCryptFreeObject(prov); return false;
    }
    out_pubkey_blob.resize(out_size);

    BCRYPT_PKCS1_PADDING_INFO pad{};
    pad.pszAlgId = BCRYPT_SHA256_ALGORITHM;

    DWORD sig_len = 0;
    if (NCryptSignHash(key, &pad, const_cast<PBYTE>(challenge), 32,
                       nullptr, 0, &sig_len, BCRYPT_PAD_PKCS1) != ERROR_SUCCESS ||
        sig_len == 0 || sig_len > max_tpm_sig_bytes)
    {
        NCryptFreeObject(key); NCryptFreeObject(prov); return false;
    }
    out_signature.assign(sig_len, 0);
    DWORD actual = 0;
    if (NCryptSignHash(key, &pad, const_cast<PBYTE>(challenge), 32,
                       out_signature.data(), sig_len, &actual, BCRYPT_PAD_PKCS1) != ERROR_SUCCESS)
    {
        out_signature.clear();
        NCryptFreeObject(key); NCryptFreeObject(prov); return false;
    }
    out_signature.resize(actual);

    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    out_bits |= bit_tpm_quote_ok;
    return true;
}

inline auto capture(const uint8_t challenge[32]) noexcept -> posture
{
    posture p{};

    if (probe_secure_boot())   p.bits |= bit_secure_boot_enabled;
    if (probe_hvci())          p.bits |= bit_hvci_enabled;
    if (probe_defender_enabled()) p.bits |= bit_defender_enabled;
    if (probe_bitlocker_active()) p.bits |= bit_bitlocker_active;
    if (probe_test_mode())     p.bits |= bit_test_mode;
    if (probe_vm_indicators()) p.bits |= bit_vm_indicators;

    p.boot_time_registry = probe_boot_time_registry();
    p.boot_time_perf     = probe_boot_time_perf();

    if (p.boot_time_registry && p.boot_time_perf)
    {
        const uint64_t diff = (p.boot_time_registry > p.boot_time_perf)
            ? (p.boot_time_registry - p.boot_time_perf)
            : (p.boot_time_perf - p.boot_time_registry);
        if (diff > 30) p.bits |= bit_boot_time_disagreement;
    }

    p.install_time = probe_install_time_registry();

    if (machine_fingerprint(p.fingerprint)) p.bits |= bit_fingerprint_ok;

    if (challenge)
    {
        (void)tpm_sign(challenge, p.tpm_pub_key_blob, p.tpm_quote, p.bits);
    }

    return p;
}

}
