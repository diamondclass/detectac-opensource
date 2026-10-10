#include "c_efi_measured_boot.h"
#include "../../utils/fresh_install.h"

#include <bcrypt.h>
#include <tbs.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "tbs.lib")

#ifndef TBS_E_BLOCKED
#define TBS_E_BLOCKED ((TBS_RESULT)0x80284004L)
#endif

namespace {

namespace fs = std::filesystem;

constexpr size_t kSha256Size = 32;
using Sha256 = std::array<uint8_t, kSha256Size>;

struct AlgHandle {
    BCRYPT_ALG_HANDLE h = nullptr;
    ~AlgHandle() {
        try { if (h) BCryptCloseAlgorithmProvider(h, 0); }
        catch (...) {}
    }
};
struct HashHandle {
    BCRYPT_HASH_HANDLE h = nullptr;
    ~HashHandle() {
        try { if (h) BCryptDestroyHash(h); }
        catch (...) {}
    }
};

class Sha256Ctx {
public:
    bool init() {
        try {
            if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
                    &alg_.h, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
                return false;
            }
            return BCRYPT_SUCCESS(BCryptCreateHash(
                alg_.h, &hash_.h, nullptr, 0, nullptr, 0, 0));
        }
        catch (...) { return false; }
    }
    bool update(const uint8_t* data, size_t size) {
        try {
            return BCRYPT_SUCCESS(BCryptHashData(
                hash_.h, const_cast<PUCHAR>(data), ULONG(size), 0));
        }
        catch (...) { return false; }
    }
    bool finish(Sha256& out) {
        try {
            return BCRYPT_SUCCESS(BCryptFinishHash(
                hash_.h, out.data(), ULONG(out.size()), 0));
        }
        catch (...) { return false; }
    }
private:
    AlgHandle  alg_;
    HashHandle hash_;
};

std::optional<Sha256> Sha256File(const fs::path& path, uint64_t* out_size = nullptr) {
    try {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
        if (h == INVALID_HANDLE_VALUE) return std::nullopt;
        LARGE_INTEGER li{};
        if (GetFileSizeEx(h, &li) && out_size) *out_size = uint64_t(li.QuadPart);
        Sha256Ctx ctx;
        if (!ctx.init()) { CloseHandle(h); return std::nullopt; }
        std::vector<uint8_t> buf(64 * 1024);
        for (;;) {
            DWORD got = 0;
            if (!ReadFile(h, buf.data(), DWORD(buf.size()), &got, nullptr)) {
                CloseHandle(h); return std::nullopt;
            }
            if (got == 0) break;
            if (!ctx.update(buf.data(), got)) {
                CloseHandle(h); return std::nullopt;
            }
        }
        CloseHandle(h);
        Sha256 out{};
        if (!ctx.finish(out)) return std::nullopt;
        return out;
    }
    catch (...) { return std::nullopt; }
}

enum EfiNodeType : uint8_t {
    NODE_HARDWARE  = 0x01,
    NODE_ACPI      = 0x02,
    NODE_MESSAGING = 0x03,
    NODE_MEDIA     = 0x04,
    NODE_END       = 0x7F,
};
enum EfiMessagingSubType : uint8_t {
    MSG_USB       = 0x05,
    MSG_USB_CLASS = 0x0F,
    MSG_USB_WWID  = 0x10,
};
enum EfiMediaSubType : uint8_t {
    MEDIA_FILE_PATH = 0x04,
};

struct EfiNode {
    uint8_t              type    = 0;
    uint8_t              subType = 0;
    std::vector<uint8_t> payload;
};

uint16_t ReadU16(const uint8_t* p) {
    try {
        return uint16_t(p[0]) | (uint16_t(p[1]) << 8);
    }
    catch (...) { return 0; }
}
uint32_t ReadU32(const uint8_t* p) {
    try {
        return uint32_t(p[0])
             | (uint32_t(p[1]) << 8)
             | (uint32_t(p[2]) << 16)
             | (uint32_t(p[3]) << 24);
    }
    catch (...) { return 0; }
}

std::string Ucs2ToUtf8(const uint8_t* data, size_t byteLen) {
    try {
        std::string out;
        out.reserve(byteLen / 2);
        for (size_t i = 0; i + 1 < byteLen; i += 2) {
            uint16_t cp = ReadU16(data + i);
            if (cp == 0) break;
            if (cp < 0x80) {
                out.push_back(char(cp));
            } else if (cp < 0x800) {
                out.push_back(char(0xC0 | (cp >> 6)));
                out.push_back(char(0x80 | (cp & 0x3F)));
            } else {
                out.push_back(char(0xE0 | (cp >> 12)));
                out.push_back(char(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(char(0x80 | (cp & 0x3F)));
            }
        }
        return out;
    }
    catch (...) { return {}; }
}

std::vector<EfiNode> ParseDevicePath(const uint8_t* data, size_t size) {
    try {
        std::vector<EfiNode> nodes;
        size_t off = 0;
        while (off + 4 <= size) {
            EfiNode n;
            n.type    = data[off + 0];
            n.subType = data[off + 1];
            uint16_t len = ReadU16(data + off + 2);
            if (len < 4 || off + len > size) break;
            if (n.type == NODE_END) break;
            n.payload.assign(data + off + 4, data + off + len);
            nodes.push_back(std::move(n));
            off += len;
        }
        return nodes;
    }
    catch (...) { return {}; }
}

bool ContainsUsbNode(const std::vector<EfiNode>& nodes) {
    try {
        for (const auto& n : nodes) {
            if (n.type != NODE_MESSAGING) continue;
            if (n.subType == MSG_USB || n.subType == MSG_USB_CLASS
                || n.subType == MSG_USB_WWID) return true;
        }
        return false;
    }
    catch (...) { return false; }
}

std::optional<std::string> ExtractFilePath(const std::vector<EfiNode>& nodes) {
    try {
        std::string out;
        bool found = false;
        for (const auto& n : nodes) {
            if (n.type == NODE_MEDIA && n.subType == MEDIA_FILE_PATH) {
                out += Ucs2ToUtf8(n.payload.data(), n.payload.size());
                found = true;
            }
        }
        if (!found) return std::nullopt;
        return out;
    }
    catch (...) { return std::nullopt; }
}

enum TcgEventType : uint32_t {
    EV_NO_ACTION                      = 0x00000003,
    EV_EFI_BOOT_SERVICES_APPLICATION  = 0x80000003,
    EV_EFI_BOOT_SERVICES_DRIVER       = 0x80000004,
    EV_EFI_RUNTIME_SERVICES_DRIVER    = 0x80000005,
};
enum TcgHashAlg : uint16_t {
    TPM_ALG_SHA1     = 0x0004,
    TPM_ALG_SHA256   = 0x000B,
    TPM_ALG_SHA384   = 0x000C,
    TPM_ALG_SHA512   = 0x000D,
    TPM_ALG_SM3_256  = 0x0012,
};

struct TcgDigest {
    uint16_t             alg = 0;
    std::vector<uint8_t> bytes;
};
struct TcgEvent {
    uint32_t               pcr   = 0;
    uint32_t               type  = 0;
    std::vector<TcgDigest> digests;
    std::vector<uint8_t>   data;
    size_t                 index = 0;
};
struct TcgCursor {
    const uint8_t* data;
    size_t         size;
    size_t         off = 0;

    void need(size_t n) const {
        if (off + n > size) throw std::runtime_error(xorstr_("trunc"));
    }
    uint8_t u8() {
        try {
            need(1);
            return data[off++];
        }
        catch (...) { throw; }
    }
    uint16_t u16() {
        try {
            need(2);
            uint16_t v = uint16_t(data[off]) | (uint16_t(data[off + 1]) << 8);
            off += 2; return v;
        }
        catch (...) { throw; }
    }
    uint32_t u32() {
        try {
            need(4);
            uint32_t v = uint32_t(data[off])
                       | (uint32_t(data[off + 1]) << 8)
                       | (uint32_t(data[off + 2]) << 16)
                       | (uint32_t(data[off + 3]) << 24);
            off += 4; return v;
        }
        catch (...) { throw; }
    }
    void bytes(uint8_t* out, size_t n) {
        try {
            need(n); std::memcpy(out, data + off, n); off += n;
        }
        catch (...) { throw; }
    }
};

using AlgSizeMap = std::unordered_map<uint16_t, uint16_t>;

size_t StaticDigestSize(uint16_t alg) {
    try {
        switch (alg) {
            case TPM_ALG_SHA1:    return 20;
            case TPM_ALG_SHA256:  return 32;
            case TPM_ALG_SHA384:  return 48;
            case TPM_ALG_SHA512:  return 64;
            case TPM_ALG_SM3_256: return 32;
            default:              return 0;
        }
    }
    catch (...) { return 0; }
}

TcgEvent ReadSpecIdHeader(TcgCursor& c, AlgSizeMap& algs) {
    try {
        TcgEvent ev{};
        ev.index = 1;
        ev.pcr  = c.u32();
        ev.type = c.u32();

        TcgDigest d;
        d.alg = TPM_ALG_SHA1;
        d.bytes.resize(20);
        c.bytes(d.bytes.data(), 20);
        ev.digests.push_back(std::move(d));

        uint32_t eventSize = c.u32();
        ev.data.resize(eventSize);
        c.bytes(ev.data.data(), eventSize);

        if (ev.type != EV_NO_ACTION) throw std::runtime_error(xorstr_("bad spec"));
        if (ev.data.size() < 16 + 4 + 4 + 4)
            throw std::runtime_error(xorstr_("bad spec"));

        {
            std::string sig = xorstr_("Spec ID Event03");
            sig.push_back('\0');
            if (sig.size() != 16
                || std::memcmp(ev.data.data(), sig.data(), 16) != 0) {
                throw std::runtime_error(xorstr_("bad spec"));
            }
        }
        size_t p = 16 + 4 + 1 + 1 + 1 + 1;
        if (ev.data.size() < p + 4) throw std::runtime_error(xorstr_("bad spec"));
        uint32_t nAlgs = uint32_t(ev.data[p])
                       | (uint32_t(ev.data[p + 1]) << 8)
                       | (uint32_t(ev.data[p + 2]) << 16)
                       | (uint32_t(ev.data[p + 3]) << 24);
        p += 4;
        for (uint32_t i = 0; i < nAlgs; ++i) {
            if (ev.data.size() < p + 4) throw std::runtime_error(xorstr_("bad spec"));
            uint16_t alg  = uint16_t(ev.data[p]) | (uint16_t(ev.data[p + 1]) << 8);
            uint16_t size = uint16_t(ev.data[p + 2]) | (uint16_t(ev.data[p + 3]) << 8);
            algs[alg] = size;
            p += 4;
        }
        return ev;
    }
    catch (...) { throw; }
}

TcgEvent ReadEvent2(TcgCursor& c, const AlgSizeMap& algs, size_t index) {
    try {
        TcgEvent ev{};
        ev.index = index;
        ev.pcr  = c.u32();
        ev.type = c.u32();
        uint32_t count = c.u32();
        if (count > 16) throw std::runtime_error(xorstr_("bad ev2"));
        ev.digests.reserve(count);
        for (uint32_t i = 0; i < count; ++i) {
            TcgDigest d;
            d.alg = c.u16();
            size_t sz = 0;
            if (auto it = algs.find(d.alg); it != algs.end()) sz = it->second;
            else                                              sz = StaticDigestSize(d.alg);
            if (sz == 0) throw std::runtime_error(xorstr_("bad ev2"));
            d.bytes.resize(sz);
            c.bytes(d.bytes.data(), sz);
            ev.digests.push_back(std::move(d));
        }
        uint32_t eventSize = c.u32();
        ev.data.resize(eventSize);
        c.bytes(ev.data.data(), eventSize);
        return ev;
    }
    catch (...) { throw; }
}

std::vector<TcgEvent> ParseLog(const uint8_t* buffer, size_t size) {
    std::vector<TcgEvent> events;
    try {
        TcgCursor c{buffer, size, 0};
        AlgSizeMap algs;
        events.push_back(ReadSpecIdHeader(c, algs));
        size_t idx = 2;
        while (c.off < c.size) events.push_back(ReadEvent2(c, algs, idx++));
        return events;
    }
    catch (...) { return events; }
}

std::optional<std::vector<uint8_t>> ReadPeCandidate(const fs::path& path) {
    try {
        HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return std::nullopt;
        LARGE_INTEGER li{};
        if (!GetFileSizeEx(h, &li)) { CloseHandle(h); return std::nullopt; }
        if (li.QuadPart <= 0 || li.QuadPart > (256ll << 20)) {
            CloseHandle(h); return std::nullopt;
        }
        std::vector<uint8_t> buf(size_t(li.QuadPart));
        DWORD got = 0;
        size_t off = 0;
        while (off < buf.size()) {
            DWORD want = DWORD(std::min<size_t>(buf.size() - off, 1u << 20));
            if (!ReadFile(h, buf.data() + off, want, &got, nullptr) || got == 0) {
                CloseHandle(h); return std::nullopt;
            }
            off += got;
        }
        CloseHandle(h);
        return buf;
    }
    catch (...) { return std::nullopt; }
}

std::optional<Sha256> AuthenticodeSha256(const fs::path& path) {
    try {
        struct SkipRange { size_t start; size_t end; };

        auto data_opt = ReadPeCandidate(path);
        if (!data_opt) return std::nullopt;
        const auto& data = *data_opt;

        if (data.size() < 0x40) return std::nullopt;
        if (data[0] != 'M' || data[1] != 'Z') return std::nullopt;
        uint32_t e_lfanew = ReadU32(&data[0x3C]);
        if (size_t(e_lfanew) + 4 + 20 + 2 > data.size()) return std::nullopt;
        if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E'
         || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0) return std::nullopt;

        size_t optOff = size_t(e_lfanew) + 4 + 20;
        uint16_t optMagic = ReadU16(&data[optOff]);
        size_t dataDirOff;
        if      (optMagic == 0x10B) dataDirOff = optOff +  96;
        else if (optMagic == 0x20B) dataDirOff = optOff + 112;
        else return std::nullopt;

        size_t certEntryOff = dataDirOff + 4 * 8;
        if (certEntryOff + 8 > data.size()) return std::nullopt;
        uint32_t certOffset = ReadU32(&data[certEntryOff]);
        uint32_t certSize   = ReadU32(&data[certEntryOff + 4]);

        size_t checksumOff = optOff + 64;
        if (checksumOff + 4 > data.size()) return std::nullopt;

        std::vector<SkipRange> skips;
        skips.push_back({checksumOff, checksumOff + 4});
        skips.push_back({certEntryOff, certEntryOff + 8});
        if (certSize > 0 && size_t(certOffset) + certSize <= data.size()) {
            skips.push_back({certOffset, size_t(certOffset) + certSize});
        }
        std::sort(skips.begin(), skips.end(),
                  [](const SkipRange& a, const SkipRange& b){ return a.start < b.start; });

        BCRYPT_ALG_HANDLE  alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
                &alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) return std::nullopt;
        if (!BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
            BCryptCloseAlgorithmProvider(alg, 0);
            return std::nullopt;
        }
        auto feed = [&](const uint8_t* p, size_t n) -> bool {
            try {
                if (n == 0) return true;
                return BCRYPT_SUCCESS(BCryptHashData(hash, PUCHAR(p), ULONG(n), 0));
            }
            catch (...) { return false; }
        };

        size_t cursor = 0;
        bool ok = true;
        for (const auto& s : skips) {
            if (s.start > cursor) {
                if (!feed(data.data() + cursor, s.start - cursor)) { ok = false; break; }
            }
            cursor = std::max(cursor, s.end);
        }
        if (ok && cursor < data.size()) {
            ok = feed(data.data() + cursor, data.size() - cursor);
        }
        Sha256 out{};
        if (ok) ok = BCRYPT_SUCCESS(BCryptFinishHash(hash, out.data(), ULONG(out.size()), 0));
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(alg, 0);
        if (!ok) return std::nullopt;
        return out;
    }
    catch (...) { return std::nullopt; }
}

struct EspCandidate {
    std::wstring volumePathW;
};

struct DiskCheck {
    enum Status { NotChecked, Found, FileMissing, AccessDenied, OpenFailed };
    Status                status       = NotChecked;
    uint64_t              fileSize     = 0;
    std::optional<Sha256> authenticode;
    bool                  sizeMatches  = false;
};

std::wstring Widen(const std::string& s) {
    try {
        if (s.empty()) return {};
        int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
        std::wstring out(n, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), out.data(), n);
        return out;
    }
    catch (...) { return {}; }
}

std::wstring NormalizeEfiPath(const std::string& efiPath) {
    try {
        std::wstring w = Widen(efiPath);
        for (auto& c : w) if (c == L'/') c = L'\\';
        while (!w.empty() && w.front() == L'\\') w.erase(w.begin());
        return w;
    }
    catch (...) { return {}; }
}

std::vector<EspCandidate> FindWindowsEsps() {
    try {
        std::vector<EspCandidate> out;
        wchar_t volName[MAX_PATH + 1] = {};
        HANDLE hFind = FindFirstVolumeW(volName, MAX_PATH);
        if (hFind == INVALID_HANDLE_VALUE) return out;

        const std::wstring probeRel = xorstr_(L"EFI\\Microsoft\\Boot\\bootmgfw.efi");
        do {
            try {
                wchar_t fsName[64] = {};
                if (!GetVolumeInformationW(volName, nullptr, 0, nullptr,
                                           nullptr, nullptr, fsName, 64)) continue;
                std::wstring probe = std::wstring(volName) + probeRel;
                HANDLE hFile = CreateFileW(probe.c_str(), 0,
                                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                           nullptr, OPEN_EXISTING,
                                           FILE_ATTRIBUTE_NORMAL, nullptr);
                if (hFile == INVALID_HANDLE_VALUE) continue;
                CloseHandle(hFile);
                EspCandidate c;
                c.volumePathW = volName;
                out.push_back(std::move(c));
            }
            catch (...) {}
        } while (FindNextVolumeW(hFind, volName, MAX_PATH));
        FindVolumeClose(hFind);
        return out;
    }
    catch (...) { return {}; }
}

DiskCheck InspectFile(const std::vector<EspCandidate>& esps,
                      const std::string& efiLogPath,
                      uint64_t logImageLength) {
    try {
        DiskCheck r;
        if (efiLogPath.empty() || esps.empty()) return r;
        std::wstring rel = NormalizeEfiPath(efiLogPath);
        DWORD worstErr = ERROR_FILE_NOT_FOUND;
        for (const auto& esp : esps) {
            try {
                std::wstring full = esp.volumePathW + rel;
                HANDLE h = CreateFileW(full.c_str(), GENERIC_READ,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                       nullptr, OPEN_EXISTING,
                                       FILE_ATTRIBUTE_NORMAL, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    DWORD e = GetLastError();
                    if (e == ERROR_ACCESS_DENIED) worstErr = e;
                    else if (worstErr != ERROR_ACCESS_DENIED && e != ERROR_FILE_NOT_FOUND
                             && e != ERROR_PATH_NOT_FOUND) worstErr = e;
                    continue;
                }
                r.status = DiskCheck::Found;
                LARGE_INTEGER li{};
                if (GetFileSizeEx(h, &li)) r.fileSize = uint64_t(li.QuadPart);
                CloseHandle(h);
                fs::path p = full;
                uint64_t sz = 0;
                if (r.fileSize == 0) {
                    if (auto raw = Sha256File(p, &sz)) r.fileSize = sz;
                }
                if (auto ah = AuthenticodeSha256(p)) r.authenticode = *ah;
                if (logImageLength && r.fileSize) {
                    r.sizeMatches = (r.fileSize == logImageLength);
                }
                return r;
            }
            catch (...) {}
        }
        if (worstErr == ERROR_ACCESS_DENIED)      r.status = DiskCheck::AccessDenied;
        else if (worstErr == ERROR_FILE_NOT_FOUND
              || worstErr == ERROR_PATH_NOT_FOUND) r.status = DiskCheck::FileMissing;
        else                                       r.status = DiskCheck::OpenFailed;
        return r;
    }
    catch (...) { return {}; }
}

struct LiveResult {
    bool                  tbsLogAvailable = false;
    std::vector<uint8_t>  tbsLogBytes;
    std::vector<TcgEvent> tbsLogEventsParsed;
    bool                  diskLogFound      = false;
    bool                  diskLogCompared   = false;
    bool                  diskLogMatchesTbs = false;
};
struct TbsCtx {
    TBS_HCONTEXT h = nullptr;
    ~TbsCtx() {
        try { if (h) Tbsip_Context_Close(h); }
        catch (...) {}
    }
};
enum class LogCmp { Identical, DiskIsPrefixOfTbs, Different };

std::optional<std::vector<uint8_t>> FetchTbsLog() {
    try {
        UINT32 size = 0;
        TBS_RESULT r = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, nullptr, &size);
        if (r != TBS_SUCCESS && r != TBS_E_INSUFFICIENT_BUFFER) return std::nullopt;
        std::vector<uint8_t> buf(size);
        r = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, buf.data(), &size);
        if (r != TBS_SUCCESS) return std::nullopt;
        buf.resize(size);
        return buf;
    }
    catch (...) { return std::nullopt; }
}

std::optional<std::vector<uint8_t>> ReadWholeFile(const fs::path& p) {
    try {
        HANDLE h = CreateFileW(p.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
        if (h == INVALID_HANDLE_VALUE) return std::nullopt;

        LARGE_INTEGER li{};
        if (!GetFileSizeEx(h, &li) || li.QuadPart < 0) {
            CloseHandle(h);
            return std::nullopt;
        }
        if (li.QuadPart > (256ll << 20)) {
            CloseHandle(h);
            return std::nullopt;
        }

        std::vector<uint8_t> buf;
        try {
            buf.resize(static_cast<size_t>(li.QuadPart));
        } catch (...) {
            CloseHandle(h);
            return std::nullopt;
        }

        size_t off = 0;
        while (off < buf.size()) {
            DWORD want = static_cast<DWORD>(std::min<size_t>(buf.size() - off, 1u << 20));
            DWORD got = 0;
            if (!ReadFile(h, buf.data() + off, want, &got, nullptr)) {
                CloseHandle(h);
                return std::nullopt;
            }
            if (got == 0) break;
            off += got;
        }
        CloseHandle(h);
        buf.resize(off);
        return buf;
    }
    catch (...) { return std::nullopt; }
}

std::optional<fs::path> FindCurrentBootLogOnDisk(const fs::path& dir) {
    try {
        static const std::regex kRe(xorstr_(R"(^0*([0-9]+)-0*([0-9]+)\.log$)"),
                                    std::regex::icase);
        std::error_code ec;
        if (!fs::exists(dir, ec)) return std::nullopt;
        uint64_t bestBoot = 0, bestSub = 0;
        fs::path bestPath;
        bool anyFound = false;
        for (auto& e : fs::directory_iterator(dir, ec)) {
            try {
                if (!e.is_regular_file()) continue;
                auto name = e.path().filename().string();
                std::smatch m;
                if (!std::regex_match(name, m, kRe)) continue;
                uint64_t b = std::stoull(m[1].str());
                uint64_t s = std::stoull(m[2].str());
                if (!anyFound || b > bestBoot || (b == bestBoot && s > bestSub)) {
                    bestBoot = b; bestSub = s; bestPath = e.path();
                    anyFound = true;
                }
            }
            catch (...) {}
        }
        if (!anyFound) return std::nullopt;
        return bestPath;
    }
    catch (...) { return std::nullopt; }
}

LogCmp CompareLogs(const std::vector<uint8_t>& tbs,
                   const std::vector<uint8_t>& disk) {
    try {
        if (tbs.size() == disk.size()
            && std::memcmp(tbs.data(), disk.data(), tbs.size()) == 0) {
            return LogCmp::Identical;
        }
        if (disk.size() < tbs.size()
            && std::memcmp(tbs.data(), disk.data(), disk.size()) == 0) {
            return LogCmp::DiskIsPrefixOfTbs;
        }
        return LogCmp::Different;
    }
    catch (...) { return LogCmp::Different; }
}

LiveResult VerifyCurrentBoot(const fs::path& measuredBootDir) {
    LiveResult out;
    try {
        auto tbsBytes = FetchTbsLog();
        if (!tbsBytes) return out;
        out.tbsLogAvailable = true;
        out.tbsLogBytes     = std::move(*tbsBytes);
        try {
            out.tbsLogEventsParsed = ParseLog(
                out.tbsLogBytes.data(), out.tbsLogBytes.size());
        } catch (...) {
        }
        if (auto diskPath = FindCurrentBootLogOnDisk(measuredBootDir)) {
            out.diskLogFound = true;
            if (auto diskBytes = ReadWholeFile(*diskPath)) {
                out.diskLogCompared = true;
                switch (CompareLogs(out.tbsLogBytes, *diskBytes)) {
                    case LogCmp::Identical:
                    case LogCmp::DiskIsPrefixOfTbs:
                        out.diskLogMatchesTbs = true; break;
                    case LogCmp::Different:
                        out.diskLogMatchesTbs = false; break;
                }
            }
        }
        return out;
    }
    catch (...) { return out; }
}

std::string FormatFileTime(const FILETIME& utc) {
    try {
        FILETIME local{};
        SYSTEMTIME st{};
        if (!FileTimeToLocalFileTime(&utc, &local)) return xorstr_("N/A");
        if (!FileTimeToSystemTime(&local, &st))     return xorstr_("N/A");
        char buf[32];
        std::snprintf(buf, sizeof(buf),
                      xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
                      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }
    catch (...) { return xorstr_("N/A"); }
}

std::string FormatFileLastWrite(const fs::path& p) {
    try {
        WIN32_FILE_ATTRIBUTE_DATA a{};
        if (!GetFileAttributesExW(p.wstring().c_str(), GetFileExInfoStandard, &a))
            return xorstr_("N/A");
        return FormatFileTime(a.ftLastWriteTime);
    }
    catch (...) { return xorstr_("N/A"); }
}

std::string NowLocalString() {
    try {
        SYSTEMTIME st{};
        GetLocalTime(&st);
        char buf[32];
        std::snprintf(buf, sizeof(buf),
                      xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
                      st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    }
    catch (...) { return xorstr_("N/A"); }
}

std::string CurrentBootLocalTimestamp() {
    try {
        ULONGLONG upMs = GetTickCount64();
        FILETIME  ftNow{};
        GetSystemTimeAsFileTime(&ftNow);
        ULARGE_INTEGER u{};
        u.LowPart  = ftNow.dwLowDateTime;
        u.HighPart = ftNow.dwHighDateTime;
        if (u.QuadPart > ULONGLONG(upMs) * 10000ULL)
            u.QuadPart -= ULONGLONG(upMs) * 10000ULL;
        FILETIME ftBoot{};
        ftBoot.dwLowDateTime  = u.LowPart;
        ftBoot.dwHighDateTime = u.HighPart;
        return FormatFileTime(ftBoot);
    }
    catch (...) { return xorstr_("N/A"); }
}

struct ImageLoadEvent {
    uint64_t                   lengthInMemory   = 0;
    uint64_t                   devicePathLength = 0;
    std::vector<EfiNode>       devicePathNodes;
    std::optional<std::string> filePath;
};

std::optional<ImageLoadEvent> DecodeImageLoad(const std::vector<uint8_t>& data) {
    try {
        if (data.size() < 32) return std::nullopt;
        ImageLoadEvent ile;
        std::memcpy(&ile.lengthInMemory,   data.data() +  8, 8);
        std::memcpy(&ile.devicePathLength, data.data() + 24, 8);
        if (ile.devicePathLength > data.size() - 32) return std::nullopt;
        ile.devicePathNodes = ParseDevicePath(
            data.data() + 32, size_t(ile.devicePathLength));
        ile.filePath = ExtractFilePath(ile.devicePathNodes);
        return ile;
    }
    catch (...) { return std::nullopt; }
}

bool IsImageLoadType(uint32_t t) {
    try {
        return t == EV_EFI_BOOT_SERVICES_APPLICATION
            || t == EV_EFI_BOOT_SERVICES_DRIVER
            || t == EV_EFI_RUNTIME_SERVICES_DRIVER;
    }
    catch (...) { return false; }
}

std::optional<uint64_t> ParseBootNumber(const fs::path& p) {
    try {
        static const std::regex kRe(xorstr_(R"(^0*([0-9]+)-0*[0-9]+\.log$)"),
                                    std::regex::icase);
        auto name = p.filename().string();
        std::smatch m;
        if (!std::regex_match(name, m, kRe)) return std::nullopt;
        return std::stoull(m[1].str());
    }
    catch (...) { return std::nullopt; }
}

struct BootInfo {
    uint64_t    number = 0;
    std::string timestamp;
};

struct ScanState {
    fs::path                  dir;
    std::vector<fs::path>     files;
    std::vector<EspCandidate> esps;
    LiveResult                tpm;
    std::vector<BootInfo>     bootInfos;
    uint64_t                  currentBoot   = 0;
    bool                      folderMissing = false;
    bool                      folderEmpty   = false;
    std::string               folderTamperTimestamp;
    std::unordered_set<std::string> emitted;
};

bool EmitOnce(ScanState& st, const std::string& key) {
    try {
        return st.emitted.insert(key).second;
    }
    catch (...) { return false; }
}

void ScanTbsEventsForCurrentBootUsb(ScanState& st) {
    try {
        const std::string bootTs = CurrentBootLocalTimestamp();
        for (const auto& ev : st.tpm.tbsLogEventsParsed) {
            try {
                if (!IsImageLoadType(ev.type)) continue;
                auto ile = DecodeImageLoad(ev.data);
                if (!ile) continue;
                if (!ContainsUsbNode(ile->devicePathNodes)) continue;
                if (!EmitOnce(st, xorstr_("usb_current"))) return;
                LOG(DETECTION, bootTs) << xorstr_(
                    "EFI Bypass:PC Has Been Booted From Bootable Drive"
                    " (EFI Cheat In Instance)");
                return;
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

void ScanOneLog(const fs::path& path, bool isCurrentBoot,
                bool tbsHandlesCurrentUsb, ScanState& st) {
    try {
        auto buf = ReadWholeFile(path);
        if (!buf || buf->empty()) return;

        std::vector<TcgEvent> events;
        try {
            events = ParseLog(buf->data(), buf->size());
        } catch (...) {
            return;
        }

        for (const auto& ev : events) {
            try {
                if (!IsImageLoadType(ev.type)) continue;
                auto ile = DecodeImageLoad(ev.data);
                if (!ile) continue;
                const bool usb = ContainsUsbNode(ile->devicePathNodes);

                if (usb && !(isCurrentBoot && tbsHandlesCurrentUsb)) {
                    if (isCurrentBoot) {
                        if (EmitOnce(st, xorstr_("usb_current"))) {
                            LOG(DETECTION, FormatFileLastWrite(path)) << xorstr_(
                                "EFI Bypass:PC Has Been Booted From Bootable Drive"
                                " (EFI Cheat In Instance)");
                        }
                    } else {
                        const std::string ts = FormatFileLastWrite(path);
                        if (EmitOnce(st, xorstr_("usb_prev|") + ts)) {
                            LOG(WARNING, ts) << xorstr_(
                                "EFI Bypass:PC Has Been Booted From Bootable Drive"
                                " Before Current Boot (EFI Cheat In Previous Boot)");
                        }
                    }
                }

                if (isCurrentBoot && !usb && ile->filePath && !st.esps.empty()) {
                    auto inspect = InspectFile(
                        st.esps, *ile->filePath, ile->lengthInMemory);
                    switch (inspect.status) {
                        case DiskCheck::AccessDenied:
                        case DiskCheck::OpenFailed:
                        case DiskCheck::NotChecked:
                            continue;
                        case DiskCheck::FileMissing:
                            if (EmitOnce(st, xorstr_("missing|") + *ile->filePath)) {
                                LOG(WARNING, NowLocalString()) << xorstr_(
                                    "EFI Bypass:File Windows Booted From Not Found"
                                    " In EFI Partition");
                            }
                            break;
                        case DiskCheck::Found:
                            break;
                    }
                }
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

constexpr long long kEfiArtifactGraceSeconds = 30LL * 24LL * 60LL * 60LL;

void EmitFolderTamperIfAny(ScanState& st) {
    try {
        if (!(st.folderMissing || st.folderEmpty)) return;
        const std::string ts = st.folderTamperTimestamp.empty()
                             ? NowLocalString() : st.folderTamperTimestamp;
        if (!EmitOnce(st, xorstr_("folder_wiped"))) return;

        if (FreshInstall::WithinGrace(kEfiArtifactGraceSeconds))
            LOG(DETECTION, ts) << xorstr_(
                "EFI Bypass:EFI Artifact Is Not Present");
        else
            LOG(WARNING, ts) << xorstr_(
                "EFI Bypass:EFI Artifact Is Not Present");
    }
    catch (...) {}
}

void EmitTbsMismatchIfAny(ScanState& st) {
    try {
        const bool folderIssue = st.folderMissing || st.folderEmpty;
        const bool logEdited  = !folderIssue && st.tpm.tbsLogAvailable
                                && st.tpm.diskLogCompared
                                && !st.tpm.diskLogMatchesTbs;
        const bool logDeleted = !folderIssue && st.tpm.tbsLogAvailable
                                && !st.tpm.diskLogFound;
        if (!(logEdited || logDeleted)) return;
        if (!EmitOnce(st, xorstr_("log_edited"))) return;
        LOG(DETECTION, NowLocalString()) << xorstr_(
            "EFI Bypass:Windows Boot Log Has Been Edited After Boot"
            " To Hide EFI Evidence");
    }
    catch (...) {}
}

void EmitBootNumberGapsIfAny(ScanState& st) {
    try {
        std::vector<uint64_t> boots;
        for (const auto& p : st.files)
            if (auto b = ParseBootNumber(p)) boots.push_back(*b);
        if (boots.empty()) return;
        std::sort(boots.begin(), boots.end());
        boots.erase(std::unique(boots.begin(), boots.end()), boots.end());

        auto findTs = [&](uint64_t n) -> std::string {
            try {
                for (const auto& b : st.bootInfos)
                    if (b.number == n) return b.timestamp;
                return xorstr_("N/A");
            }
            catch (...) { return xorstr_("N/A"); }
        };

        size_t i = 0;
        for (uint64_t n = boots.front(); n <= boots.back(); ++n) {
            try {
                if (i < boots.size() && boots[i] == n) { ++i; continue; }
                uint64_t after = 0;
                for (const auto& b : st.bootInfos) {
                    if (b.number > n && (after == 0 || b.number < after)) after = b.number;
                }
                std::string tsAfter = after ? findTs(after) : NowLocalString();
                if (!EmitOnce(st, xorstr_("gap|") + std::to_string(n))) continue;
                LOG(WARNING, tsAfter) << xorstr_(
                    "EFI Bypass:Windows Boot Logs Missing For One Or More Boots: Potential Attempt To Hide EFI Evidence");
            }
            catch (...) {}
        }
    }
    catch (...) {}
}

void RunScan() {
    try {
        ScanState st;
        st.dir = xorstr_(LR"(C:\Windows\Logs\MeasuredBoot)");

        std::error_code ec;
        if (fs::exists(st.dir, ec)) {
            for (auto& e : fs::directory_iterator(st.dir, ec)) {
                try {
                    if (!e.is_regular_file()) continue;
                    auto ext = e.path().extension().string();
                    std::transform(ext.begin(), ext.end(), ext.begin(),
                                   [](unsigned char c) { return std::tolower(c); });
                    if (ext == xorstr_(".log")) st.files.push_back(e.path());
                }
                catch (...) {}
            }
            std::sort(st.files.begin(), st.files.end());
            if (st.files.empty()) {
                st.folderEmpty = true;
                st.folderTamperTimestamp = FormatFileLastWrite(st.dir);
            }
        } else {
            st.folderMissing = true;
            fs::path parent = st.dir.parent_path();
            st.folderTamperTimestamp = parent.empty()
                ? NowLocalString()
                : FormatFileLastWrite(parent);
        }

        st.esps = FindWindowsEsps();
        st.tpm  = VerifyCurrentBoot(st.dir);
        const bool tbsHandlesCurrentUsb = st.tpm.tbsLogAvailable;

        for (const auto& p : st.files) {
            try {
                if (auto b = ParseBootNumber(p)) st.currentBoot = std::max(st.currentBoot, *b);
            }
            catch (...) {}
        }

        for (const auto& p : st.files) {
            try {
                auto b = ParseBootNumber(p);
                if (!b) continue;
                bool have = false;
                for (const auto& e : st.bootInfos) if (e.number == *b) { have = true; break; }
                if (!have) {
                    BootInfo n;
                    n.number    = *b;
                    n.timestamp = FormatFileLastWrite(p);
                    st.bootInfos.push_back(n);
                }
            }
            catch (...) {}
        }

        for (const auto& p : st.files) {
            try {
                bool isCurrent = false;
                if (auto b = ParseBootNumber(p)) isCurrent = (*b == st.currentBoot);
                ScanOneLog(p, isCurrent, tbsHandlesCurrentUsb, st);
            }
            catch (...) {}
        }

        try { if (tbsHandlesCurrentUsb) ScanTbsEventsForCurrentBootUsb(st); }
        catch (...) {}

        try { EmitFolderTamperIfAny(st); } catch (...) {}
        try { EmitTbsMismatchIfAny(st); } catch (...) {}
        try { EmitBootNumberGapsIfAny(st); } catch (...) {}
    }
    catch (...) {}
}

}

void EfiMeasuredBoot::start_efi_measured_boot() {
    try {
        RunScan();
    } catch (...) {}
}
