#include "java_state.h"
#include "ntdefs.h"

#include <cstdio>

namespace atlas {
namespace {

#pragma pack(push, 1)
struct PerfPrologue {
    uint32_t magic;
    uint8_t  byteOrder, major, minor, accessible;
    uint32_t used, overflow;
    uint64_t modTimestamp;
    uint32_t entryOffset, numEntries;
};
struct PerfEntry {
    uint32_t entryLength, nameOffset, vectorLength;
    uint8_t  dataType, flags, dataUnits, dataVariability;
    uint32_t dataOffset;
};
#pragma pack(pop)

bool IsNameByte(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '/';
}

void ScanSymbolsIn(const std::vector<uint8_t>& buf, std::set<std::string>* out,
                   size_t maxOut) {
    const size_t n = buf.size();
    size_t i = 0;
    while (i < n && out->size() < maxOut) {
        if (!IsNameByte(buf[i])) { ++i; continue; }
        size_t start = i;
        while (i < n && IsNameByte(buf[i])) ++i;
        size_t len = i - start;
        if (len < 6 || len > 255) continue;

        bool hasSlash = false;
        for (size_t k = start; k < i; ++k) if (buf[k] == '/') { hasSlash = true; break; }
        if (!hasSlash) continue;

        bool ok = false;
        if (start >= 6) {
            uint16_t l = 0;
            memcpy(&l, buf.data() + start - 2, 2);
            if (l == len) ok = true;
        }
        if (!ok && start >= 8) {
            uint16_t l = 0;
            memcpy(&l, buf.data() + start - 8, 2);
            if (l == len) ok = true;
        }
        if (!ok) continue;
        out->insert(std::string(reinterpret_cast<const char*>(buf.data() + start), len));
    }
}

bool ReadJarClassNames(const std::wstring& path, std::set<std::string>* out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart < 22 || sz.QuadPart >(512ll << 20)) {
        CloseHandle(h);
        return false;
    }

    const uint32_t kEocd = 0x06054b50;
    size_t tailLen = (size_t)(std::min)(sz.QuadPart, (LONGLONG)(64 * 1024 + 22));
    std::vector<uint8_t> tail(tailLen);
    LARGE_INTEGER off{};
    off.QuadPart = sz.QuadPart - (LONGLONG)tailLen;
    SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
    DWORD got = 0;
    if (!ReadFile(h, tail.data(), (DWORD)tail.size(), &got, nullptr) || got != tail.size()) {
        CloseHandle(h);
        return false;
    }

    long long cdOffset = -1, cdSize = 0;
    for (size_t i = tail.size() >= 22 ? tail.size() - 22 : 0; ; --i) {
        uint32_t sig = 0;
        memcpy(&sig, tail.data() + i, 4);
        if (sig == kEocd) {
            memcpy(&cdSize, tail.data() + i + 12, 4);
            uint32_t o32 = 0;
            memcpy(&o32, tail.data() + i + 16, 4);
            cdOffset = o32;
            break;
        }
        if (i == 0) break;
    }
    if (cdOffset < 0 || cdOffset >= sz.QuadPart || cdSize <= 0 || cdSize >(64ll << 20)) {
        CloseHandle(h);
        return false;
    }

    std::vector<uint8_t> cd((size_t)cdSize);
    off.QuadPart = cdOffset;
    SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
    bool okRead = ReadFile(h, cd.data(), (DWORD)cd.size(), &got, nullptr) && got == cd.size();
    CloseHandle(h);
    if (!okRead) return false;

    const uint32_t kCen = 0x02014b50;
    size_t p = 0;
    while (p + 46 <= cd.size()) {
        uint32_t sig = 0;
        memcpy(&sig, cd.data() + p, 4);
        if (sig != kCen) break;
        uint16_t nameLen = 0, extraLen = 0, commentLen = 0;
        memcpy(&nameLen, cd.data() + p + 28, 2);
        memcpy(&extraLen, cd.data() + p + 30, 2);
        memcpy(&commentLen, cd.data() + p + 32, 2);
        if (p + 46 + nameLen > cd.size()) break;
        std::string name(reinterpret_cast<const char*>(cd.data() + p + 46), nameLen);
        if (name.size() > 6 && name.compare(name.size() - 6, 6, xorstr_(".class")) == 0)
            out->insert(name.substr(0, name.size() - 6));
        p += 46 + nameLen + extraLen + commentLen;
    }
    return true;
}

}

JvmCounters ReadJvmCounters(const Target& t) {
    JvmCounters r;

    std::wstring temp = t.EnvValue(xorstr_(L"TEMP"));
    if (temp.empty()) temp = t.EnvValue(xorstr_(L"TMP"));
    if (temp.empty()) {
        wchar_t buf[MAX_PATH] = {};
        if (GetTempPathW(MAX_PATH, buf)) temp = buf;
    }
    if (temp.empty()) return r;
    while (!temp.empty() && (temp.back() == L'\\' || temp.back() == L'/')) temp.pop_back();

    std::wstring user = t.EnvValue(xorstr_(L"USERNAME"));
    if (user.empty()) {
        wchar_t u[256] = {};
        DWORD n = 256;
        if (GetUserNameW(u, &n) && n) user.assign(u, n - 1);
    }

    r.path = temp + xorstr_(L"\\hsperfdata_") + user + xorstr_(L"\\") +
             Utf8ToWide(Format(xorstr_("%lu"), (unsigned long)t.pid()));
    HANDLE h = CreateFileW(r.path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return r;
    }

    std::vector<uint8_t> buf;
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (8 << 20)) {
        buf.resize((size_t)sz.QuadPart);
        DWORD got = 0;
        if (ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr)) buf.resize(got);
        else buf.clear();
    }
    CloseHandle(h);
    if (buf.size() < sizeof(PerfPrologue)) return r;

    const PerfPrologue* pro = reinterpret_cast<const PerfPrologue*>(buf.data());
    if (pro->magic != 0xcafec0c0u && _byteswap_ulong(pro->magic) != 0xcafec0c0u) {
        return r;
    }

    size_t off = pro->entryOffset;
    for (uint32_t i = 0; i < pro->numEntries && off + sizeof(PerfEntry) <= buf.size(); ++i) {
        const PerfEntry* e = reinterpret_cast<const PerfEntry*>(buf.data() + off);
        if (e->entryLength == 0 || off + e->entryLength > buf.size()) break;
        if (e->nameOffset >= e->entryLength) break;
        const char* np = reinterpret_cast<const char*>(buf.data() + off + e->nameOffset);
        std::string name(np, strnlen(np, e->entryLength - e->nameOffset));
        if (!name.empty() && e->dataOffset < e->entryLength) {
            const uint8_t* data = buf.data() + off + e->dataOffset;
            size_t avail = e->entryLength - e->dataOffset;
            if (e->vectorLength == 0) {
                if (avail >= 8) {
                    long long v = 0;
                    memcpy(&v, data, 8);
                    r.values[name] = Format(xorstr_("%lld"), v);
                }
            } else {
                size_t len = (std::min)((size_t)e->vectorLength, avail);
                r.values[name] = std::string((const char*)data, strnlen((const char*)data, len));
            }
        }
        off += e->entryLength;
    }
    r.ok = !r.values.empty();
    return r;
}

MetaspaceNames ScanMetaspaceClassNames(const Target& t, size_t maxNames) {
    MetaspaceNames out;

    std::vector<const Region*> cands;
    for (size_t i = 0; i < t.regions().size(); ++i) {
        const Region& r = t.regions()[i];
        if (r.type != MEM_PRIVATE || r.state != MEM_COMMIT) continue;
        if (!r.Readable() || !r.Writable() || r.Executable()) continue;
        if (t.ModuleAt(r.base)) continue;
        if (r.size < 0x1000) continue;
        cands.push_back(&r);
    }
    std::sort(cands.begin(), cands.end(),
              [](const Region* a, const Region* b) { return a->size < b->size; });

    size_t budget = 768u << 20;
    for (size_t i = 0; i < cands.size() && budget > 0 && out.names.size() < maxNames; ++i) {
        const Region& r = *cands[i];
        size_t want = (size_t)(std::min)(r.size,
                                         (uint64_t)(std::min)(budget, (size_t)(64u << 20)));
        std::vector<uint8_t> buf;
        if (!t.ReadRegion(r, buf, want) || buf.empty()) continue;
        budget -= (std::min)(budget, buf.size());
        out.bytesScanned += buf.size();
        ScanSymbolsIn(buf, &out.names, maxNames);
    }
    out.truncated = out.names.size() >= maxNames;
    return out;
}

std::vector<NamedObject> EnumNamedObjects(const Target& t) {
    std::vector<NamedObject> out;
    if (!nt::NtQuerySystemInformation || !nt::NtDuplicateObject || !nt::NtQueryObject)
        return out;

    ULONG len = 1 << 20;
    std::vector<uint8_t> table;
    for (int attempt = 0; attempt < 8; ++attempt) {
        table.assign(len, 0);
        ULONG needed = 0;
        nt::NTSTATUS st = nt::NtQuerySystemInformation(nt::SystemExtendedHandleInformation,
                                                       table.data(), len, &needed);
        if (ATLAS_NT_SUCCESS(st)) { table.resize(needed ? needed : len); break; }
        len = (needed > len) ? needed + (1 << 20) : len * 2;
        if (len > (256u << 20)) { table.clear(); break; }
    }
    if (table.empty()) return out;

    HANDLE dup = OpenProcess(PROCESS_DUP_HANDLE, FALSE, t.pid());
    if (!dup) return out;

    const nt::SYSTEM_HANDLE_INFORMATION_EX* info =
        reinterpret_cast<const nt::SYSTEM_HANDLE_INFORMATION_EX*>(table.data());
    std::set<std::wstring> seen;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const nt::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX& e = info->Handles[i];
        if ((DWORD)e.UniqueProcessId != t.pid()) continue;
        HANDLE h = nullptr;
        if (!ATLAS_NT_SUCCESS(nt::NtDuplicateObject(dup, e.HandleValue, GetCurrentProcess(),
                                                    &h, 0, 0, DUPLICATE_SAME_ACCESS)))
            continue;
        if (GetFileType(h) == FILE_TYPE_DISK) { CloseHandle(h); continue; }

        uint8_t tbuf[1024] = {};
        ULONG got = 0;
        std::wstring typeName;
        if (ATLAS_NT_SUCCESS(nt::NtQueryObject(h, 2 ,
                                               tbuf, sizeof(tbuf), &got))) {
            const nt::UNICODE_STRING* us = reinterpret_cast<const nt::UNICODE_STRING*>(tbuf);
            if (us->Buffer && us->Length && us->Length < sizeof(tbuf))
                typeName.assign(us->Buffer, us->Length / sizeof(wchar_t));
        }
        static const std::wstring kSafe[] = {
            xorstr_(L"Mutant"), xorstr_(L"Event"), xorstr_(L"Semaphore"), xorstr_(L"Section"), xorstr_(L"Key"), xorstr_(L"Timer"),
            xorstr_(L"Job"), xorstr_(L"Directory"), xorstr_(L"SymbolicLink"), xorstr_(L"WindowStation"), xorstr_(L"Desktop"),
        };
        bool safe = false;
        for (size_t k = 0; k < sizeof(kSafe) / sizeof(kSafe[0]); ++k)
            if (typeName == kSafe[k]) { safe = true; break; }
        if (!safe) { CloseHandle(h); continue; }

        uint8_t nbuf[2048] = {};
        std::wstring objName;
        if (ATLAS_NT_SUCCESS(nt::NtQueryObject(h, nt::ObjectNameInformation,
                                               nbuf, sizeof(nbuf), &got))) {
            const nt::UNICODE_STRING* us = reinterpret_cast<const nt::UNICODE_STRING*>(nbuf);
            if (us->Buffer && us->Length && us->Length < sizeof(nbuf))
                objName.assign(us->Buffer, us->Length / sizeof(wchar_t));
        }
        CloseHandle(h);
        if (objName.empty()) continue;
        if (!seen.insert(typeName + xorstr_(L"|") + objName).second) continue;
        NamedObject o;
        o.type = WideToUtf8(typeName);
        o.name = objName;
        out.push_back(o);
        if (out.size() >= 4000) break;
    }
    CloseHandle(dup);
    return out;
}

bool ReadClasspathClassNames(const Target& t, std::set<std::string>* out,
                             int* jarsRead, int* jarsMissing) {
    *jarsRead = 0;
    *jarsMissing = 0;
    const std::vector<std::wstring>& cp = t.classpath();
    for (size_t i = 0; i < cp.size(); ++i) {
        if (GetFileAttributesW(cp[i].c_str()) == INVALID_FILE_ATTRIBUTES) { ++(*jarsMissing); continue; }
        if (ReadJarClassNames(cp[i], out)) ++(*jarsRead);
        else ++(*jarsMissing);
    }
    return *jarsRead > 0;
}

}
