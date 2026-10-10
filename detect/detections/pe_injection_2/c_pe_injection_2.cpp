#include "c_pe_injection_2.h"

namespace {

struct SruNetEntry {
    std::wstring path;
    ULONGLONG    bytesSent    = 0;
    ULONGLONG    bytesRecvd   = 0;
    ULONGLONG    rawTimestamp = 0;
    std::wstring timestamp;
};

#pragma pack(push, 1)

constexpr DWORD kFileMagic = 0x454C4946;
constexpr DWORD kIndxMagic = 0x58444E49;

constexpr DWORD kAttrAttributeList   = 0x20;
constexpr DWORD kAttrFileName        = 0x30;
constexpr DWORD kAttrData            = 0x80;
constexpr DWORD kAttrIndexRoot       = 0x90;
constexpr DWORD kAttrIndexAllocation = 0xA0;
constexpr DWORD kAttrEnd             = 0xFFFFFFFF;

constexpr WORD  kIndexEntryHasSubnode = 0x0001;
constexpr WORD  kIndexEntryLast       = 0x0002;

constexpr LONGLONG kRootDirRecord = 5;

struct FileRecordHeader {
    DWORD     magic;
    WORD      usaOffset;
    WORD      usaCount;
    LONGLONG  logFileSequence;
    WORD      sequenceNumber;
    WORD      hardLinkCount;
    WORD      firstAttributeOffset;
    WORD      flags;
    DWORD     usedSize;
    DWORD     allocatedSize;
    LONGLONG  baseRef;
    WORD      nextAttrId;
};

struct AttributeHeader {
    DWORD type;
    DWORD length;
    BYTE  nonResident;
    BYTE  nameLength;
    WORD  nameOffset;
    WORD  flags;
    WORD  attrId;
};

struct ResidentAttribute {
    AttributeHeader header;
    DWORD valueLength;
    WORD  valueOffset;
    BYTE  indexed;
    BYTE  align;
};

struct NonResidentAttribute {
    AttributeHeader header;
    LONGLONG startVcn;
    LONGLONG endVcn;
    WORD     runListOffset;
    WORD     compressionUnit;
    DWORD    padding;
    LONGLONG allocatedSize;
    LONGLONG realSize;
    LONGLONG initializedSize;
};

struct FileNameAttribute {
    LONGLONG parentDirectory;
    LONGLONG creationTime;
    LONGLONG changeTime;
    LONGLONG lastWriteTime;
    LONGLONG lastAccessTime;
    LONGLONG allocatedSize;
    LONGLONG realSize;
    DWORD    fileAttributes;
    DWORD    reparseValue;
    BYTE     nameLength;
    BYTE     namespaceFlag;
    wchar_t  name[1];
};

struct IndexHeader {
    DWORD firstEntryOffset;
    DWORD totalEntrySize;
    DWORD allocatedSize;
    BYTE  flags;
    BYTE  padding[3];
};

struct IndexRoot {
    DWORD       attrType;
    DWORD       collationRule;
    DWORD       bytesPerIndexRecord;
    BYTE        clustersPerIndexRecord;
    BYTE        padding[3];
    IndexHeader header;
};

struct IndexBlockHeader {
    DWORD       magic;
    WORD        usaOffset;
    WORD        usaCount;
    LONGLONG    logFileSequence;
    LONGLONG    vcn;
    IndexHeader header;
};

struct IndexEntry {
    LONGLONG fileReference;
    WORD     size;
    WORD     contentSize;
    WORD     flags;
    WORD     reserved;
};

#pragma pack(pop)

struct DataRun {
    LONGLONG lcn;
    LONGLONG length;
};

struct AttrListEntry {
    DWORD        type     = 0;
    LONGLONG     startVcn = 0;
    LONGLONG     fileRef  = 0;
    WORD         attrId   = 0;
    std::wstring name;
};

struct DirEntry {
    LONGLONG     recordNumber = 0;
    std::wstring name;
};

struct EseColumns {
    JET_COLUMNID timestamp     = 0;
    JET_COLTYP   timestampType = JET_coltypNil;
    JET_COLUMNID appId         = 0;
    JET_COLUMNID userId        = 0;
    JET_COLUMNID interfaceLuid = 0;
    JET_COLUMNID l2ProfileId   = 0;
    JET_COLUMNID bytesSent     = 0;
    JET_COLUMNID bytesRecvd    = 0;
};

struct IdMapEntry {
    short        idType = -1;
    std::wstring text;
    std::wstring sidString;
};

bool ParseDataRuns(const BYTE* p, const BYTE* end, std::vector<DataRun>& runs)
{
    try {
        runs.clear();
        LONGLONG currentLcn = 0;
        while (p && p < end) {
            BYTE hdr = *p;
            if (hdr == 0) break;
            ++p;
            int lenLen = hdr & 0x0F;
            int ofsLen = (hdr >> 4) & 0x0F;
            if (lenLen == 0) return false;
            if (p + lenLen + ofsLen > end) return false;
            LONGLONG len = 0;
            for (int i = 0; i < lenLen; ++i)
                len |= static_cast<LONGLONG>(p[i]) << (i * 8);
            p += lenLen;
            if (ofsLen > 0) {
                LONGLONG ofs = 0;
                for (int i = 0; i < ofsLen; ++i)
                    ofs |= static_cast<LONGLONG>(p[i]) << (i * 8);
                if (p[ofsLen - 1] & 0x80) {
                    for (int i = ofsLen; i < 8; ++i)
                        ofs |= static_cast<LONGLONG>(0xFF) << (i * 8);
                }
                p += ofsLen;
                currentLcn += ofs;
                runs.push_back({ currentLcn, len });
            } else {
                runs.push_back({ -1, len });
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

void ApplyFixups(BYTE* buf, size_t bufSize, WORD usaOffset, WORD usaCount, DWORD sectorSize)
{
    try {
        if (usaCount < 2 || sectorSize == 0) return;
        if (static_cast<size_t>(usaOffset) + usaCount * 2u > bufSize) return;
        const BYTE* usa = buf + usaOffset;
        WORD usn = *reinterpret_cast<const WORD*>(usa);
        (void)usn;
        for (WORD i = 1; i < usaCount; ++i) {
            size_t off = static_cast<size_t>(i) * sectorSize - 2;
            if (off + 2 > bufSize) break;
            std::memcpy(buf + off, usa + i * 2, 2);
        }
    } catch (...) {
        return;
    }
}

class Volume {
public:
    HANDLE   handle           = INVALID_HANDLE_VALUE;
    DWORD    bytesPerSector   = 0;
    DWORD    sectorsPerCluster= 0;
    DWORD    bytesPerCluster  = 0;
    DWORD    mftRecordSize    = 1024;
    LONGLONG mftStartCluster  = 0;
    std::vector<DataRun> mftRuns;

    Volume() = default;
    ~Volume() {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
    Volume(const Volume&)            = delete;
    Volume& operator=(const Volume&) = delete;

    bool ReadAt(LONGLONG offset, void* buf, DWORD size) const
    {
        try {
            DWORD sec = bytesPerSector ? bytesPerSector : 512;
            LONGLONG alignedOffset = (offset / sec) * sec;
            DWORD    prefix        = static_cast<DWORD>(offset - alignedOffset);
            DWORD    alignedSize   = ((prefix + size + sec - 1) / sec) * sec;
            if (prefix == 0 && alignedSize == size) {
                OVERLAPPED ov{};
                ov.Offset     = static_cast<DWORD>(offset & 0xFFFFFFFF);
                ov.OffsetHigh = static_cast<DWORD>(static_cast<ULONGLONG>(offset) >> 32);
                DWORD rd = 0;
                if (!ReadFile(handle, buf, size, &rd, &ov)) return false;
                return rd == size;
            }
            std::vector<BYTE> tmp(alignedSize);
            OVERLAPPED ov{};
            ov.Offset     = static_cast<DWORD>(alignedOffset & 0xFFFFFFFF);
            ov.OffsetHigh = static_cast<DWORD>(static_cast<ULONGLONG>(alignedOffset) >> 32);
            DWORD rd = 0;
            if (!ReadFile(handle, tmp.data(), alignedSize, &rd, &ov)) return false;
            if (rd < prefix + size) return false;
            std::memcpy(buf, tmp.data() + prefix, size);
            return true;
        } catch (...) {
            return false;
        }
    }

    static LONGLONG VcnToLcn(const std::vector<DataRun>& runs, LONGLONG vcn)
    {
        try {
            LONGLONG cur = 0;
            for (const auto& r : runs) {
                if (vcn < cur + r.length) {
                    if (r.lcn < 0) return -1;
                    return r.lcn + (vcn - cur);
                }
                cur += r.length;
            }
            return -1;
        } catch (...) {
            return -1;
        }
    }
};

bool OpenVolume(wchar_t letter, Volume& vol)
{
    try {
        std::wstring path = xorstr_(L"\\\\.\\");
        path.push_back(letter);
        path.push_back(L':');
        vol.handle = CreateFileW(path.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING,
            FILE_FLAG_RANDOM_ACCESS, NULL);
        if (vol.handle == INVALID_HANDLE_VALUE) return false;

        BYTE bootSector[512];
        if (!vol.ReadAt(0, bootSector, sizeof(bootSector))) return false;

        const std::string sig = xorstr_("NTFS    ");
        if (std::memcmp(bootSector + 3, sig.c_str(), 8) != 0) return false;

        vol.bytesPerSector    = *reinterpret_cast<WORD*>(bootSector + 0x0B);
        vol.sectorsPerCluster = bootSector[0x0D];
        vol.bytesPerCluster   = vol.bytesPerSector * vol.sectorsPerCluster;
        vol.mftStartCluster   = *reinterpret_cast<LONGLONG*>(bootSector + 0x30);
        if (vol.bytesPerSector == 0 || vol.bytesPerCluster == 0) return false;

        signed char clustersPerMftRecord = static_cast<signed char>(bootSector[0x40]);
        if (clustersPerMftRecord > 0)
            vol.mftRecordSize = static_cast<DWORD>(clustersPerMftRecord) * vol.bytesPerCluster;
        else
            vol.mftRecordSize = 1U << static_cast<DWORD>(-clustersPerMftRecord);
        if (vol.mftRecordSize == 0 || vol.mftRecordSize > 64 * 1024) return false;

        std::vector<BYTE> rec(vol.mftRecordSize);
        LONGLONG mftByteOffset = vol.mftStartCluster * static_cast<LONGLONG>(vol.bytesPerCluster);
        if (!vol.ReadAt(mftByteOffset, rec.data(), vol.mftRecordSize)) return false;

        auto* fr = reinterpret_cast<FileRecordHeader*>(rec.data());
        if (fr->magic != kFileMagic) return false;
        ApplyFixups(rec.data(), rec.size(), fr->usaOffset, fr->usaCount, vol.bytesPerSector);

        const BYTE* p = rec.data() + fr->firstAttributeOffset;
        const BYTE* e = rec.data() + fr->usedSize;
        while (p + sizeof(AttributeHeader) <= e) {
            auto* ah = reinterpret_cast<const AttributeHeader*>(p);
            if (ah->type == kAttrEnd || ah->length == 0) break;
            if (ah->type == kAttrData && ah->nameLength == 0) {
                if (!ah->nonResident) return false;
                auto* nra = reinterpret_cast<const NonResidentAttribute*>(p);
                const BYTE* runStart = p + nra->runListOffset;
                const BYTE* runEnd   = p + ah->length;
                if (!ParseDataRuns(runStart, runEnd, vol.mftRuns) || vol.mftRuns.empty())
                    return false;
                return true;
            }
            p += ah->length;
        }
        return false;
    } catch (...) {
        return false;
    }
}

bool ReadRunlistRange(const Volume& vol, const std::vector<DataRun>& runs,
                      LONGLONG byteOffset, DWORD byteCount, BYTE* out)
{
    try {
        DWORD bytesPerCluster = vol.bytesPerCluster;
        LONGLONG vcn       = byteOffset / bytesPerCluster;
        DWORD    inCluster = static_cast<DWORD>(byteOffset % bytesPerCluster);
        DWORD    written   = 0;
        while (written < byteCount) {
            LONGLONG lcn = Volume::VcnToLcn(runs, vcn);
            DWORD chunk = bytesPerCluster - inCluster;
            if (chunk > byteCount - written) chunk = byteCount - written;
            if (lcn < 0) {
                std::memset(out + written, 0, chunk);
            } else {
                LONGLONG diskOffset = lcn * static_cast<LONGLONG>(bytesPerCluster) + inCluster;
                if (!vol.ReadAt(diskOffset, out + written, chunk)) return false;
            }
            written   += chunk;
            ++vcn;
            inCluster = 0;
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool ReadMftRecord(const Volume& vol, LONGLONG recordNumber, std::vector<BYTE>& record)
{
    try {
        record.assign(vol.mftRecordSize, 0);
        LONGLONG byteOffset = recordNumber * vol.mftRecordSize;
        if (!ReadRunlistRange(vol, vol.mftRuns, byteOffset, vol.mftRecordSize, record.data()))
            return false;
        auto* fr = reinterpret_cast<FileRecordHeader*>(record.data());
        if (fr->magic != kFileMagic) return false;
        ApplyFixups(record.data(), record.size(), fr->usaOffset, fr->usaCount, vol.bytesPerSector);
        return true;
    } catch (...) {
        return false;
    }
}

bool AttrNameEquals(const AttributeHeader* ah, const BYTE* base,
                    const wchar_t* name, size_t nameLen)
{
    try {
        if (ah->nameLength != nameLen) return false;
        if (nameLen == 0) return true;
        auto* an = reinterpret_cast<const wchar_t*>(base + ah->nameOffset);
        for (size_t i = 0; i < nameLen; ++i)
            if (towlower(an[i]) != towlower(name[i])) return false;
        return true;
    } catch (...) {
        return false;
    }
}

const BYTE* FindAttribute(const std::vector<BYTE>& record, DWORD type,
                          const wchar_t* name, size_t nameLen)
{
    try {
        auto* fr = reinterpret_cast<const FileRecordHeader*>(record.data());
        const BYTE* p = record.data() + fr->firstAttributeOffset;
        const BYTE* e = record.data() + fr->usedSize;
        while (p + sizeof(AttributeHeader) <= e) {
            auto* ah = reinterpret_cast<const AttributeHeader*>(p);
            if (ah->type == kAttrEnd || ah->length == 0) break;
            if (ah->type == type && AttrNameEquals(ah, p, name, nameLen)) return p;
            p += ah->length;
        }
        return nullptr;
    } catch (...) {
        return nullptr;
    }
}

bool ReadNonResidentBytes(const Volume& vol, const BYTE* attr, DWORD attrLen,
                          std::vector<BYTE>& out)
{
    try {
        auto* ah  = reinterpret_cast<const AttributeHeader*>(attr);
        if (!ah->nonResident) return false;
        auto* nra = reinterpret_cast<const NonResidentAttribute*>(attr);
        std::vector<DataRun> runs;
        if (!ParseDataRuns(attr + nra->runListOffset, attr + attrLen, runs)) return false;
        out.assign(static_cast<size_t>(nra->realSize), 0);
        if (nra->realSize == 0) return true;
        constexpr DWORD kChunk = 1 << 16;
        LONGLONG written = 0;
        while (written < nra->realSize) {
            DWORD chunk = kChunk;
            if (static_cast<LONGLONG>(chunk) > nra->realSize - written)
                chunk = static_cast<DWORD>(nra->realSize - written);
            if (!ReadRunlistRange(vol, runs, written, chunk, out.data() + written))
                return false;
            written += chunk;
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool ParseAttributeList(const Volume& vol, const std::vector<BYTE>& baseRecord,
                        std::vector<AttrListEntry>& out)
{
    try {
        out.clear();
        const BYTE* alAttr = FindAttribute(baseRecord, kAttrAttributeList, nullptr, 0);
        if (!alAttr) return true;
        auto* alAh = reinterpret_cast<const AttributeHeader*>(alAttr);
        const BYTE* data = nullptr;
        DWORD       len  = 0;
        std::vector<BYTE> nonResStorage;
        if (!alAh->nonResident) {
            auto* ra = reinterpret_cast<const ResidentAttribute*>(alAttr);
            data = alAttr + ra->valueOffset;
            len  = ra->valueLength;
        } else {
            if (!ReadNonResidentBytes(vol, alAttr, alAh->length, nonResStorage)) return false;
            data = nonResStorage.data();
            len  = static_cast<DWORD>(nonResStorage.size());
        }
        const BYTE* p = data;
        const BYTE* e = data + len;
        while (p + 26 <= e) {
            DWORD type    = *reinterpret_cast<const DWORD*>(p + 0);
            WORD  entLen  = *reinterpret_cast<const WORD*>(p + 4);
            BYTE  nameLen = p[6];
            BYTE  nameOff = p[7];
            if (type == kAttrEnd || entLen == 0) break;
            if (p + entLen > e) break;
            AttrListEntry ale;
            ale.type     = type;
            ale.startVcn = *reinterpret_cast<const LONGLONG*>(p + 8);
            ale.fileRef  = *reinterpret_cast<const LONGLONG*>(p + 16);
            ale.attrId   = *reinterpret_cast<const WORD*>(p + 24);
            if (nameLen > 0 &&
                static_cast<DWORD>(nameOff) + static_cast<DWORD>(nameLen) * 2u <= entLen)
            {
                ale.name.assign(reinterpret_cast<const wchar_t*>(p + nameOff),
                                static_cast<size_t>(nameLen));
            }
            out.push_back(std::move(ale));
            p += entLen;
        }
        return true;
    } catch (...) {
        return false;
    }
}

LONGLONG FindRecordForAttr(const std::vector<AttrListEntry>& list,
                           DWORD type, const wchar_t* name, size_t nameLen)
{
    try {
        for (const auto& ale : list) {
            if (ale.type != type) continue;
            if (ale.startVcn != 0) continue;
            if (nameLen == 0) {
                if (!ale.name.empty()) continue;
            } else {
                if (ale.name.size() != nameLen) continue;
                bool ok = true;
                for (size_t i = 0; i < nameLen; ++i) {
                    if (towlower(ale.name[i]) != towlower(name[i])) { ok = false; break; }
                }
                if (!ok) continue;
            }
            return static_cast<LONGLONG>(ale.fileRef & 0x0000FFFFFFFFFFFFLL);
        }
        return -1;
    } catch (...) {
        return -1;
    }
}

const BYTE* FindAttrAnywhere(const Volume& vol, const std::vector<BYTE>& baseRecord,
                             DWORD type, const wchar_t* name, size_t nameLen,
                             std::vector<BYTE>& extStorage)
{
    try {
        extStorage.clear();
        if (const BYTE* p = FindAttribute(baseRecord, type, name, nameLen)) return p;
        std::vector<AttrListEntry> entries;
        if (!ParseAttributeList(vol, baseRecord, entries)) return nullptr;
        if (entries.empty()) return nullptr;
        LONGLONG extRec = FindRecordForAttr(entries, type, name, nameLen);
        if (extRec < 0) return nullptr;
        if (!ReadMftRecord(vol, extRec, extStorage)) return nullptr;
        return FindAttribute(extStorage, type, name, nameLen);
    } catch (...) {
        return nullptr;
    }
}

LONGLONG SearchEntries(const BYTE* entriesStart, const BYTE* entriesEnd,
                       const std::wstring& targetLower)
{
    try {
        const BYTE* p = entriesStart;
        while (p + sizeof(IndexEntry) <= entriesEnd) {
            auto* ie = reinterpret_cast<const IndexEntry*>(p);
            if (ie->size == 0 || p + ie->size > entriesEnd) break;
            if (ie->contentSize > 0 && !(ie->flags & kIndexEntryLast)) {
                auto* fn = reinterpret_cast<const FileNameAttribute*>(p + sizeof(IndexEntry));
                if (fn->namespaceFlag != 2) {
                    std::wstring lower(fn->name, fn->name + fn->nameLength);
                    for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));
                    if (lower == targetLower)
                        return static_cast<LONGLONG>(ie->fileReference & 0x0000FFFFFFFFFFFFLL);
                }
            }
            if (ie->flags & kIndexEntryLast) break;
            p += ie->size;
        }
        return -1;
    } catch (...) {
        return -1;
    }
}

LONGLONG SearchDirectory(const Volume& vol, LONGLONG dirRecordNumber,
                         const std::wstring& nameLower)
{
    try {
        std::vector<BYTE> record;
        if (!ReadMftRecord(vol, dirRecordNumber, record)) return -1;
        auto* fr = reinterpret_cast<FileRecordHeader*>(record.data());
        if (!(fr->flags & 0x0002)) return -1;
        const std::wstring i30 = xorstr_(L"$I30");
        std::vector<BYTE> rootStorage;
        const BYTE* rootAttr = FindAttrAnywhere(vol, record, kAttrIndexRoot,
                                                i30.c_str(), 4, rootStorage);
        if (!rootAttr) return -1;
        auto* rootAh = reinterpret_cast<const AttributeHeader*>(rootAttr);
        if (rootAh->nonResident) return -1;
        auto* rootRa = reinterpret_cast<const ResidentAttribute*>(rootAttr);
        const BYTE* rootValue = rootAttr + rootRa->valueOffset;
        auto* ir = reinterpret_cast<const IndexRoot*>(rootValue);
        const BYTE* hdr = reinterpret_cast<const BYTE*>(&ir->header);
        const BYTE* entStart = hdr + ir->header.firstEntryOffset;
        const BYTE* entEnd   = hdr + ir->header.totalEntrySize;
        if (entEnd > rootAttr + rootAh->length) entEnd = rootAttr + rootAh->length;
        LONGLONG hit = SearchEntries(entStart, entEnd, nameLower);
        if (hit >= 0) return hit;
        std::vector<BYTE> allocStorage;
        const BYTE* allocAttr = FindAttrAnywhere(vol, record, kAttrIndexAllocation,
                                                 i30.c_str(), 4, allocStorage);
        if (!allocAttr) return -1;
        auto* allocAh = reinterpret_cast<const AttributeHeader*>(allocAttr);
        if (!allocAh->nonResident) return -1;
        auto* nra = reinterpret_cast<const NonResidentAttribute*>(allocAttr);
        std::vector<DataRun> idxRuns;
        if (!ParseDataRuns(allocAttr + nra->runListOffset,
                           allocAttr + allocAh->length, idxRuns)) return -1;
        DWORD blockSize = ir->bytesPerIndexRecord;
        if (blockSize == 0) blockSize = 4096;
        LONGLONG totalBytes = nra->realSize;
        if (totalBytes <= 0)
            for (const auto& r : idxRuns) totalBytes += r.length * vol.bytesPerCluster;
        std::vector<BYTE> block(blockSize);
        for (LONGLONG ofs = 0; ofs + blockSize <= totalBytes; ofs += blockSize) {
            if (!ReadRunlistRange(vol, idxRuns, ofs, blockSize, block.data())) continue;
            auto* ibh = reinterpret_cast<IndexBlockHeader*>(block.data());
            if (ibh->magic != kIndxMagic) continue;
            ApplyFixups(block.data(), block.size(),
                        ibh->usaOffset, ibh->usaCount, vol.bytesPerSector);
            const BYTE* bhdr = reinterpret_cast<const BYTE*>(&ibh->header);
            const BYTE* bStart = bhdr + ibh->header.firstEntryOffset;
            const BYTE* bEnd   = bhdr + ibh->header.totalEntrySize;
            if (bEnd > block.data() + blockSize) bEnd = block.data() + blockSize;
            hit = SearchEntries(bStart, bEnd, nameLower);
            if (hit >= 0) return hit;
        }
        return -1;
    } catch (...) {
        return -1;
    }
}

bool WalkPathToMft(const Volume& vol, const std::wstring& relPath, LONGLONG& outRecord)
{
    try {
        LONGLONG cur = kRootDirRecord;
        size_t start = 0;
        while (start < relPath.size()) {
            size_t end = relPath.find(L'\\', start);
            if (end == std::wstring::npos) end = relPath.size();
            if (end > start) {
                std::wstring comp = relPath.substr(start, end - start);
                std::wstring lower = comp;
                for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));
                LONGLONG next = SearchDirectory(vol, cur, lower);
                if (next < 0) return false;
                cur = next;
            }
            start = end + 1;
        }
        outRecord = cur;
        return true;
    } catch (...) {
        return false;
    }
}

bool CopyFileFromMft(const Volume& vol, LONGLONG fileRecord, const std::wstring& dstPath)
{
    try {
        std::vector<BYTE> record;
        if (!ReadMftRecord(vol, fileRecord, record)) return false;
        std::vector<BYTE> dataStorage;
        const BYTE* dataAttr = FindAttrAnywhere(vol, record, kAttrData, nullptr, 0, dataStorage);
        if (!dataAttr) return false;
        auto* ah = reinterpret_cast<const AttributeHeader*>(dataAttr);
        HANDLE hDst = CreateFileW(dstPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, NULL);
        if (hDst == INVALID_HANDLE_VALUE) return false;
        bool ok = true;
        if (!ah->nonResident) {
            auto* ra = reinterpret_cast<const ResidentAttribute*>(dataAttr);
            const BYTE* data = dataAttr + ra->valueOffset;
            DWORD wr = 0;
            if (!WriteFile(hDst, data, ra->valueLength, &wr, NULL) || wr != ra->valueLength)
                ok = false;
        } else {
            auto* nra = reinterpret_cast<const NonResidentAttribute*>(dataAttr);
            LONGLONG fileSize = nra->realSize;
            std::vector<DataRun> runs;
            if (!ParseDataRuns(dataAttr + nra->runListOffset,
                               dataAttr + ah->length, runs)) ok = false;
            if (ok) {
                constexpr DWORD kChunk = 1 << 20;
                std::vector<BYTE> buf(kChunk);
                LONGLONG written = 0;
                while (written < fileSize) {
                    DWORD chunk = kChunk;
                    if (static_cast<LONGLONG>(chunk) > fileSize - written)
                        chunk = static_cast<DWORD>(fileSize - written);
                    if (!ReadRunlistRange(vol, runs, written, chunk, buf.data())) { ok = false; break; }
                    DWORD wr = 0;
                    if (!WriteFile(hDst, buf.data(), chunk, &wr, NULL) || wr != chunk) { ok = false; break; }
                    written += chunk;
                }
            }
        }
        CloseHandle(hDst);
        if (!ok) DeleteFileW(dstPath.c_str());
        return ok;
    } catch (...) {
        return false;
    }
}

bool ListDirectory(const Volume& vol, LONGLONG dirRecordNumber, std::vector<DirEntry>& out)
{
    try {
        out.clear();
        std::vector<BYTE> record;
        if (!ReadMftRecord(vol, dirRecordNumber, record)) return false;
        const std::wstring i30 = xorstr_(L"$I30");
        std::vector<BYTE> rootStorage;
        const BYTE* rootAttr = FindAttrAnywhere(vol, record, kAttrIndexRoot,
                                                i30.c_str(), 4, rootStorage);
        if (!rootAttr) return false;
        auto* rootAh = reinterpret_cast<const AttributeHeader*>(rootAttr);
        if (rootAh->nonResident) return false;
        auto* rootRa = reinterpret_cast<const ResidentAttribute*>(rootAttr);
        const BYTE* rootValue = rootAttr + rootRa->valueOffset;
        auto* ir = reinterpret_cast<const IndexRoot*>(rootValue);

        auto collect = [&](const BYTE* s, const BYTE* e) {
            const BYTE* p = s;
            while (p + sizeof(IndexEntry) <= e) {
                auto* ie = reinterpret_cast<const IndexEntry*>(p);
                if (ie->size == 0 || p + ie->size > e) break;
                if (ie->contentSize > 0 && !(ie->flags & kIndexEntryLast)) {
                    auto* fn = reinterpret_cast<const FileNameAttribute*>(p + sizeof(IndexEntry));
                    if (fn->namespaceFlag != 2 && fn->nameLength > 0) {
                        DirEntry d;
                        d.recordNumber = static_cast<LONGLONG>(
                            ie->fileReference & 0x0000FFFFFFFFFFFFLL);
                        d.name.assign(fn->name, fn->nameLength);
                        out.push_back(std::move(d));
                    }
                }
                if (ie->flags & kIndexEntryLast) break;
                p += ie->size;
            }
        };

        const BYTE* hdr = reinterpret_cast<const BYTE*>(&ir->header);
        const BYTE* entStart = hdr + ir->header.firstEntryOffset;
        const BYTE* entEnd   = hdr + ir->header.totalEntrySize;
        if (entEnd > rootAttr + rootAh->length) entEnd = rootAttr + rootAh->length;
        collect(entStart, entEnd);

        std::vector<BYTE> allocStorage;
        const BYTE* allocAttr = FindAttrAnywhere(vol, record, kAttrIndexAllocation,
                                                 i30.c_str(), 4, allocStorage);
        if (allocAttr) {
            auto* allocAh = reinterpret_cast<const AttributeHeader*>(allocAttr);
            if (allocAh->nonResident) {
                auto* nra = reinterpret_cast<const NonResidentAttribute*>(allocAttr);
                std::vector<DataRun> idxRuns;
                if (ParseDataRuns(allocAttr + nra->runListOffset,
                                  allocAttr + allocAh->length, idxRuns)) {
                    DWORD blockSize = ir->bytesPerIndexRecord;
                    if (blockSize == 0) blockSize = 4096;
                    LONGLONG totalBytes = nra->realSize;
                    if (totalBytes <= 0)
                        for (const auto& r : idxRuns) totalBytes += r.length * vol.bytesPerCluster;
                    std::vector<BYTE> block(blockSize);
                    for (LONGLONG ofs = 0; ofs + blockSize <= totalBytes; ofs += blockSize) {
                        if (!ReadRunlistRange(vol, idxRuns, ofs, blockSize, block.data())) continue;
                        auto* ibh = reinterpret_cast<IndexBlockHeader*>(block.data());
                        if (ibh->magic != kIndxMagic) continue;
                        ApplyFixups(block.data(), block.size(),
                                    ibh->usaOffset, ibh->usaCount, vol.bytesPerSector);
                        const BYTE* bhdr = reinterpret_cast<const BYTE*>(&ibh->header);
                        const BYTE* bStart = bhdr + ibh->header.firstEntryOffset;
                        const BYTE* bEnd   = bhdr + ibh->header.totalEntrySize;
                        if (bEnd > block.data() + blockSize) bEnd = block.data() + blockSize;
                        collect(bStart, bEnd);
                    }
                }
            }
        }
        return true;
    } catch (...) {
        return false;
    }
}

bool RawCopyAllInDirectory(const std::wstring& srcDir, const std::wstring& dstDir)
{
    try {
        std::wstring src = srcDir;
        const std::wstring qpfx = xorstr_(L"\\\\?\\");
        if (src.size() >= 4 && src.compare(0, 4, qpfx) == 0) src.erase(0, 4);
        if (src.size() < 3 || src[1] != L':' || src[2] != L'\\') return false;
        Volume vol;
        if (!OpenVolume(static_cast<wchar_t>(towupper(src[0])), vol)) return false;
        std::wstring rel = src.substr(3);
        while (!rel.empty() && rel.back() == L'\\') rel.pop_back();
        LONGLONG dirRec = -1;
        if (!WalkPathToMft(vol, rel, dirRec)) return false;
        std::vector<DirEntry> entries;
        if (!ListDirectory(vol, dirRec, entries)) return false;
        std::wstring dst = dstDir;
        if (!dst.empty() && dst.back() != L'\\') dst += L'\\';
        const std::wstring dot1 = xorstr_(L".");
        const std::wstring dot2 = xorstr_(L"..");
        int copied = 0;
        for (const auto& e : entries) {
            if (e.name == dot1 || e.name == dot2) continue;
            std::vector<BYTE> recCheck;
            if (ReadMftRecord(vol, e.recordNumber, recCheck)) {
                auto* fr = reinterpret_cast<FileRecordHeader*>(recCheck.data());
                if (fr->flags & 0x0002) continue;
                if (!(fr->flags & 0x0001)) continue;
            }
            if (!CopyFileFromMft(vol, e.recordNumber, dst + e.name)) continue;
            ++copied;
        }
        return copied > 0;
    } catch (...) {
        return false;
    }
}

bool ReadLong(JET_SESID ses, JET_TABLEID tbl, JET_COLUMNID col, LONG& out)
{
    try {
        unsigned long actual = 0;
        JET_ERR err = JetRetrieveColumn(ses, tbl, col, &out, sizeof(out), &actual, 0, NULL);
        return (err == JET_errSuccess) && (actual >= sizeof(LONG));
    } catch (...) {
        return false;
    }
}

bool ReadShort(JET_SESID ses, JET_TABLEID tbl, JET_COLUMNID col, short& out)
{
    try {
        unsigned long actual = 0;
        JET_ERR err = JetRetrieveColumn(ses, tbl, col, &out, sizeof(out), &actual, 0, NULL);
        return (err == JET_errSuccess) && (actual >= sizeof(short));
    } catch (...) {
        return false;
    }
}

bool ReadLongLong(JET_SESID ses, JET_TABLEID tbl, JET_COLUMNID col, LONGLONG& out)
{
    try {
        unsigned long actual = 0;
        JET_ERR err = JetRetrieveColumn(ses, tbl, col, &out, sizeof(out), &actual, 0, NULL);
        return (err == JET_errSuccess) && (actual >= sizeof(LONGLONG));
    } catch (...) {
        return false;
    }
}

bool ReadBinary(JET_SESID ses, JET_TABLEID tbl, JET_COLUMNID col, std::vector<BYTE>& out)
{
    try {
        out.clear();
        BYTE stack[4096];
        unsigned long actual = 0;
        JET_ERR err = JetRetrieveColumn(ses, tbl, col, stack, sizeof(stack), &actual, 0, NULL);
        if (err == JET_errSuccess && actual > 0) {
            out.assign(stack, stack + actual);
            return true;
        }
        if (err == JET_wrnBufferTruncated && actual > 0) {
            out.resize(actual);
            err = JetRetrieveColumn(ses, tbl, col, out.data(), actual, &actual, 0, NULL);
            return err == JET_errSuccess;
        }
        return false;
    } catch (...) {
        return false;
    }
}

JET_ERR GetColumnId(JET_SESID ses, JET_TABLEID tbl, const char* name, JET_COLUMNID& out)
{
    try {
        JET_COLUMNDEF def{};
        JET_ERR err = JetGetTableColumnInfo(ses, tbl, name, &def, sizeof(def), JET_ColInfo);
        if (err == JET_errSuccess) out = def.columnid;
        return err;
    } catch (...) {
        return JET_errInternalError;
    }
}

JET_ERR GetColumnIdAndType(JET_SESID ses, JET_TABLEID tbl, const char* name,
                           JET_COLUMNID& outId, JET_COLTYP& outType)
{
    try {
        JET_COLUMNDEF def{};
        JET_ERR err = JetGetTableColumnInfo(ses, tbl, name, &def, sizeof(def), JET_ColInfo);
        if (err == JET_errSuccess) {
            outId   = def.columnid;
            outType = def.coltyp;
        }
        return err;
    } catch (...) {
        return JET_errInternalError;
    }
}

std::wstring FormatFileTime(ULONGLONG raw)
{
    try {
        if (raw == 0) return L"";
        FILETIME ft{};
        ft.dwLowDateTime  = static_cast<DWORD>(raw & 0xFFFFFFFFu);
        ft.dwHighDateTime = static_cast<DWORD>(raw >> 32);
        FILETIME local{};
        if (!FileTimeToLocalFileTime(&ft, &local)) return L"";
        SYSTEMTIME st{};
        if (!FileTimeToSystemTime(&local, &st)) return L"";
        wchar_t buf[64];
        swprintf_s(buf, xorstr_(L"%04d-%02d-%02d %02d:%02d:%02d"),
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        return buf;
    } catch (...) {
        return L"";
    }
}

ULONGLONG OleDateToFileTimeTicks(double oleDate)
{
    try {
        if (oleDate <= 0.0) return 0;
        static const ULONGLONG kOleEpochTicks = []() -> ULONGLONG {
            SYSTEMTIME st{};
            st.wYear  = 1899;
            st.wMonth = 12;
            st.wDay   = 30;
            FILETIME ft{};
            if (!SystemTimeToFileTime(&st, &ft)) return 0;
            ULARGE_INTEGER u;
            u.LowPart  = ft.dwLowDateTime;
            u.HighPart = ft.dwHighDateTime;
            return u.QuadPart;
        }();
        constexpr ULONGLONG kTicksPerDay = 86400ULL * 10000000ULL;
        double ticks = oleDate * static_cast<double>(kTicksPerDay);
        if (ticks < 0.0) return 0;
        return kOleEpochTicks + static_cast<ULONGLONG>(ticks);
    } catch (...) {
        return 0;
    }
}

bool IsSaneFileTime(ULONGLONG ticks)
{
    try {
        if (ticks == 0) return false;
        FILETIME ft{};
        ft.dwLowDateTime  = static_cast<DWORD>(ticks & 0xFFFFFFFFu);
        ft.dwHighDateTime = static_cast<DWORD>(ticks >> 32);
        SYSTEMTIME st{};
        if (!FileTimeToSystemTime(&ft, &st)) return false;
        return st.wYear >= 1990 && st.wYear <= 2200;
    } catch (...) {
        return false;
    }
}

ULONGLONG ReadTimestampTicks(JET_SESID ses, JET_TABLEID tbl, JET_COLUMNID col)
{
    try {
        if (col == 0) return 0;
        BYTE buf[16] = {};
        unsigned long actual = 0;
        JET_ERR err = JetRetrieveColumn(ses, tbl, col, buf, sizeof(buf), &actual, 0, NULL);
        if (err != JET_errSuccess || actual < 8) return 0;
        ULONGLONG asLong = 0;
        double    asDbl  = 0.0;
        std::memcpy(&asLong, buf, sizeof(ULONGLONG));
        std::memcpy(&asDbl,  buf, sizeof(double));
        if (IsSaneFileTime(asLong)) return asLong;
        ULONGLONG fromOle = OleDateToFileTimeTicks(asDbl);
        if (IsSaneFileTime(fromOle)) return fromOle;
        return 0;
    } catch (...) {
        return 0;
    }
}

std::wstring SidToString(const BYTE* data, size_t size)
{
    try {
        if (!data || size < 8) return L"";
        PSID sid = const_cast<PSID>(static_cast<const void*>(data));
        if (!IsValidSid(sid)) return L"";
        LPWSTR s = nullptr;
        if (!ConvertSidToStringSidW(sid, &s)) return L"";
        std::wstring out(s);
        LocalFree(s);
        return out;
    } catch (...) {
        return L"";
    }
}

std::wstring DecodeAppBlob(const std::vector<BYTE>& blob)
{
    try {
        if (blob.size() < 2) return L"";
        size_t offset = 0;
        if (blob[0] == 0xFF) {
            offset = 1;
            if (offset < blob.size() && blob[offset] == 0x00) offset++;
        }
        if (offset + 2 > blob.size()) return L"";
        size_t bytes = blob.size() - offset;
        bytes &= ~1u;
        if (bytes < 2) return L"";
        const wchar_t* p = reinterpret_cast<const wchar_t*>(blob.data() + offset);
        size_t wlen = bytes / sizeof(wchar_t);
        while (wlen > 0 && p[wlen - 1] == L'\0') --wlen;
        if (wlen == 0) return L"";
        std::wstring out(p, wlen);
        size_t nul = out.find(L'\0');
        if (nul != std::wstring::npos) out.resize(nul);
        return out;
    } catch (...) {
        return L"";
    }
}

bool ParseDevicePath(const std::wstring& path, int& vol, std::wstring& rest)
{
    try {
        const std::wstring kPrefix = xorstr_(L"\\Device\\HarddiskVolume");
        size_t plen = kPrefix.size();
        if (path.size() <= plen) return false;
        if (_wcsnicmp(path.c_str(), kPrefix.c_str(), plen) != 0) return false;
        size_t pos = plen;
        if (pos >= path.size() || !iswdigit(path[pos])) return false;
        size_t end = path.find(L'\\', pos);
        if (end == std::wstring::npos) return false;
        vol  = _wtoi(path.substr(pos, end - pos).c_str());
        rest = path.substr(end);
        return true;
    } catch (...) {
        return false;
    }
}

std::wstring ResolveDevicePath(const std::wstring& path, std::map<int, wchar_t>& cache)
{
    try {
        int vol = 0;
        std::wstring rest;
        if (!ParseDevicePath(path, vol, rest)) return path;
        auto it = cache.find(vol);
        const std::wstring colon = xorstr_(L":");
        if (it != cache.end())
            return std::wstring(1, it->second) + colon + rest;
        std::wstring test = xorstr_(L"C") + colon + rest;
        if (GetFileAttributesW(test.c_str()) != INVALID_FILE_ATTRIBUTES) {
            cache[vol] = L'C';
            return test;
        }
        for (wchar_t d = L'A'; d <= L'Z'; d++) {
            if (d == L'C') continue;
            test = std::wstring(1, d) + colon + rest;
            if (GetFileAttributesW(test.c_str()) != INVALID_FILE_ATTRIBUTES) {
                cache[vol] = d;
                return test;
            }
        }
        return path;
    } catch (...) {
        return path;
    }
}

void DeleteEseRawArtifacts(const std::wstring& dir)
{
    try {
        if (dir.empty()) return;
        std::wstring pattern = dir;
        if (pattern.back() != L'\\') pattern += L'\\';
        pattern += xorstr_(L"*");
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        const std::wstring ext = xorstr_(L".raw");
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring name(fd.cFileName);
            std::wstring lower(name);
            for (auto& c : lower) c = static_cast<wchar_t>(towlower(c));
            bool hit = false;
            size_t pos = lower.find(ext);
            while (pos != std::wstring::npos) {
                size_t after = pos + ext.size();
                if (after == lower.size() || lower[after] == L'.') { hit = true; break; }
                pos = lower.find(ext, pos + 1);
            }
            if (hit) {
                std::wstring base = dir;
                if (base.back() != L'\\') base += L'\\';
                std::wstring full = base + name;
                SetFileAttributesW(full.c_str(), FILE_ATTRIBUTE_NORMAL);
                DeleteFileW(full.c_str());
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    } catch (...) {
        return;
    }
}

const wchar_t* TempRootName()
{
    static const std::wstring s = xorstr_(L"SrumPe2Scan");
    return s.c_str();
}

void SweepStaleRawArtifactsInRoot()
{
    try {
        wchar_t base[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, base)) return;
        std::wstring root = base;
        if (!root.empty() && root.back() != L'\\') root += L'\\';
        root += TempRootName();
        root += L'\\';
        if (GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) return;
        std::wstring pattern = root + xorstr_(L"*");
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return;
        const std::wstring dot1 = xorstr_(L".");
        const std::wstring dot2 = xorstr_(L"..");
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (dot1 == fd.cFileName) continue;
            if (dot2 == fd.cFileName) continue;
            std::wstring child = root + fd.cFileName + xorstr_(L"\\");
            DeleteEseRawArtifacts(child);
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    } catch (...) {
        return;
    }
}

void SweepStaleRawArtifactsInExeAndCwd()
{
    try {
        wchar_t exeBuf[MAX_PATH]{};
        if (GetModuleFileNameW(NULL, exeBuf, MAX_PATH) > 0) {
            std::wstring exePath = exeBuf;
            size_t slash = exePath.find_last_of(L'\\');
            if (slash != std::wstring::npos)
                DeleteEseRawArtifacts(exePath.substr(0, slash + 1));
        }
        wchar_t cwdBuf[MAX_PATH]{};
        if (GetCurrentDirectoryW(MAX_PATH, cwdBuf) > 0) {
            std::wstring cwd = cwdBuf;
            if (cwd.back() != L'\\') cwd += L'\\';
            DeleteEseRawArtifacts(cwd);
        }
    } catch (...) {
        return;
    }
}

void DeleteDirRecursive(const std::wstring& dir)
{
    try {
        if (dir.empty()) return;
        std::wstring base = dir;
        if (base.back() != L'\\') base += L'\\';
        std::wstring pattern = base + xorstr_(L"*");
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
        const std::wstring dot1 = xorstr_(L".");
        const std::wstring dot2 = xorstr_(L"..");
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (dot1 == fd.cFileName) continue;
                if (dot2 == fd.cFileName) continue;
                std::wstring child = base + fd.cFileName;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    DeleteDirRecursive(child);
                } else {
                    SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                    DeleteFileW(child.c_str());
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        SetFileAttributesW(dir.c_str(),
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_NORMAL);
        RemoveDirectoryW(dir.c_str());
    } catch (...) {
        return;
    }
}

std::wstring MakeTempDir()
{
    try {
        wchar_t base[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, base)) return L"";
        std::wstring root = std::wstring(base);
        if (!root.empty() && root.back() != L'\\') root += L'\\';
        root += TempRootName();
        CreateDirectoryW(root.c_str(), NULL);
        SetFileAttributesW(root.c_str(),
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_TEMPORARY
            | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        SYSTEMTIME st{};
        GetLocalTime(&st);
        wchar_t stamp[96];
        swprintf_s(stamp, xorstr_(L"%04u%02u%02u-%02u%02u%02u-%lu-%lu"),
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
            GetCurrentProcessId(), GetCurrentThreadId());
        std::wstring dir = root + L'\\' + stamp;
        if (!CreateDirectoryW(dir.c_str(), NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) return L"";
        }
        SetFileAttributesW(dir.c_str(),
            FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_TEMPORARY
            | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
        if (!dir.empty() && dir.back() != L'\\') dir += L'\\';
        return dir;
    } catch (...) {
        return L"";
    }
}

JET_ERR DiscoverPageSize(const std::wstring& srudb, unsigned long& pageSize)
{
    try {
        pageSize = 0;
        JET_DBINFOMISC info{};
        JET_ERR err = JetGetDatabaseFileInfoW(srudb.c_str(), &info, sizeof(info), JET_DbInfoMisc);
        if (err == JET_errSuccess) { pageSize = info.cbPageSize; return JET_errSuccess; }
        unsigned long ps = 0;
        err = JetGetDatabaseFileInfoW(srudb.c_str(), &ps, sizeof(ps), JET_DbInfoPageSize);
        if (err == JET_errSuccess) { pageSize = ps; return JET_errSuccess; }
        return err;
    } catch (...) {
        return JET_errInternalError;
    }
}

void SetParamW(JET_INSTANCE inst, unsigned long pid, JET_API_PTR n, const wchar_t* str)
{
    try {
        JetSetSystemParameterW(&inst, 0, pid, n, reinterpret_cast<JET_PCWSTR>(str));
    } catch (...) {
        return;
    }
}

bool BuildIdMap(JET_SESID ses, JET_DBID dbid,
                std::unordered_map<LONG, IdMapEntry>& map,
                std::map<int, wchar_t>& volumeCache)
{
    try {
        const std::string idMapTable = xorstr_("SruDbIdMapTable");
        JET_TABLEID tbl = 0;
        JET_ERR err = JetOpenTable(ses, dbid, idMapTable.c_str(), NULL, 0,
                                   JET_bitTableReadOnly, &tbl);
        if (err != JET_errSuccess) return false;
        JET_COLUMNID idTypeCol = 0, idIndexCol = 0, idBlobCol = 0;
        GetColumnId(ses, tbl, xorstr_("IdType"),  idTypeCol);
        GetColumnId(ses, tbl, xorstr_("IdIndex"), idIndexCol);
        GetColumnId(ses, tbl, xorstr_("IdBlob"),  idBlobCol);
        if (idIndexCol == 0 || idBlobCol == 0) {
            JetCloseTable(ses, tbl);
            return false;
        }
        err = JetMove(ses, tbl, JET_MoveFirst, 0);
        while (err == JET_errSuccess) {
            IdMapEntry e;
            LONG idx = 0;
            short idType = -1;
            std::vector<BYTE> blob;
            if (idTypeCol) ReadShort(ses, tbl, idTypeCol, idType);
            ReadLong(ses, tbl, idIndexCol, idx);
            ReadBinary(ses, tbl, idBlobCol, blob);
            e.idType = idType;
            if (idType == 3) {
                e.sidString = SidToString(blob.data(), blob.size());
            } else {
                std::wstring raw = DecodeAppBlob(blob);
                e.text = ResolveDevicePath(raw, volumeCache);
            }
            if (idx != 0) map[idx] = std::move(e);
            err = JetMove(ses, tbl, JET_MoveNext, 0);
        }
        JetCloseTable(ses, tbl);
        return true;
    } catch (...) {
        return false;
    }
}

bool LoadNetworkColumns(JET_SESID ses, JET_TABLEID tbl, EseColumns& cols)
{
    try {
        GetColumnIdAndType(ses, tbl, xorstr_("TimeStamp"), cols.timestamp, cols.timestampType);
        GetColumnId(ses, tbl, xorstr_("AppId"),         cols.appId);
        GetColumnId(ses, tbl, xorstr_("UserId"),        cols.userId);
        GetColumnId(ses, tbl, xorstr_("InterfaceLuid"), cols.interfaceLuid);
        GetColumnId(ses, tbl, xorstr_("L2ProfileId"),   cols.l2ProfileId);
        GetColumnId(ses, tbl, xorstr_("BytesSent"),     cols.bytesSent);
        GetColumnId(ses, tbl, xorstr_("BytesRecvd"),    cols.bytesRecvd);
        if (cols.bytesRecvd == 0)
            GetColumnId(ses, tbl, xorstr_("BytesReceived"), cols.bytesRecvd);
        return cols.appId != 0 && cols.bytesSent != 0 && cols.bytesRecvd != 0;
    } catch (...) {
        return false;
    }
}

void ReadNetworkRows(JET_SESID ses, JET_DBID dbid,
                     const std::unordered_map<LONG, IdMapEntry>& idMap,
                     std::vector<SruNetEntry>& out)
{
    try {
        const std::string netTable = xorstr_("{973F5D5C-1D90-4944-BE8E-24B94231A174}");
        JET_TABLEID tbl = 0;
        JET_ERR err = JetOpenTable(ses, dbid, netTable.c_str(), NULL, 0,
                                   JET_bitTableReadOnly, &tbl);
        if (err != JET_errSuccess) return;
        EseColumns cols;
        if (!LoadNetworkColumns(ses, tbl, cols)) { JetCloseTable(ses, tbl); return; }
        out.reserve(8192);
        const std::wstring unknown = xorstr_(L"<unknown>");
        err = JetMove(ses, tbl, JET_MoveFirst, 0);
        while (err == JET_errSuccess) {
            LONG appId = 0;
            LONGLONG sent = 0, recvd = 0;
            ULONGLONG tsTicks = 0;
            ReadLong(ses, tbl, cols.appId,  appId);
            ReadLongLong(ses, tbl, cols.bytesSent,  sent);
            ReadLongLong(ses, tbl, cols.bytesRecvd, recvd);
            tsTicks = ReadTimestampTicks(ses, tbl, cols.timestamp);
            SruNetEntry e;
            auto it = idMap.find(appId);
            if (it != idMap.end() && !it->second.text.empty())
                e.path = it->second.text;
            else
                e.path = unknown;
            e.bytesSent    = static_cast<ULONGLONG>(sent  > 0 ? sent  : 0);
            e.bytesRecvd   = static_cast<ULONGLONG>(recvd > 0 ? recvd : 0);
            e.rawTimestamp = tsTicks;
            e.timestamp    = FormatFileTime(tsTicks);
            out.push_back(std::move(e));
            err = JetMove(ses, tbl, JET_MoveNext, 0);
        }
        JetCloseTable(ses, tbl);
    } catch (...) {
        return;
    }
}

bool RunEsentutl(const std::wstring& args, const std::wstring& workingDir, DWORD& exitCode)
{
    try {
        exitCode = (DWORD)-1;
        wchar_t sysDirBuf[MAX_PATH] = L"";
        UINT len = GetSystemDirectoryW(sysDirBuf, MAX_PATH);
        if (len == 0 || len >= MAX_PATH) return false;
        std::wstring exe = sysDirBuf;
        if (!exe.empty() && exe.back() != L'\\') exe += L'\\';
        exe += xorstr_(L"esentutl.exe");
        if (GetFileAttributesW(exe.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
        std::wstring cmdLine = xorstr_(L"\"") + exe + xorstr_(L"\" ") + args;
        HANDLE readPipe = NULL, writePipe = NULL;
        SECURITY_ATTRIBUTES sa{};
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = TRUE;
        if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) return false;
        SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = writePipe;
        si.hStdError  = writePipe;
        si.hStdInput  = GetStdHandle(STD_INPUT_HANDLE);
        PROCESS_INFORMATION pi{};
        std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
        cmdBuf.push_back(L'\0');
        std::wstring cwd = workingDir;
        if (!cwd.empty() && cwd.back() == L'\\') cwd.pop_back();
        LPCWSTR cwdArg = cwd.empty() ? nullptr : cwd.c_str();
        BOOL ok = CreateProcessW(exe.c_str(), cmdBuf.data(),
                                 nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                 nullptr, cwdArg, &si, &pi);
        CloseHandle(writePipe);
        if (!ok) { CloseHandle(readPipe); return false; }
        char readBuf[4096];
        DWORD bytesRead = 0;
        DWORD total = 0;
        while (ReadFile(readPipe, readBuf, sizeof(readBuf), &bytesRead, NULL)
               && bytesRead > 0) {
            total += bytesRead;
            if (total > 64 * 1024) break;
        }
        CloseHandle(readPipe);
        if (WaitForSingleObject(pi.hProcess, 120000) == WAIT_TIMEOUT) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        GetExitCodeProcess(pi.hProcess, &exitCode);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    } catch (...) {
        return false;
    }
}

bool EsentutlSoftRecover(const std::wstring& tempDir)
{
    try {
        std::wstring d = tempDir;
        if (!d.empty() && d.back() == L'\\') d.pop_back();
        const std::wstring base = xorstr_(L"SRU");
        std::wstring args = xorstr_(L"/r ") + base +
                            xorstr_(L" /i /l\"") + d + xorstr_(L"\"") +
                            xorstr_(L" /s\"") + d + xorstr_(L"\"");
        DWORD exitCode = 0;
        if (!RunEsentutl(args, tempDir, exitCode)) return false;
        return exitCode == 0;
    } catch (...) {
        return false;
    }
}

bool EsentutlRepair(const std::wstring& srudbCopy, const std::wstring& tempDir)
{
    try {
        std::wstring t = tempDir;
        if (!t.empty() && t.back() == L'\\') t.pop_back();
        std::wstring args = xorstr_(L"/p \"") + srudbCopy + xorstr_(L"\"") +
                            xorstr_(L" /o /t\"") + t + xorstr_(L"\\repair.tmp\"");
        DWORD exitCode = 0;
        if (!RunEsentutl(args, tempDir, exitCode)) return false;
        return exitCode == 0;
    } catch (...) {
        return false;
    }
}

JET_ERR OpenAndReadDatabase(const std::wstring& srudbPath, const std::wstring& sysDir,
                            const wchar_t* instanceName, bool readOnly, bool recoveryOn,
                            unsigned long pageSize, std::vector<SruNetEntry>& out)
{
    try {
        out.clear();
        if (pageSize == 0) pageSize = 32 * 1024;
        const std::string baseName = xorstr_("SRU");
        std::wstring kBaseNameW(baseName.begin(), baseName.end());
        JET_INSTANCE inst = JET_instanceNil;
        JET_ERR jerr = JetCreateInstance2W(&inst, instanceName, instanceName, 0);
        if (jerr != JET_errSuccess) return jerr;
        SetParamW(inst, JET_paramSystemPath,  0, sysDir.c_str());
        SetParamW(inst, JET_paramLogFilePath, 0, sysDir.c_str());
        SetParamW(inst, JET_paramTempPath,    0, sysDir.c_str());
        SetParamW(inst, JET_paramBaseName,    0, kBaseNameW.c_str());
        const std::wstring on  = xorstr_(L"On");
        const std::wstring off = xorstr_(L"Off");
        SetParamW(inst, JET_paramRecovery, 0,
                  recoveryOn ? on.c_str() : off.c_str());
        JetSetSystemParameterW(&inst, 0, JET_paramCircularLog,           1, NULL);
        JetSetSystemParameterW(&inst, 0, JET_paramDatabasePageSize, pageSize, NULL);
        JetSetSystemParameterW(&inst, 0, JET_paramMaxTemporaryTables,    0, NULL);
        JetSetSystemParameterW(&inst, 0, JET_paramEnableIndexChecking,   0, NULL);
        JetSetSystemParameterW(&inst, 0, JET_paramCheckpointDepthMax, 0x20000000, NULL);
        JetSetSystemParameterW(&inst, 0, JET_paramNoInformationEvent,    1, NULL);
        jerr = JetInit(&inst);
        if (jerr != JET_errSuccess) {
            if (inst != JET_instanceNil) JetTerm(inst);
            return jerr;
        }
        JET_SESID ses = JET_sesidNil;
        jerr = JetBeginSessionW(inst, &ses, NULL, NULL);
        if (jerr != JET_errSuccess) { JetTerm(inst); return jerr; }
        const JET_GRBIT roBit = readOnly ? JET_bitDbReadOnly : 0;
        JET_GRBIT attachAttempts[] = {
            static_cast<JET_GRBIT>(roBit | JET_bitDbDeleteCorruptIndexes
                                         | JET_bitDbDeleteUnicodeIndexes),
            static_cast<JET_GRBIT>(roBit | JET_bitDbDeleteCorruptIndexes),
            roBit,
        };
        jerr = JET_errInvalidGrbit;
        for (JET_GRBIT g : attachAttempts) {
            jerr = JetAttachDatabaseW(ses, srudbPath.c_str(), g);
            if (jerr == JET_errSuccess || jerr == JET_wrnDatabaseAttached) break;
            if (jerr != JET_errInvalidGrbit) break;
        }
        if (jerr != JET_errSuccess && jerr != JET_wrnDatabaseAttached) {
            JetEndSession(ses, 0);
            JetTerm(inst);
            return jerr;
        }
        JET_DBID dbid = 0;
        JET_ERR openErr = JetOpenDatabaseW(ses, srudbPath.c_str(), NULL, &dbid,
                                           JET_bitDbReadOnly);
        if (openErr != JET_errSuccess) {
            JetDetachDatabaseW(ses, srudbPath.c_str());
            JetEndSession(ses, 0);
            JetTerm(inst);
            return openErr;
        }
        std::map<int, wchar_t> volumeCache;
        std::unordered_map<LONG, IdMapEntry> idMap;
        BuildIdMap(ses, dbid, idMap, volumeCache);
        ReadNetworkRows(ses, dbid, idMap, out);
        JetCloseDatabase(ses, dbid, 0);
        JetDetachDatabaseW(ses, srudbPath.c_str());
        JetEndSession(ses, 0);
        JetTerm(inst);
        return JET_errSuccess;
    } catch (...) {
        return JET_errInternalError;
    }
}

std::vector<SruNetEntry> ParseFromPath(const std::wstring& srudbPath)
{
    try {
        std::vector<SruNetEntry> empty;
        if (srudbPath.empty()) return empty;
        SweepStaleRawArtifactsInRoot();
        SweepStaleRawArtifactsInExeAndCwd();
        std::wstring srcDir = srudbPath;
        size_t slash = srcDir.find_last_of(xorstr_(L"\\/"));
        if (slash == std::wstring::npos) return empty;
        srcDir.resize(slash + 1);
        std::wstring tempDir = MakeTempDir();
        if (tempDir.empty()) return empty;
        if (!RawCopyAllInDirectory(srcDir, tempDir)) return empty;
        std::wstring srudbCopy = tempDir + xorstr_(L"SRUDB.dat");
        if (GetFileAttributesW(srudbCopy.c_str()) == INVALID_FILE_ATTRIBUTES) return empty;
        EsentutlSoftRecover(tempDir);
        unsigned long pageSize = 0;
        DiscoverPageSize(srudbCopy, pageSize);
        std::vector<SruNetEntry> result;
        const std::wstring instA = xorstr_(L"SrumPe2Snap");
        const std::wstring instB = xorstr_(L"SrumPe2Rep");
        JET_ERR jerr = OpenAndReadDatabase(srudbCopy, tempDir, instA.c_str(),
                                           true, false, pageSize, result);
        if (jerr != JET_errSuccess) {
            if (EsentutlRepair(srudbCopy, tempDir)) {
                result.clear();
                jerr = OpenAndReadDatabase(srudbCopy, tempDir, instB.c_str(),
                                           true, false, pageSize, result);
            }
        }
        DeleteEseRawArtifacts(tempDir);
        if (jerr != JET_errSuccess) return empty;
        return result;
    } catch (...) {
        return {};
    }
}

std::vector<SruNetEntry> ParseLive()
{
    try {
        const std::wstring liveDir  = xorstr_(L"C:\\Windows\\System32\\sru\\");
        const std::wstring fileName = xorstr_(L"SRUDB.dat");
        return ParseFromPath(liveDir + fileName);
    } catch (...) {
        return {};
    }
}

void CleanupAllTempFiles()
{
    try {
        wchar_t base[MAX_PATH]{};
        if (!GetTempPathW(MAX_PATH, base)) return;
        std::wstring root = base;
        if (!root.empty() && root.back() != L'\\') root += L'\\';
        root += TempRootName();
        if (GetFileAttributesW(root.c_str()) == INVALID_FILE_ATTRIBUTES) return;
        DeleteDirRecursive(root);
        SweepStaleRawArtifactsInExeAndCwd();
    } catch (...) {
        return;
    }
}

bool IsSuspiciousBasename(const std::wstring& path)
{
    try {
        if (path.empty()) return false;
        size_t slash = path.find_last_of(xorstr_(L"\\/"));
        std::wstring base = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
        if (base.empty()) return false;
        for (auto& c : base) c = static_cast<wchar_t>(towlower(c));

        static const std::unordered_set<std::wstring> kNames = {
            xorstr_(L"notepad.exe"),        xorstr_(L"snippingtool.exe"),
            xorstr_(L"osk.exe"),            xorstr_(L"mspaint.exe"),
            xorstr_(L"calc.exe"),           xorstr_(L"calculatorapp.exe"),
            xorstr_(L"svchost.exe"),        xorstr_(L"ctfmon.exe"),
            xorstr_(L"powershell.exe"),     xorstr_(L"powershell_ise.exe"),
            xorstr_(L"cmd.exe"),            xorstr_(L"conhost.exe"),
        };
        return kNames.find(base) != kNames.end();
    } catch (...) {
        return false;
    }
}

std::string WideToNarrowAscii(const std::wstring& w)
{
    try {
        std::string out;
        out.reserve(w.size());
        for (wchar_t wc : w) {
            if (wc >= 32 && wc <= 126) out += static_cast<char>(wc);
            else out += '?';
        }
        return out;
    } catch (...) {
        return {};
    }
}

void RunCpp()
{
    try {
        static std::mutex s_mu;
        std::lock_guard<std::mutex> lock(s_mu);

        std::vector<SruNetEntry> entries = ParseLive();

        std::unordered_set<std::wstring> seen;
        const std::wstring prefix = xorstr_(L"App Has Suspicious Data Usage (Possible PE Injection/Bypass Related):");

        for (const SruNetEntry& e : entries) {
            if (!IsSuspiciousBasename(e.path)) continue;
            std::wstring key = e.path;
            for (auto& c : key) c = static_cast<wchar_t>(towlower(c));
            if (!seen.insert(key).second) continue;

            std::string ts = e.timestamp.empty()
                             ? std::string(xorstr_("N/A"))
                             : WideToNarrowAscii(e.timestamp);
            LOG(WARNING, ts) << prefix << e.path;
        }

        CleanupAllTempFiles();
    } catch (...) {
        try { CleanupAllTempFiles(); } catch (...) {}
        return;
    }
}

}

void c_pe_injection_2::start_pe_injection_2_scan()
{
    __try {
        RunCpp();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
}
