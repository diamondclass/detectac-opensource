#include "c_amcache.h"
#include "c_amcache_filters.h"
#include "../../../utils/fresh_install.h"

namespace {

#pragma pack(push, 1)

    struct NtfsRecHeaderCommon {
        DWORD     signature;
        WORD      usaOffset;
        WORD      usaCount;
        LONGLONG  logFileSeq;
    };

    struct MftRecord {
        NtfsRecHeaderCommon hdr;
        WORD      seqNum;
        WORD      hardLinkCount;
        WORD      attrOffset;
        WORD      flags;
        DWORD     usedSize;
        DWORD     allocSize;
        LONGLONG  baseFileRef;
        WORD      nextAttrId;
        WORD      align;
        DWORD     recordNumber;
    };

    struct AttrHdr {
        DWORD type;
        DWORD length;
        BYTE  nonResident;
        BYTE  nameLen;
        WORD  nameOffset;
        WORD  flags;
        WORD  id;
    };

    struct AttrResident {
        AttrHdr hdr;
        DWORD   valueLen;
        WORD    valueOffset;
        BYTE    indexed;
        BYTE    pad;
    };

    struct AttrNonResident {
        AttrHdr  hdr;
        LONGLONG firstVcn;
        LONGLONG lastVcn;
        WORD     runlistOffset;
        WORD     compressionUnit;
        DWORD    pad;
        LONGLONG allocSize;
        LONGLONG dataSize;
        LONGLONG initSize;
    };

    struct FileNameAttr {
        LONGLONG parentRef;
        LONGLONG createTime;
        LONGLONG modTime;
        LONGLONG mftModTime;
        LONGLONG accessTime;
        LONGLONG allocSize;
        LONGLONG dataSize;
        DWORD    flags;
        DWORD    reparseValue;
        BYTE     nameLen;
        BYTE     nameSpace;
    };

    struct IndexRootHeader {
        DWORD attrType;
        DWORD collation;
        DWORD bytesPerIndex;
        BYTE  clustersPerIndex;
        BYTE  pad[3];
    };

    struct IndexNodeHeader {
        DWORD entriesOffset;
        DWORD endUsedOffset;
        DWORD endAllocOffset;
        DWORD flags;
    };

    struct IndexEntry {
        LONGLONG fileRef;
        WORD     entrySize;
        WORD     keyLen;
        WORD     flags;
        WORD     reserved;
    };

    struct IndexBlockHdr {
        NtfsRecHeaderCommon hdr;
        LONGLONG vcn;
        IndexNodeHeader     node;
    };

#pragma pack(pop)

    constexpr DWORD ATTR_FILE_NAME = 0x30;
    constexpr DWORD ATTR_DATA = 0x80;
    constexpr DWORD ATTR_INDEX_ROOT = 0x90;
    constexpr DWORD ATTR_INDEX_ALLOC = 0xA0;
    constexpr DWORD ATTR_END = 0xFFFFFFFF;
    constexpr ULONGLONG FILEREF_MASK = 0x0000FFFFFFFFFFFFULL;
    constexpr DWORD ROOT_DIR_RECORD = 5;
    constexpr DWORD MFT_FIXUP_BLOCK = 512;
    constexpr WORD  MFT_FLAG_IN_USE = 0x0001;
    constexpr WORD  MFT_FLAG_DIRECTORY = 0x0002;

    constexpr uint32_t INVALID_OFF = 0xFFFFFFFFu;
    constexpr uint32_t DATA_AREA = 0x1000;

    struct NkInfo {
        size_t      cellOff;
        bool        allocated;
        uint32_t    parentRaw;
        int         parentIdx;
        uint32_t    valueCount;
        uint32_t    valueListRaw;
        uint64_t    timestamp;
        std::string name;
    };

    struct VkInfo {
        size_t      cellOff;
        uint32_t    dataSize;
        uint32_t    dataOffset;
        uint32_t    dataType;
        std::string name;
    };

    uint16_t r16(const BYTE* p) noexcept { uint16_t v = 0; memcpy(&v, p, 2); return v; }
    uint32_t r32(const BYTE* p) noexcept { uint32_t v = 0; memcpy(&v, p, 4); return v; }
    uint64_t r64(const BYTE* p) noexcept { uint64_t v = 0; memcpy(&v, p, 8); return v; }

    std::string FormatKeyWriteTime(uint64_t ts) noexcept
    {
        try {
            if (ts == 0) return xorstr_("N/A");
            FILETIME ft;
            ft.dwLowDateTime  = static_cast<DWORD>(ts & 0xFFFFFFFFull);
            ft.dwHighDateTime = static_cast<DWORD>(ts >> 32);
            SYSTEMTIME st{};
            if (!FileTimeToSystemTime(&ft, &st)) return xorstr_("N/A");
            std::ostringstream oss;
            oss << std::setfill('0')
                << std::setw(4) << st.wYear   << '-'
                << std::setw(2) << st.wMonth  << '-'
                << std::setw(2) << st.wDay    << 'T'
                << std::setw(2) << st.wHour   << ':'
                << std::setw(2) << st.wMinute << ':'
                << std::setw(2) << st.wSecond << 'Z';
            return oss.str();
        }
        catch (...) { return xorstr_("N/A"); }
    }

    struct NtfsRun { ULONGLONG lcn; ULONGLONG length; };

    struct NtfsContext {
        HANDLE   hVol = INVALID_HANDLE_VALUE;
        DWORD    bytesPerSector = 0;
        DWORD    bytesPerCluster = 0;
        DWORD    bytesPerMftRec = 0;
        DWORD    bytesPerIndex = 4096;
        ULONGLONG mftLcn = 0;
        std::vector<NtfsRun> mftRuns;

        BYTE* scratch = nullptr;
        SIZE_T scratchSize = 0;

        ~NtfsContext() {
            try {
                if (scratch) VirtualFree(scratch, 0, MEM_RELEASE);
                if (hVol != INVALID_HANDLE_VALUE) CloseHandle(hVol);
            }
            catch (...) {}
        }

        bool EnsureScratch(SIZE_T need) noexcept {
            try {
                if (need <= scratchSize && scratch) return true;
                if (scratch) {
                    VirtualFree(scratch, 0, MEM_RELEASE);
                    scratch = nullptr;
                    scratchSize = 0;
                }
                SIZE_T page = 4096;
                SIZE_T sz = ((need + page - 1) / page) * page;
                scratch = static_cast<BYTE*>(VirtualAlloc(nullptr, sz,
                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
                if (!scratch) return false;
                scratchSize = sz;
                return true;
            }
            catch (...) {
                return false;
            }
        }

        bool ReadRange(ULONGLONG offset, void* dst, SIZE_T len) noexcept {
            try {
                if (hVol == INVALID_HANDLE_VALUE) return false;
                if (len == 0) return true;

                DWORD sec = bytesPerSector ? bytesPerSector : 512;
                ULONGLONG start = offset & ~static_cast<ULONGLONG>(sec - 1);
                SIZE_T    skip = static_cast<SIZE_T>(offset - start);
                SIZE_T    need = ((skip + len + sec - 1) / sec) * sec;

                if (!EnsureScratch(need)) return false;

                LARGE_INTEGER li; li.QuadPart = static_cast<LONGLONG>(start);
                if (!SetFilePointerEx(hVol, li, nullptr, FILE_BEGIN))
                    return false;

                SIZE_T done = 0;
                while (done < need) {
                    DWORD step = static_cast<DWORD>(
                        (std::min<SIZE_T>)(need - done, 8ULL * 1024 * 1024));
                    DWORD got = 0;
                    if (!::ReadFile(hVol, scratch + done, step, &got, nullptr) ||
                        got != step)
                        return false;
                    done += step;
                }
                memcpy(dst, scratch + skip, len);
                return true;
            }
            catch (...) {
                return false;
            }
        }
    };

    struct MftMatch {
        ULONGLONG recordNum;
        ULONGLONG dataSize;
    };

    inline char AsciiLower(char c) noexcept
    {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    }

    inline char AsciiUpper(char c) noexcept
    {
        return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
    }

    bool ApplyFixup(BYTE* rec, DWORD recSize) noexcept
    {
        try {
            if (recSize < sizeof(NtfsRecHeaderCommon)) return false;
            auto* h = reinterpret_cast<NtfsRecHeaderCommon*>(rec);
            if (h->usaCount < 2) return false;
            if (static_cast<size_t>(h->usaOffset) + h->usaCount * 2 > recSize) return false;

            DWORD sectors = recSize / MFT_FIXUP_BLOCK;
            if (h->usaCount - 1u > sectors) return false;

            WORD* usa = reinterpret_cast<WORD*>(rec + h->usaOffset);
            WORD usn = usa[0];
            DWORD count = static_cast<DWORD>(h->usaCount) - 1u;

            for (DWORD s = 0; s < count; ++s) {
                DWORD off = (s + 1) * MFT_FIXUP_BLOCK - 2;
                if (off + 2 > recSize) return false;
                WORD* sectEnd = reinterpret_cast<WORD*>(rec + off);
                if (*sectEnd != usn) return false;
                *sectEnd = usa[s + 1];
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool AttrNameMatches(const BYTE* rec, DWORD off, const AttrHdr* a,
        const char* name) noexcept
    {
        try {
            if (!name) return true;
            size_t want = strlen(name);
            if (a->nameLen != want) return false;
            const BYTE* nameBytes = rec + off + a->nameOffset;
            for (size_t i = 0; i < want; ++i) {
                uint16_t w = 0;
                memcpy(&w, nameBytes + i * 2, 2);
                char wc = static_cast<char>(w & 0xFF);
                if ((w & 0xFF00) != 0) return false;
                if (AsciiLower(wc) != AsciiLower(name[i])) return false;
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }

    const AttrHdr* FindAttribute(const BYTE* rec, DWORD recSize,
        DWORD attrType, const char* name = nullptr) noexcept
    {
        try {
            auto* mft = reinterpret_cast<const MftRecord*>(rec);
            DWORD off = mft->attrOffset;

            while (off + sizeof(AttrHdr) <= recSize) {
                auto* a = reinterpret_cast<const AttrHdr*>(rec + off);
                if (a->type == ATTR_END) return nullptr;
                if (a->length == 0 || off + a->length > recSize) return nullptr;

                if (a->type == attrType && AttrNameMatches(rec, off, a, name))
                    return a;
                off += a->length;
            }
            return nullptr;
        }
        catch (...) {
            return nullptr;
        }
    }

    bool DecodeRuns(const BYTE* runs, DWORD maxLen, std::vector<NtfsRun>& out) noexcept
    {
        try {
            LONGLONG curLcn = 0;
            DWORD off = 0;

            while (off < maxLen) {
                BYTE hdr = runs[off++];
                if (hdr == 0) return true;

                DWORD lenSize = hdr & 0x0F;
                DWORD lcnSize = (hdr >> 4) & 0x0F;
                if (lenSize == 0 || lenSize > 8 || lcnSize > 8) return false;
                if (off + lenSize + lcnSize > maxLen) return false;

                ULONGLONG length = 0;
                for (DWORD i = 0; i < lenSize; ++i)
                    length |= (static_cast<ULONGLONG>(runs[off + i])) << (i * 8);
                off += lenSize;

                NtfsRun r{};
                r.length = length;

                if (lcnSize == 0) {
                    r.lcn = 0;
                }
                else {
                    LONGLONG lcnDelta = 0;
                    for (DWORD i = 0; i < lcnSize; ++i)
                        lcnDelta |= (static_cast<LONGLONG>(runs[off + i])) << (i * 8);
                    if (runs[off + lcnSize - 1] & 0x80) {
                        for (DWORD i = lcnSize; i < 8; ++i)
                            lcnDelta |= (static_cast<LONGLONG>(0xFF)) << (i * 8);
                    }
                    off += lcnSize;
                    curLcn += lcnDelta;
                    r.lcn = static_cast<ULONGLONG>(curLcn);
                }
                out.push_back(r);
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool ReadFromRuns(NtfsContext& ctx, const std::vector<NtfsRun>& runs,
        ULONGLONG validBytes, ULONGLONG totalBytes,
        std::vector<BYTE>& out) noexcept
    {
        try {
            out.assign(static_cast<size_t>(totalBytes), 0);
            ULONGLONG pos = 0;

            for (auto& r : runs) {
                if (pos >= totalBytes) break;
                ULONGLONG bytesInRun = r.length * ctx.bytesPerCluster;
                ULONGLONG remain = totalBytes - pos;
                ULONGLONG toRead = (std::min)(bytesInRun, remain);

                if (r.lcn != 0) {
                    ULONGLONG readNow = (pos + toRead <= validBytes) ? toRead
                        : (pos < validBytes ? validBytes - pos : 0);
                    if (readNow > 0) {
                        ULONGLONG diskOff = r.lcn * ctx.bytesPerCluster;
                        if (!ctx.ReadRange(diskOff, out.data() + pos,
                            static_cast<SIZE_T>(readNow)))
                            return false;
                    }
                }
                pos += toRead;
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool ReadMftRecord(NtfsContext& ctx, ULONGLONG recordNum,
        std::vector<BYTE>& outRec) noexcept
    {
        try {
            ULONGLONG byteOff = recordNum * ctx.bytesPerMftRec;
            ULONGLONG vcnInMft = byteOff / ctx.bytesPerCluster;
            ULONGLONG inClusterOff = byteOff % ctx.bytesPerCluster;

            ULONGLONG accumulated = 0;
            bool      mapped = false;
            ULONGLONG targetLcn = 0;
            for (auto& r : ctx.mftRuns) {
                if (vcnInMft >= accumulated && vcnInMft < accumulated + r.length) {
                    targetLcn = r.lcn + (vcnInMft - accumulated);
                    mapped = true;
                    break;
                }
                accumulated += r.length;
            }
            if (!mapped) return false;

            outRec.resize(ctx.bytesPerMftRec);
            ULONGLONG diskOff = targetLcn * ctx.bytesPerCluster + inClusterOff;
            if (!ctx.ReadRange(diskOff, outRec.data(), ctx.bytesPerMftRec))
                return false;

            if (memcmp(outRec.data(), xorstr_("FILE"), 4) != 0) return false;
            if (!ApplyFixup(outRec.data(), ctx.bytesPerMftRec)) return false;
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool MatchAsciiName(const BYTE* wideBytes, size_t nWchars,
        const std::string& target) noexcept
    {
        try {
            if (nWchars != target.size()) return false;
            for (size_t i = 0; i < nWchars; ++i) {
                uint16_t w = 0;
                memcpy(&w, wideBytes + i * 2, 2);
                if ((w & 0xFF00) != 0) return false;
                char wc = static_cast<char>(w & 0xFF);
                if (AsciiLower(wc) != AsciiLower(target[i])) return false;
            }
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool ScanIndexEntries(const BYTE* entries, const BYTE* end,
        const std::string& target, ULONGLONG& outRef) noexcept
    {
        try {
            while (entries + sizeof(IndexEntry) <= end) {
                auto* e = reinterpret_cast<const IndexEntry*>(entries);
                if (e->entrySize < sizeof(IndexEntry)) return false;
                if (entries + e->entrySize > end)      return false;

                if (!(e->flags & 2) && e->keyLen >= sizeof(FileNameAttr)) {
                    auto* fn = reinterpret_cast<const FileNameAttr*>(
                        entries + sizeof(IndexEntry));

                    if (fn->nameSpace != 2 && fn->nameLen == target.size()) {
                        const BYTE* nameBytes = reinterpret_cast<const BYTE*>(fn) +
                            sizeof(FileNameAttr);
                        if (MatchAsciiName(nameBytes, fn->nameLen, target)) {
                            outRef = static_cast<ULONGLONG>(e->fileRef) & FILEREF_MASK;
                            return true;
                        }
                    }
                }

                if (e->flags & 2) break;
                entries += e->entrySize;
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool LookupChild(NtfsContext& ctx, ULONGLONG dirRecord,
        const std::string& name, ULONGLONG& outRecord) noexcept
    {
        try {
            std::vector<BYTE> rec;
            if (!ReadMftRecord(ctx, dirRecord, rec)) return false;
            DWORD recSize = static_cast<DWORD>(rec.size());

            if (auto* a = FindAttribute(rec.data(), recSize,
                ATTR_INDEX_ROOT, xorstr_("$I30"))) {
                auto* ra = reinterpret_cast<const AttrResident*>(a);
                const BYTE* val = reinterpret_cast<const BYTE*>(a) + ra->valueOffset;
                DWORD valLen = ra->valueLen;
                if (valLen >= sizeof(IndexRootHeader) + sizeof(IndexNodeHeader)) {
                    auto* root = reinterpret_cast<const IndexRootHeader*>(val);
                    ctx.bytesPerIndex = root->bytesPerIndex
                        ? root->bytesPerIndex : 4096;

                    const BYTE* nodeStart = val + sizeof(IndexRootHeader);
                    auto* node = reinterpret_cast<const IndexNodeHeader*>(nodeStart);
                    const BYTE* entries = nodeStart + node->entriesOffset;
                    const BYTE* end = nodeStart + node->endUsedOffset;
                    if (entries >= val && end <= val + valLen &&
                        ScanIndexEntries(entries, end, name, outRecord))
                        return true;
                }
            }

            if (auto* a = FindAttribute(rec.data(), recSize,
                ATTR_INDEX_ALLOC, xorstr_("$I30"))) {
                if (!a->nonResident) return false;
                auto* nra = reinterpret_cast<const AttrNonResident*>(a);

                std::vector<NtfsRun> runs;
                const BYTE* runStart = reinterpret_cast<const BYTE*>(a) + nra->runlistOffset;
                DWORD runMax = a->length - nra->runlistOffset;
                if (!DecodeRuns(runStart, runMax, runs)) return false;

                std::vector<BYTE> data;
                if (!ReadFromRuns(ctx, runs,
                    static_cast<ULONGLONG>(nra->initSize),
                    static_cast<ULONGLONG>(nra->dataSize),
                    data))
                    return false;

                DWORD ib = ctx.bytesPerIndex ? ctx.bytesPerIndex : 4096;
                for (size_t off = 0; off + ib <= data.size(); off += ib) {
                    BYTE* blk = data.data() + off;
                    if (memcmp(blk, xorstr_("INDX"), 4) != 0) continue;
                    if (!ApplyFixup(blk, ib)) continue;

                    auto* ibHdr = reinterpret_cast<const IndexBlockHdr*>(blk);
                    const BYTE* nodeStart = reinterpret_cast<const BYTE*>(&ibHdr->node);
                    const BYTE* entries = nodeStart + ibHdr->node.entriesOffset;
                    const BYTE* end = nodeStart + ibHdr->node.endUsedOffset;
                    if (entries >= blk && end <= blk + ib &&
                        ScanIndexEntries(entries, end, name, outRecord))
                        return true;
                }
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool OpenVolume(char letter, NtfsContext& ctx) noexcept
    {
        try {
            char path[8] = { '\\', '\\', '.', '\\', letter, ':', 0, 0 };
            ctx.hVol = CreateFileA(path, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (ctx.hVol == INVALID_HANDLE_VALUE) return false;

            NTFS_VOLUME_DATA_BUFFER vdb{};
            DWORD got = 0;
            if (!DeviceIoControl(ctx.hVol, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0,
                &vdb, sizeof(vdb), &got, nullptr))
                return false;

            ctx.bytesPerSector = vdb.BytesPerSector;
            ctx.bytesPerCluster = vdb.BytesPerCluster;
            ctx.bytesPerMftRec = vdb.BytesPerFileRecordSegment;
            ctx.mftLcn = static_cast<ULONGLONG>(vdb.MftStartLcn.QuadPart);

            if (ctx.bytesPerSector == 0 || ctx.bytesPerCluster == 0 ||
                ctx.bytesPerMftRec == 0)
                return false;

            ULONGLONG mftByteOff = ctx.mftLcn * ctx.bytesPerCluster;
            std::vector<BYTE> rec0(ctx.bytesPerMftRec);
            if (!ctx.ReadRange(mftByteOff, rec0.data(), ctx.bytesPerMftRec))
                return false;
            if (memcmp(rec0.data(), xorstr_("FILE"), 4) != 0) return false;
            if (!ApplyFixup(rec0.data(), ctx.bytesPerMftRec)) return false;

            auto* dataAttr = FindAttribute(rec0.data(), ctx.bytesPerMftRec, ATTR_DATA);
            if (!dataAttr || !dataAttr->nonResident) return false;

            auto* nra = reinterpret_cast<const AttrNonResident*>(dataAttr);
            const BYTE* runStart = reinterpret_cast<const BYTE*>(dataAttr) + nra->runlistOffset;
            DWORD runMax = dataAttr->length - nra->runlistOffset;
            if (!DecodeRuns(runStart, runMax, ctx.mftRuns) || ctx.mftRuns.empty())
                return false;
            return true;
        }
        catch (...) {
            return false;
        }
    }

    ULONGLONG GetUnnamedDataSize(const BYTE* rec, DWORD recSize) noexcept
    {
        try {
            auto* mft = reinterpret_cast<const MftRecord*>(rec);
            DWORD off = mft->attrOffset;
            while (off + sizeof(AttrHdr) <= recSize) {
                auto* a = reinterpret_cast<const AttrHdr*>(rec + off);
                if (a->type == ATTR_END) break;
                if (a->length == 0 || off + a->length > recSize) break;
                if (a->type == ATTR_DATA && a->nameLen == 0) {
                    if (a->nonResident) {
                        auto* nra = reinterpret_cast<const AttrNonResident*>(a);
                        return static_cast<ULONGLONG>(nra->dataSize);
                    }
                    auto* ra = reinterpret_cast<const AttrResident*>(a);
                    return ra->valueLen;
                }
                off += a->length;
            }
            return 0;
        }
        catch (...) {
            return 0;
        }
    }

    bool RecordHasName(const BYTE* rec, DWORD recSize, const std::string& target) noexcept
    {
        try {
            auto* mft = reinterpret_cast<const MftRecord*>(rec);
            DWORD off = mft->attrOffset;
            while (off + sizeof(AttrHdr) <= recSize) {
                auto* a = reinterpret_cast<const AttrHdr*>(rec + off);
                if (a->type == ATTR_END) break;
                if (a->length == 0 || off + a->length > recSize) break;

                if (a->type == ATTR_FILE_NAME && !a->nonResident) {
                    auto* ra = reinterpret_cast<const AttrResident*>(a);
                    if (ra->valueLen >= sizeof(FileNameAttr)) {
                        auto* fn = reinterpret_cast<const FileNameAttr*>(
                            rec + off + ra->valueOffset);
                        if (fn->nameSpace != 2 && fn->nameLen == target.size()) {
                            const BYTE* nameBytes = reinterpret_cast<const BYTE*>(fn) +
                                sizeof(FileNameAttr);
                            if (MatchAsciiName(nameBytes, fn->nameLen, target))
                                return true;
                        }
                    }
                }
                off += a->length;
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    bool ScanMftForFile(NtfsContext& ctx, const std::string& target,
        std::vector<MftMatch>& matches) noexcept
    {
        try {
            matches.clear();
            if (ctx.mftRuns.empty() || ctx.bytesPerMftRec == 0) return false;

            constexpr SIZE_T kChunk = 8ULL * 1024 * 1024;
            std::vector<BYTE> chunk(kChunk);
            std::vector<BYTE> recScratch(ctx.bytesPerMftRec);

            ULONGLONG vcnAccumulated = 0;
            for (auto& run : ctx.mftRuns) {
                ULONGLONG runBytes = run.length * ctx.bytesPerCluster;
                ULONGLONG runDiskOff = run.lcn * ctx.bytesPerCluster;
                ULONGLONG firstRecInRun =
                    (vcnAccumulated * ctx.bytesPerCluster) / ctx.bytesPerMftRec;

                if (run.lcn == 0) {
                    vcnAccumulated += run.length;
                    continue;
                }

                ULONGLONG done = 0;
                while (done < runBytes) {
                    SIZE_T step = static_cast<SIZE_T>(
                        (std::min<ULONGLONG>)(kChunk, runBytes - done));
                    if (!ctx.ReadRange(runDiskOff + done, chunk.data(), step))
                        break;

                    for (SIZE_T r = 0; r + ctx.bytesPerMftRec <= step;
                        r += ctx.bytesPerMftRec) {
                        BYTE* recPtr = chunk.data() + r;
                        if (memcmp(recPtr, xorstr_("FILE"), 4) != 0) continue;

                        WORD flagsRaw = *reinterpret_cast<const WORD*>(recPtr + 22);
                        if (!(flagsRaw & MFT_FLAG_IN_USE)) continue;
                        if (flagsRaw & MFT_FLAG_DIRECTORY) continue;

                        memcpy(recScratch.data(), recPtr, ctx.bytesPerMftRec);
                        if (!ApplyFixup(recScratch.data(), ctx.bytesPerMftRec)) continue;

                        if (!RecordHasName(recScratch.data(),
                            ctx.bytesPerMftRec, target))
                            continue;

                        ULONGLONG dataSize = GetUnnamedDataSize(
                            recScratch.data(), ctx.bytesPerMftRec);
                        if (dataSize == 0) continue;

                        ULONGLONG recordNum = firstRecInRun +
                            (done + r) / ctx.bytesPerMftRec;
                        matches.push_back({ recordNum, dataSize });
                    }
                    done += step;
                }
                vcnAccumulated += run.length;
            }

            std::sort(matches.begin(), matches.end(),
                [](const MftMatch& a, const MftMatch& b) {
                    return a.dataSize > b.dataSize;
                });
            return !matches.empty();
        }
        catch (...) {
            return false;
        }
    }

    bool ReadFileData(NtfsContext& ctx, ULONGLONG fileRecord,
        std::vector<BYTE>& out) noexcept
    {
        try {
            std::vector<BYTE> rec;
            if (!ReadMftRecord(ctx, fileRecord, rec)) return false;

            auto* da = FindAttribute(rec.data(), static_cast<DWORD>(rec.size()),
                ATTR_DATA);
            if (!da) return false;

            if (!da->nonResident) {
                auto* ra = reinterpret_cast<const AttrResident*>(da);
                const BYTE* base = reinterpret_cast<const BYTE*>(da) + ra->valueOffset;
                out.assign(base, base + ra->valueLen);
                return true;
            }

            auto* nra = reinterpret_cast<const AttrNonResident*>(da);
            if (nra->dataSize <= 0) { out.clear(); return true; }

            std::vector<NtfsRun> runs;
            const BYTE* runStart = reinterpret_cast<const BYTE*>(da) + nra->runlistOffset;
            DWORD runMax = da->length - nra->runlistOffset;
            if (!DecodeRuns(runStart, runMax, runs)) return false;

            return ReadFromRuns(ctx, runs,
                static_cast<ULONGLONG>(nra->initSize),
                static_cast<ULONGLONG>(nra->dataSize),
                out);
        }
        catch (...) {
            return false;
        }
    }

    bool RawNtfsReadFile(char driveLetter, const std::string& path,
        std::vector<BYTE>& out) noexcept
    {
        try {
            NtfsContext ctx;
            if (!OpenVolume(driveLetter, ctx)) return false;

            std::vector<std::string> parts;
            std::string cur;
            for (char c : path) {
                if (c == '\\' || c == '/') {
                    if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
                }
                else {
                    cur += c;
                }
            }
            if (!cur.empty()) parts.push_back(cur);
            if (parts.empty()) return false;

            bool walked = true;
            ULONGLONG record = ROOT_DIR_RECORD;
            for (const auto& p : parts) {
                ULONGLONG next = 0;
                if (!LookupChild(ctx, record, p, next)) {
                    walked = false;
                    break;
                }
                record = next;
            }

            if (walked) return ReadFileData(ctx, record, out);

            std::vector<MftMatch> matches;
            if (!ScanMftForFile(ctx, parts.back(), matches)) return false;

            for (const auto& m : matches) {
                if (ReadFileData(ctx, m.recordNum, out)) return true;
            }
            return false;
        }
        catch (...) {
            return false;
        }
    }

    std::string DecodeName(const BYTE* p, size_t maxBytes,
        uint16_t nameLen, bool ascii) noexcept
    {
        try {
            if (nameLen == 0) return std::string();
            if (ascii) {
                size_t n = (std::min<size_t>)(static_cast<size_t>(nameLen), maxBytes);
                return std::string(reinterpret_cast<const char*>(p), n);
            }
            size_t bytes = (std::min<size_t>)(static_cast<size_t>(nameLen), maxBytes);
            bytes &= ~static_cast<size_t>(1);
            size_t chars = bytes / 2;
            std::string out(chars, '\0');
            for (size_t i = 0; i < chars; ++i) {
                uint16_t w = 0;
                memcpy(&w, p + i * 2, 2);
                out[i] = static_cast<char>(w & 0xFF);
            }
            while (!out.empty() && out.back() == '\0') out.pop_back();
            return out;
        }
        catch (...) {
            return std::string();
        }
    }

    bool ReadValueData(const VkInfo& vk, const BYTE* base, size_t fileSize,
        std::vector<BYTE>& out) noexcept
    {
        try {
            uint32_t sz = vk.dataSize;
            if (sz & 0x80000000u) {
                sz &= 0x7FFFFFFFu;
                out.resize((std::min<size_t>)(static_cast<size_t>(sz), size_t{ 4 }));
                if (!out.empty())
                    memcpy(out.data(), &vk.dataOffset, out.size());
                return true;
            }
            if (sz == 0) { out.clear(); return true; }
            if (sz > 16344u) return false;

            size_t cellOff = static_cast<size_t>(vk.dataOffset) + DATA_AREA;
            if (cellOff + 4 > fileSize) return false;
            int32_t cellSize = 0;
            memcpy(&cellSize, base + cellOff, 4);
            uint32_t absSize = cellSize < 0
                ? static_cast<uint32_t>(-cellSize)
                : static_cast<uint32_t>(cellSize);
            if (absSize <= 4) return false;
            if (cellOff + 4 + sz > fileSize) return false;
            if (sz > absSize - 4u)            return false;

            out.assign(base + cellOff + 4, base + cellOff + 4 + sz);
            return true;
        }
        catch (...) {
            return false;
        }
    }

    std::string AsString(const std::vector<BYTE>& bytes) noexcept
    {
        try {
            if (bytes.size() < 2) return std::string();
            size_t chars = bytes.size() / 2;
            std::string out;
            out.reserve(chars);
            for (size_t i = 0; i < chars; ++i) {
                uint16_t w = static_cast<uint16_t>(bytes[i * 2]) |
                             (static_cast<uint16_t>(bytes[i * 2 + 1]) << 8);
                if (w == 0) break;
                out += static_cast<char>(w & 0xFF);
            }
            return out;
        }
        catch (...) {
            return std::string();
        }
    }

    ULONGLONG AsQword(const std::vector<BYTE>& bytes) noexcept
    {
        try {
            ULONGLONG v = 0;
            size_t n = (std::min<size_t>)(bytes.size(), sizeof(v));
            if (n > 0) memcpy(&v, bytes.data(), n);
            return v;
        }
        catch (...) {
            return 0;
        }
    }

    std::string StripFileId(const std::string& fileId) noexcept
    {
        try {
            if (fileId.size() <= 4) return fileId;
            if (fileId.compare(0, 4, xorstr_("0000")) != 0) return fileId;
            std::string out = fileId.substr(4);
            for (auto& c : out) c = AsciiUpper(c);
            return out;
        }
        catch (...) {
            return std::string();
        }
    }

    bool ParseAmcacheHive(const std::vector<BYTE>& bytes,
        std::vector<AmcacheEntry>& out) noexcept
    {
        try {
            if (bytes.size() < DATA_AREA) return false;
            if (memcmp(bytes.data(), xorstr_("regf"), 4) != 0) return false;

            const BYTE* base = bytes.data();
            size_t      fsize = bytes.size();
            uint32_t    rootRaw = r32(base + 0x24);

            std::vector<NkInfo> nks;
            std::vector<VkInfo> vks;
            nks.reserve(8192);
            vks.reserve(32768);

            size_t pos = DATA_AREA;
            while (pos + 32 <= fsize) {
                if (memcmp(base + pos, xorstr_("hbin"), 4) != 0) break;
                uint32_t hbinSize = r32(base + pos + 8);
                if (hbinSize < 32 || pos + hbinSize > fsize) break;

                size_t cellPos = pos + 32;
                size_t hbinEnd = pos + hbinSize;

                while (cellPos + 4 < hbinEnd) {
                    int32_t cellSize = 0;
                    memcpy(&cellSize, base + cellPos, 4);
                    bool allocated = cellSize < 0;
                    uint32_t absSize = allocated
                        ? static_cast<uint32_t>(-cellSize)
                        : static_cast<uint32_t>(cellSize);
                    if (absSize <= 4 || cellPos + absSize > hbinEnd) {
                        cellPos += 4;
                        continue;
                    }

                    const BYTE* payload = base + cellPos + 4;
                    size_t payloadSize = static_cast<size_t>(absSize) - 4;

                    if (payloadSize >= 2) {
                        if (memcmp(payload, xorstr_("nk"), 2) == 0 &&
                            payloadSize >= 0x4C) {
                            NkInfo nk{};
                            nk.cellOff = cellPos;
                            nk.allocated = allocated;
                            nk.parentRaw = r32(payload + 0x10);
                            nk.valueCount = r32(payload + 0x24);
                            nk.valueListRaw = r32(payload + 0x28);
                            nk.timestamp = r64(payload + 0x04);
                            nk.parentIdx = -1;

                            uint16_t flags = r16(payload + 0x02);
                            uint16_t nameLen = r16(payload + 0x48);
                            if (0x4Cu + nameLen <= payloadSize) {
                                nk.name = DecodeName(payload + 0x4C,
                                    payloadSize - 0x4C, nameLen,
                                    (flags & 0x0020) != 0);
                            }
                            nks.push_back(std::move(nk));
                        }
                        else if (memcmp(payload, xorstr_("vk"), 2) == 0 &&
                            payloadSize >= 0x14) {
                            VkInfo vk{};
                            vk.cellOff = cellPos;
                            vk.dataSize = r32(payload + 0x04);
                            vk.dataOffset = r32(payload + 0x08);
                            vk.dataType = r32(payload + 0x0C);

                            uint16_t nameLen = r16(payload + 0x02);
                            uint16_t flags = r16(payload + 0x10);
                            if (0x14u + nameLen <= payloadSize) {
                                vk.name = DecodeName(payload + 0x14,
                                    payloadSize - 0x14, nameLen,
                                    (flags & 0x0001) != 0);
                            }
                            vks.push_back(std::move(vk));
                        }
                    }

                    cellPos += absSize;
                }
                pos = hbinEnd;
            }

            if (nks.empty()) return false;

            std::unordered_map<size_t, int> nkOffToIdx;
            nkOffToIdx.reserve(nks.size() * 2);
            for (int i = 0; i < static_cast<int>(nks.size()); ++i)
                nkOffToIdx[nks[i].cellOff] = i;

            std::unordered_map<size_t, int> vkOffToIdx;
            vkOffToIdx.reserve(vks.size() * 2);
            for (int i = 0; i < static_cast<int>(vks.size()); ++i)
                vkOffToIdx[vks[i].cellOff] = i;

            for (auto& nk : nks) {
                size_t parOff = static_cast<size_t>(nk.parentRaw) + DATA_AREA;
                auto it = nkOffToIdx.find(parOff);
                if (it != nkOffToIdx.end()) nk.parentIdx = it->second;
            }

            std::vector<std::vector<int>> children(nks.size());
            for (int i = 0; i < static_cast<int>(nks.size()); ++i) {
                if (nks[i].parentIdx >= 0)
                    children[nks[i].parentIdx].push_back(i);
            }

            int rootIdx = -1;
            {
                size_t rootCellOff = static_cast<size_t>(rootRaw) + DATA_AREA;
                auto it = nkOffToIdx.find(rootCellOff);
                if (it != nkOffToIdx.end()) rootIdx = it->second;
            }
            if (rootIdx < 0) return false;

            auto findChild = [&](int parent, const char* name) -> int {
                if (parent < 0 || parent >= static_cast<int>(children.size()))
                    return -1;
                for (int c : children[parent]) {
                    if (_stricmp(nks[c].name.c_str(), name) == 0)
                        return c;
                }
                return -1;
                };

            int rootKey = findChild(rootIdx, xorstr_("Root"));
            if (rootKey < 0) rootKey = rootIdx;

            int invKey = findChild(rootKey, xorstr_("InventoryApplicationFile"));
            if (invKey < 0)
                invKey = findChild(rootIdx, xorstr_("InventoryApplicationFile"));

            out.clear();
            if (invKey >= 0)
                out.reserve(children[invKey].size());

            auto valuesOf = [&](int nkIdx,
                std::unordered_map<std::string, int>& byName)
                {
                    const auto& nk = nks[nkIdx];
                    byName.clear();
                    if (nk.valueCount == 0 || nk.valueCount > 4096 ||
                        nk.valueListRaw == INVALID_OFF) return;

                    size_t cellOff = static_cast<size_t>(nk.valueListRaw) + DATA_AREA;
                    if (cellOff + 4 + nk.valueCount * 4u > fsize) return;

                    const BYTE* listPtr = base + cellOff + 4;
                    for (uint32_t i = 0; i < nk.valueCount; ++i) {
                        uint32_t vkRel = r32(listPtr + i * 4);
                        if (vkRel == INVALID_OFF) continue;
                        size_t vkOff = static_cast<size_t>(vkRel) + DATA_AREA;
                        auto it = vkOffToIdx.find(vkOff);
                        if (it == vkOffToIdx.end()) continue;

                        const auto& vk = vks[it->second];
                        std::string lname = vk.name;
                        for (auto& c : lname) c = AsciiLower(c);
                        byName[lname] = it->second;
                    }
                };

            auto getString = [&](const std::unordered_map<std::string, int>& byName,
                const char* name, std::string& out_)
                {
                    std::string key = name;
                    for (auto& c : key) c = AsciiLower(c);
                    auto it = byName.find(key);
                    if (it == byName.end()) return;
                    std::vector<BYTE> data;
                    if (!ReadValueData(vks[it->second], base, fsize, data)) return;
                    out_ = AsString(data);
                };

            auto getQword = [&](const std::unordered_map<std::string, int>& byName,
                const char* name, ULONGLONG& out_)
                {
                    std::string key = name;
                    for (auto& c : key) c = AsciiLower(c);
                    auto it = byName.find(key);
                    if (it == byName.end()) return;
                    std::vector<BYTE> data;
                    if (!ReadValueData(vks[it->second], base, fsize, data)) return;
                    out_ = AsQword(data);
                };

            static const std::vector<int> kNoChildren;
            const std::vector<int>& fileChildren =
                (invKey >= 0) ? children[invKey] : kNoChildren;

            std::unordered_map<std::string, int> byName;
            for (int childIdx : fileChildren) {
                const auto& nk = nks[childIdx];
                if (!nk.allocated) continue;

                AmcacheEntry e;

                valuesOf(childIdx, byName);

                std::string fileId;
                getString(byName, xorstr_("FileId"), fileId);
                getString(byName, xorstr_("LowerCaseLongPath"), e.path);
                getQword(byName, xorstr_("Size"), e.sizeBytes);

                if (e.path.empty()) {
                    size_t bar = nk.name.find('|');
                    std::string keyName = (bar != std::string::npos)
                        ? nk.name.substr(0, bar)
                        : nk.name;
                    e.path = keyName.empty() ? nk.name : keyName;
                    e.pathIsKeyName = true;
                }

                e.sha1 = StripFileId(fileId);
                e.timestamp = FormatKeyWriteTime(nk.timestamp);

                out.push_back(std::move(e));
            }

            int drvKey = findChild(rootKey, xorstr_("InventoryDriverBinary"));
            if (drvKey < 0)
                drvKey = findChild(rootIdx, xorstr_("InventoryDriverBinary"));

            if (drvKey >= 0) {
                out.reserve(out.size() + children[drvKey].size());
                for (int childIdx : children[drvKey]) {
                    const auto& nk = nks[childIdx];
                    if (!nk.allocated) continue;

                    AmcacheEntry e;

                    valuesOf(childIdx, byName);

                    std::string driverId, driverName;
                    getString(byName, xorstr_("DriverId"), driverId);
                    getString(byName, xorstr_("DriverName"), driverName);
                    if (driverId.empty())
                        getString(byName, xorstr_("Hash"), driverId);

                    bool keyLooksLikePath =
                        nk.name.find('\\') != std::string::npos ||
                        nk.name.find('/')  != std::string::npos ||
                        nk.name.find('.')  != std::string::npos;
                    e.path = keyLooksLikePath
                        ? nk.name
                        : (!driverName.empty() ? driverName : nk.name);
                    e.pathIsKeyName = !keyLooksLikePath;

                    for (auto& c : e.path) if (c == '/') c = '\\';

                    e.sha1 = StripFileId(driverId);
                    e.timestamp = FormatKeyWriteTime(nk.timestamp);

                    out.push_back(std::move(e));
                }
            }

            return true;
        }
        catch (...) {
            return false;
        }
    }

    void TriggerCompatibilityAppraiser() noexcept
    {
        try {
            std::string cmd = xorstr_("schtasks /Run /TN \"\\Microsoft\\Windows\\"
                "Application Experience\\Microsoft Compatibility Appraiser\"");

            STARTUPINFOA si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            PROCESS_INFORMATION pi{};
            if (CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 30000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        catch (...) {}
    }

    char GetWindowsDrive() noexcept
    {
        try {
            char winDir[MAX_PATH]{};
            UINT n = GetWindowsDirectoryA(winDir, MAX_PATH);
            return (n >= 1) ? winDir[0] : 'C';
        }
        catch (...) {
            return 'C';
        }
    }

    bool AcquireHiveBytes(std::vector<BYTE>& bytes) noexcept
    {
        try {
            std::string kHive = xorstr_("\\Windows\\AppCompat\\Programs\\Amcache.hve");
            return RawNtfsReadFile(GetWindowsDrive(), kHive, bytes);
        }
        catch (...) {
            bytes.clear();
            return false;
        }
    }

    bool ParseAmcacheEntries(std::vector<AmcacheEntry>& entries) noexcept
    {
        try {
            entries.clear();

            TriggerCompatibilityAppraiser();

            std::vector<BYTE> hiveBytes;
            if (!AcquireHiveBytes(hiveBytes)) return false;
            if (!ParseAmcacheHive(hiveBytes, entries)) return false;
            return true;
        }
        catch (...) {
            return false;
        }
    }

    bool LooksLikeFilePath(const std::string& p) noexcept
    {
        try {
            if (p.size() < 3) return false;
            bool hasSep = false;
            for (char c : p) {
                if (c == '\\' || c == '/') { hasSep = true; break; }
            }
            if (!hasSep) return false;

            size_t dot = p.find_last_of('.');
            size_t sep = p.find_last_of(xorstr_("\\/"));
            if (dot == std::string::npos) return false;
            if (sep != std::string::npos && dot < sep) return false;
            size_t extLen = p.size() - dot - 1;
            if (extLen == 0 || extLen > 8) return false;
            for (size_t i = dot + 1; i < p.size(); ++i) {
                char c = p[i];
                bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                          (c >= '0' && c <= '9');
                if (!ok) return false;
            }
            return true;
        }
        catch (...) { return false; }
    }

    std::string ToUpper(std::string s) noexcept
    {
        try {
            for (auto& c : s) c = AsciiUpper(c);
            return s;
        }
        catch (...) {
            return std::string();
        }
    }

    const std::unordered_map<std::string, std::string>& NormalisedFilters() noexcept
    {
        static const std::unordered_map<std::string, std::string> map = [] {
            std::unordered_map<std::string, std::string> m;
            try {
                const auto& src = Filters::Sha1Filters();
                m.reserve(src.size() * 2);
                for (const auto& kv : src)
                    m.emplace(ToUpper(kv.first), kv.second);
            }
            catch (...) {}
            return m;
            }();
        return map;
    }

    bool IsRunningElevated() noexcept
    {
        try {
            BOOL elevated = FALSE;
            HANDLE token = nullptr;
            if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
                TOKEN_ELEVATION e{};
                DWORD ret = 0;
                if (GetTokenInformation(token, TokenElevation, &e, sizeof(e), &ret))
                    elevated = e.TokenIsElevated;
                CloseHandle(token);
            }
            return elevated == TRUE;
        }
        catch (...) {
            return false;
        }
    }

    bool FileExistsOnDisk(const std::string& path) noexcept
    {
        try {
            if (path.size() < 3) return false;
            const bool drivePath = path[1] == ':' &&
                                   (path[2] == '\\' || path[2] == '/');
            const bool uncPath   = path[0] == '\\' && path[1] == '\\';
            if (!drivePath && !uncPath) return false;
            DWORD attr = GetFileAttributesA(path.c_str());
            return attr != INVALID_FILE_ATTRIBUTES;
        }
        catch (...) {
            return false;
        }
    }

    std::string FetchLOLDriversJson() noexcept
    {
        try {
            std::string result;

            HINTERNET hSession = WinHttpOpen(xorstr_(L"AMC/1.0"),
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
            if (!hRequest) {
                WinHttpCloseHandle(hConnect);
                WinHttpCloseHandle(hSession);
                return result;
            }

            constexpr size_t kMaxBody = 64ULL << 20;
            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                    WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                WinHttpReceiveResponse(hRequest, NULL)) {
                result.reserve(16ULL << 20);
                DWORD bytesAvailable = 0;
                while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
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

    const std::unordered_set<std::string>& GetLOLDriversHashes() noexcept
    {
        static std::once_flag onceFlag;
        static std::unordered_set<std::string> hashes;
        std::call_once(onceFlag, [] {
            try {
                const std::string json = FetchLOLDriversJson();
                if (json.empty()) return;

                const std::string needle = xorstr_("\"SHA1\"");
                size_t pos = 0;
                while ((pos = json.find(needle, pos)) != std::string::npos) {
                    pos += needle.size();
                    const size_t q1 = json.find('"', pos);
                    if (q1 == std::string::npos) break;
                    const size_t q2 = json.find('"', q1 + 1);
                    if (q2 == std::string::npos) break;

                    if (q2 - q1 - 1 == 40) {
                        std::string h = json.substr(q1 + 1, 40);
                        bool allHex = true;
                        for (char& c : h) {
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

}



bool AmcacheFilters::GetAmcacheEntries(std::vector<AmcacheEntry>& out) noexcept
{
    try {
        out.clear();
        if (!IsRunningElevated()) return false;
        return ParseAmcacheEntries(out);
    }
    catch (...) {
        return false;
    }
}

void AmcacheFilters::start_amcache_scan() noexcept
{
    try {
        std::vector<AmcacheEntry> entries;
        if (!GetAmcacheEntries(entries)) return;

        size_t entriesWithRealPath = 0;
        for (const auto& e : entries) {
            if (LooksLikeFilePath(e.path)) {
                ++entriesWithRealPath;
                if (entriesWithRealPath >= 3) break;
            }
        }
        if (entriesWithRealPath == 0) {
            if (FreshInstall::WithinGrace()) return;
            LOG(DETECTION, xorstr_("N/A")) << xorstr_("Amcache Cleaned");
            return;
        }

        const auto& filters   = NormalisedFilters();
        const auto& lolHashes  = GetLOLDriversHashes();

        for (const auto& e : entries) {
            if (e.sha1.empty()) continue;

            std::string sha1_lower = e.sha1;
            for (auto& c : sha1_lower) {
                if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + 32);
            }

            const bool onDisk = !e.pathIsKeyName && FileExistsOnDisk(e.path);

            if (!lolHashes.empty() &&
                lolHashes.find(sha1_lower) != lolHashes.end()) {
                LOG(WARNING, e.timestamp)
                    << (onDisk
                        ? xorstr_("Vulnerable Driver Found On Disk:")
                        : xorstr_("Vulnerable Driver Found Off Disk:"))
                    << e.path
                    << xorstr_(" | SHA1=")
                    << sha1_lower;
            }

            auto it = filters.find(e.sha1);
            if (it == filters.end()) continue;

            LOG(DETECTION, e.timestamp)
                << it->second
                << (onDisk
                    ? xorstr_(" Found On PC:")
                    : xorstr_(" Not Found On PC:"))
                << e.path
                << xorstr_(" | SHA1=")
                << sha1_lower;
        }
    }
    catch (...) {}
}