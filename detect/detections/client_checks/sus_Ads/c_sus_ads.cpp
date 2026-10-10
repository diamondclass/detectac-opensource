#include "c_sus_ads.h"

namespace {

#pragma pack(push, 1)

    struct NtfsBootSector {
        uint8_t  Jump[3];
        char     Oem[8];
        uint16_t BytesPerSector;
        uint8_t  SectorsPerCluster;
        uint16_t ReservedSectors;
        uint8_t  Unused1[3];
        uint16_t Unused2;
        uint8_t  MediaDescriptor;
        uint16_t Unused3;
        uint16_t SectorsPerTrack;
        uint16_t NumberOfHeads;
        uint32_t HiddenSectors;
        uint32_t Unused4;
        uint32_t Unused5;
        uint64_t TotalSectors;
        uint64_t MftLcn;
        uint64_t MftMirrLcn;
        int8_t   ClustersPerMftRecord;
        uint8_t  Unused6[3];
        int8_t   ClustersPerIndexRecord;
        uint8_t  Unused7[3];
        uint64_t VolumeSerial;
        uint32_t Checksum;
        uint8_t  Bootstrap[426];
        uint16_t Signature;
    };
    static_assert(sizeof(NtfsBootSector) == 512);

    struct FileRecordHeader {
        char     Signature[4];
        uint16_t UpdateSequenceOffset;
        uint16_t UpdateSequenceSize;
        uint64_t LogFileSequenceNumber;
        uint16_t SequenceNumber;
        uint16_t HardLinkCount;
        uint16_t FirstAttributeOffset;
        uint16_t Flags;
        uint32_t BytesInUse;
        uint32_t BytesAllocated;
        uint64_t BaseFileRecord;
        uint16_t NextAttributeId;
        uint16_t Alignment;
        uint32_t MftRecordNumber;
    };

    struct AttributeHeader {
        uint32_t Type;
        uint32_t Length;
        uint8_t  NonResident;
        uint8_t  NameLength;
        uint16_t NameOffset;
        uint16_t Flags;
        uint16_t AttributeId;
    };

    struct ResidentAttribute {
        AttributeHeader Header;
        uint32_t ValueLength;
        uint16_t ValueOffset;
        uint8_t  IndexedFlag;
        uint8_t  Padding;
    };

    struct NonResidentAttribute {
        AttributeHeader Header;
        uint64_t StartVcn;
        uint64_t LastVcn;
        uint16_t DataRunsOffset;
        uint16_t CompressionUnit;
        uint32_t Padding;
        int64_t  AllocatedSize;
        int64_t  RealSize;
        int64_t  InitializedSize;
    };

    struct StandardInformation {
        uint64_t CreationTime;
        uint64_t LastModifiedTime;
        uint64_t LastChangedTime;
        uint64_t LastAccessTime;
        uint32_t FileAttributes;
        uint32_t MaxVersions;
        uint32_t VersionNumber;
        uint32_t ClassId;
        uint32_t OwnerId;
        uint32_t SecurityId;
        uint64_t QuotaCharged;
        uint64_t Usn;
    };

    struct FileNameAttribute {
        uint64_t ParentDirectory;
        uint64_t CreationTime;
        uint64_t LastModifiedTime;
        uint64_t LastChangedTime;
        uint64_t LastAccessTime;
        uint64_t AllocatedSize;
        uint64_t RealSize;
        uint32_t Flags;
        uint32_t ReparseValue;
        uint8_t  NameLength;
        uint8_t  Namespace;
        wchar_t  Name[1];
    };

#pragma pack(pop)

    constexpr uint16_t kFileRecordFlagInUse = 0x0001;
    constexpr uint32_t kAttrStandardInformation = 0x10;
    constexpr uint32_t kAttrFileName = 0x30;
    constexpr uint32_t kAttrData = 0x80;
    constexpr uint32_t kAttrEnd = 0xFFFFFFFF;
    constexpr uint8_t  kNamespacePosix = 0;
    constexpr uint8_t  kNamespaceWin32 = 1;
    constexpr uint8_t  kNamespaceDos = 2;
    constexpr uint8_t  kNamespaceWin32Dos = 3;
    constexpr uint32_t kFileMagic = 0x454C4946u;
    constexpr uint64_t kNtfsOem = 0x202020205346544Eull;

    struct DataStream {
        std::wstring Name;
        uint64_t     LogicalSize = 0;
        uint64_t     PhysicalSize = 0;
        uint16_t     AttrFlags = 0;
        bool         NonResident = false;
        bool         LooksLikePe = false;
    };

    struct ParsedRecord {
        uint32_t RecordNumber = 0;
        uint16_t SequenceNumber = 0;
        uint16_t Flags = 0;
        wchar_t  Drive = 0;
        bool     ParseFailed = false;
        bool     HasStdInfo = false;
        bool     HasFileName = false;
        uint32_t FileAttributes = 0;
        uint64_t CreationTime = 0;
        uint64_t ModifiedTime = 0;
        uint64_t AccessedTime = 0;
        uint64_t MftChangedTime = 0;
        uint64_t LogicalSize = 0;
        uint64_t PhysicalSize = 0;
        uint32_t ParentRecord = 0;
        uint16_t ParentSequence = 0;
        std::wstring Name;
        uint8_t  NameNamespace = 0xFF;
        uint32_t BaseRecord = 0;
        std::vector<DataStream> Streams;
    };

    struct LoadResult {
        bool                  Ok = false;
        std::vector<uint8_t>  MftBytes;
        uint32_t              RecordSize = 1024;
        uint32_t              ClusterSize = 4096;
        uint16_t              BytesPerSector = 512;
        wchar_t               Drive = 0;
    };

    struct Extent {
        uint64_t DiskOffset = 0;
        uint64_t LengthInBytes = 0;
        bool     Sparse = false;
    };

    struct MftDataAttr {
        std::vector<Extent> Extents;
        uint64_t            RealSize = 0;
        uint64_t            AllocatedSize = 0;
        uint64_t            InitializedSize = 0;
    };

    struct HandleOwner {
        HANDLE h = INVALID_HANDLE_VALUE;
        HandleOwner() = default;
        explicit HandleOwner(HANDLE handle) : h(handle) {}
        ~HandleOwner() { try { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); } catch (...) {} }
        HandleOwner(const HandleOwner&) = delete;
        HandleOwner& operator=(const HandleOwner&) = delete;
        HandleOwner(HandleOwner&& o) noexcept : h(o.h) { o.h = INVALID_HANDLE_VALUE; }
        HandleOwner& operator=(HandleOwner&& o) noexcept {
            if (this != &o) {
                try { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
                catch (...) {}
                h = o.h;
                o.h = INVALID_HANDLE_VALUE;
            }
            return *this;
        }
        bool valid() const noexcept { return h != INVALID_HANDLE_VALUE; }
    };

    template <typename T>
    T ReadLe(const uint8_t* p) noexcept {
        try {
            T value{};
            std::memcpy(&value, p, sizeof(T));
            return value;
        }
        catch (...) { return T{}; }
    }

    bool LooksLikePeBytes(const uint8_t* p, size_t n) noexcept {
        try {
            if (!p || n < 0x40) return false;
            if (p[0] != 'M' || p[1] != 'Z') return false;
            uint32_t e_lfanew = 0;
            std::memcpy(&e_lfanew, p + 0x3C, sizeof(e_lfanew));
            if (e_lfanew < 0x40)  return false;
            if (e_lfanew + 4 > n) return false;
            const uint8_t* sig = p + e_lfanew;
            return sig[0] == 'P' && sig[1] == 'E' && sig[2] == 0 && sig[3] == 0;
        }
        catch (...) { return false; }
    }

    int NamespaceScore(uint8_t ns) noexcept {
        try {
            switch (ns) {
            case kNamespaceWin32Dos: return 4;
            case kNamespaceWin32:    return 3;
            case kNamespacePosix:    return 2;
            case kNamespaceDos:      return 1;
            default:                 return 0;
            }
        }
        catch (...) { return 0; }
    }

    bool IsInUse(const ParsedRecord& r) noexcept {
        try { return (r.Flags & kFileRecordFlagInUse) != 0; }
        catch (...) { return false; }
    }

    bool ApplyUsaFixup(std::span<uint8_t> recordBytes, uint16_t bytesPerSector) noexcept {
        try {
            if (recordBytes.size() < sizeof(FileRecordHeader)) return false;
            auto* header = reinterpret_cast<FileRecordHeader*>(recordBytes.data());
            uint32_t magic = 0;
            std::memcpy(&magic, header->Signature, sizeof(magic));
            if (magic != kFileMagic) return false;

            const uint16_t usaOffset = header->UpdateSequenceOffset;
            const uint16_t usaSize = header->UpdateSequenceSize;
            if (usaSize < 2 || usaOffset + usaSize * 2u > recordBytes.size()) return false;
            if (bytesPerSector == 0) return false;

            const uint16_t usaNumber = ReadLe<uint16_t>(recordBytes.data() + usaOffset);
            const uint16_t sectorCount = static_cast<uint16_t>(usaSize - 1);
            if (sectorCount * static_cast<size_t>(bytesPerSector) > recordBytes.size()) return false;

            for (uint16_t i = 0; i < sectorCount; ++i) {
                const size_t   lastWordOffset = (i + 1) * bytesPerSector - 2;
                const uint16_t observed = ReadLe<uint16_t>(recordBytes.data() + lastWordOffset);
                if (observed != usaNumber) return false;
                const uint16_t replacement = ReadLe<uint16_t>(
                    recordBytes.data() + usaOffset + (i + 1) * 2);
                std::memcpy(recordBytes.data() + lastWordOffset, &replacement, 2);
            }
            return true;
        }
        catch (...) { return false; }
    }

    ParsedRecord ParseRecord(std::span<uint8_t> recordBytes) {
        try {
            ParsedRecord out;
            if (recordBytes.size() < sizeof(FileRecordHeader)) {
                out.ParseFailed = true;
                return out;
            }
            const auto* header = reinterpret_cast<const FileRecordHeader*>(recordBytes.data());
            uint32_t magic = 0;
            std::memcpy(&magic, header->Signature, sizeof(magic));
            if (magic != kFileMagic) {
                out.ParseFailed = true;
                return out;
            }

            out.RecordNumber = header->MftRecordNumber;
            out.SequenceNumber = header->SequenceNumber;
            out.Flags = header->Flags;
            out.BaseRecord = static_cast<uint32_t>(
                header->BaseFileRecord & 0x0000FFFFFFFFFFFFULL);

            size_t offset = header->FirstAttributeOffset;
            if (offset + 8 > recordBytes.size()) {
                out.ParseFailed = true;
                return out;
            }

            int  bestFileNameScore = -1;
            bool dataAttrSeen = false;

            while (offset + 8 <= recordBytes.size()) {
                const uint32_t type = ReadLe<uint32_t>(recordBytes.data() + offset);
                if (type == kAttrEnd) break;

                const uint32_t length = ReadLe<uint32_t>(recordBytes.data() + offset + 4);
                if (length < 16 || offset + length > recordBytes.size()) {
                    out.ParseFailed = true;
                    break;
                }

                const auto* attrHdr = reinterpret_cast<const AttributeHeader*>(
                    recordBytes.data() + offset);

                if (attrHdr->NonResident == 0) {
                    if (offset + sizeof(ResidentAttribute) > recordBytes.size()) {
                        out.ParseFailed = true;
                        break;
                    }
                    const auto* resHdr = reinterpret_cast<const ResidentAttribute*>(
                        recordBytes.data() + offset);
                    const size_t valueOff = offset + resHdr->ValueOffset;
                    const size_t valueLen = resHdr->ValueLength;
                    if (valueOff + valueLen > recordBytes.size()) {
                        out.ParseFailed = true;
                        break;
                    }
                    const uint8_t* value = recordBytes.data() + valueOff;

                    switch (type) {
                    case kAttrStandardInformation:
                        if (valueLen >= 48) {
                            const auto* si = reinterpret_cast<const StandardInformation*>(value);
                            out.HasStdInfo = true;
                            out.CreationTime = si->CreationTime;
                            out.ModifiedTime = si->LastModifiedTime;
                            out.MftChangedTime = si->LastChangedTime;
                            out.AccessedTime = si->LastAccessTime;
                            out.FileAttributes = si->FileAttributes;
                        }
                        break;

                    case kAttrFileName: {
                        if (valueLen < sizeof(FileNameAttribute) - sizeof(wchar_t)) break;
                        const auto* fn = reinterpret_cast<const FileNameAttribute*>(value);
                        const size_t nameBytes =
                            static_cast<size_t>(fn->NameLength) * sizeof(wchar_t);
                        if (offsetof(FileNameAttribute, Name) + nameBytes > valueLen) break;

                        const int score = NamespaceScore(fn->Namespace);
                        if (score > bestFileNameScore) {
                            bestFileNameScore = score;
                            out.HasFileName = true;
                            out.NameNamespace = fn->Namespace;
                            out.ParentRecord = static_cast<uint32_t>(
                                fn->ParentDirectory & 0x0000FFFFFFFFFFFFULL);
                            out.ParentSequence = static_cast<uint16_t>(
                                (fn->ParentDirectory >> 48) & 0xFFFF);
                            out.Name.assign(fn->Name, fn->NameLength);

                            if (!dataAttrSeen) {
                                out.LogicalSize = fn->RealSize;
                                out.PhysicalSize = fn->AllocatedSize;
                            }
                        }
                        break;
                    }

                    case kAttrData: {
                        DataStream stream;
                        stream.NonResident = false;
                        stream.AttrFlags = attrHdr->Flags;
                        if (attrHdr->NameLength > 0) {
                            const size_t nameOff = offset + attrHdr->NameOffset;
                            const size_t nameBytes =
                                static_cast<size_t>(attrHdr->NameLength) * sizeof(wchar_t);
                            if (nameOff + nameBytes <= recordBytes.size()) {
                                stream.Name.assign(
                                    reinterpret_cast<const wchar_t*>(
                                        recordBytes.data() + nameOff),
                                    attrHdr->NameLength);
                            }
                        }
                        stream.LogicalSize = valueLen;
                        stream.PhysicalSize = valueLen;
                        if (!stream.Name.empty() && valueLen >= 0x40) {
                            stream.LooksLikePe = LooksLikePeBytes(value, valueLen);
                        }
                        out.Streams.push_back(std::move(stream));

                        if (attrHdr->NameLength == 0) {
                            dataAttrSeen = true;
                            out.LogicalSize = valueLen;
                            out.PhysicalSize = valueLen;
                        }
                        break;
                    }
                    }
                }
                else {
                    if (offset + sizeof(NonResidentAttribute) > recordBytes.size()) {
                        out.ParseFailed = true;
                        break;
                    }
                    const auto* nrHdr = reinterpret_cast<const NonResidentAttribute*>(
                        recordBytes.data() + offset);

                    if (type == kAttrData) {
                        DataStream stream;
                        stream.NonResident = true;
                        stream.AttrFlags = attrHdr->Flags;
                        stream.LogicalSize = static_cast<uint64_t>(nrHdr->RealSize);
                        stream.PhysicalSize = static_cast<uint64_t>(nrHdr->AllocatedSize);
                        if (attrHdr->NameLength > 0) {
                            const size_t nameOff = offset + attrHdr->NameOffset;
                            const size_t nameBytes =
                                static_cast<size_t>(attrHdr->NameLength) * sizeof(wchar_t);
                            if (nameOff + nameBytes <= recordBytes.size()) {
                                stream.Name.assign(
                                    reinterpret_cast<const wchar_t*>(
                                        recordBytes.data() + nameOff),
                                    attrHdr->NameLength);
                            }
                        }
                        out.Streams.push_back(std::move(stream));

                        if (attrHdr->NameLength == 0) {
                            dataAttrSeen = true;
                            out.LogicalSize = static_cast<uint64_t>(nrHdr->RealSize);
                            out.PhysicalSize = static_cast<uint64_t>(nrHdr->AllocatedSize);
                        }
                    }
                }

                offset += length;
            }
            return out;
        }
        catch (...) {
            ParsedRecord out;
            out.ParseFailed = true;
            return out;
        }
    }

    void ParseRange(std::span<uint8_t> mftBytes,
        uint32_t recordSize,
        wchar_t  driveLetter,
        size_t   start,
        size_t   end,
        ParsedRecord* out) noexcept {
        try {
            for (size_t i = start; i < end; ++i) {
                uint8_t* src = mftBytes.data() + i * recordSize;
                std::span<uint8_t> recSpan(src, recordSize);

                if (src[0] != 'F' || src[1] != 'I' || src[2] != 'L' || src[3] != 'E') {
                    ParsedRecord placeholder;
                    placeholder.RecordNumber = static_cast<uint32_t>(i);
                    placeholder.Drive = driveLetter;
                    placeholder.ParseFailed = true;
                    out[i] = std::move(placeholder);
                    continue;
                }

                ApplyUsaFixup(recSpan, 512);

                ParsedRecord parsed = ParseRecord(recSpan);
                parsed.Drive = driveLetter;
                if (parsed.RecordNumber == 0 && i != 0) {
                    parsed.RecordNumber = static_cast<uint32_t>(i);
                }
                out[i] = std::move(parsed);
            }
        }
        catch (...) {}
    }

    void MergeExtensionRecords(std::vector<ParsedRecord>& records) noexcept {
        try {
            for (size_t i = 0; i < records.size(); ++i) {
                ParsedRecord& r = records[i];
                if (r.BaseRecord == 0)             continue;
                if (r.BaseRecord >= records.size()) continue;
                if (r.BaseRecord == i)             continue;
                if (r.Streams.empty())             continue;

                ParsedRecord& base = records[r.BaseRecord];
                for (auto& s : r.Streams) {
                    if (s.Name.empty()) {
                        if (base.LogicalSize == 0 && base.PhysicalSize == 0) {
                            base.LogicalSize = s.LogicalSize;
                            base.PhysicalSize = s.PhysicalSize;
                        }
                        continue;
                    }
                    bool duplicate = false;
                    for (const auto& existing : base.Streams) {
                        if (existing.Name == s.Name) { duplicate = true; break; }
                    }
                    if (!duplicate) base.Streams.push_back(std::move(s));
                }
                r.Streams.clear();
            }
        }
        catch (...) {}
    }

    std::vector<ParsedRecord> ParseRecords(std::span<uint8_t> mftBytes,
        uint32_t recordSize,
        wchar_t  driveLetter) {
        try {
            std::vector<ParsedRecord> records;
            if (recordSize == 0) return records;
            const size_t count = mftBytes.size() / recordSize;
            records.resize(count);

            constexpr size_t kSerialThreshold = 4096;
            unsigned threadCount = std::thread::hardware_concurrency();
            if (threadCount == 0) threadCount = 1;
            if (count < kSerialThreshold) threadCount = 1;

            if (threadCount == 1) {
                ParseRange(mftBytes, recordSize, driveLetter, 0, count, records.data());
            }
            else {
                constexpr size_t kMinChunk = 1024;
                size_t chunkSize = (count + threadCount - 1) / threadCount;
                if (chunkSize < kMinChunk) chunkSize = kMinChunk;

                std::vector<std::thread> pool;
                pool.reserve(threadCount);
                ParsedRecord* outPtr = records.data();
                for (size_t start = 0; start < count; start += chunkSize) {
                    const size_t end = std::min(start + chunkSize, count);
                    pool.emplace_back(ParseRange, mftBytes, recordSize, driveLetter,
                        start, end, outPtr);
                }
                for (auto& t : pool) {
                    try { t.join(); }
                    catch (...) {}
                }
            }

            MergeExtensionRecords(records);
            return records;
        }
        catch (...) { return {}; }
    }

    std::vector<std::wstring> ComputePaths(const std::vector<ParsedRecord>& records,
        wchar_t driveLetter) {
        try {
            constexpr uint32_t kRootRecord = 5;
            enum class State : uint8_t { NotComputed, InProgress, Done };

            std::vector<std::wstring> paths(records.size());
            std::vector<State>        state(records.size(), State::NotComputed);

            std::wstring rootPath;
            if (driveLetter) {
                rootPath.push_back(driveLetter);
                rootPath.push_back(L':');
                rootPath.push_back(L'\\');
            }

            std::vector<size_t> stack;
            stack.reserve(64);

            for (size_t i = 0; i < records.size(); ++i) {
                if (state[i] == State::Done) continue;
                stack.clear();
                size_t cur = i;
                while (true) {
                    if (cur >= records.size())           break;
                    if (state[cur] == State::Done)       break;
                    if (state[cur] == State::InProgress) break;
                    state[cur] = State::InProgress;
                    stack.push_back(cur);

                    const ParsedRecord& r = records[cur];
                    if (cur == kRootRecord)    break;
                    if (!r.HasFileName)        break;
                    if (r.ParentRecord == cur) break;
                    cur = r.ParentRecord;
                }

                while (!stack.empty()) {
                    const size_t idx = stack.back();
                    stack.pop_back();

                    const ParsedRecord& r = records[idx];
                    std::wstring& dst = paths[idx];

                    if (idx == kRootRecord) {
                        dst = rootPath;
                    }
                    else if (!r.HasFileName) {
                        dst.clear();
                    }
                    else {
                        const uint32_t parent = r.ParentRecord;
                        if (parent < paths.size() && state[parent] == State::Done) {
                            const std::wstring& p = paths[parent];
                            dst.clear();
                            dst.reserve(p.size() + 1 + r.Name.size());
                            dst.append(p);
                            if (!dst.empty() && dst.back() != L'\\') dst.push_back(L'\\');
                            dst.append(r.Name);
                        }
                        else {
                            dst = rootPath;
                            dst.append(r.Name);
                        }
                    }
                    state[idx] = State::Done;
                }
            }
            return paths;
        }
        catch (...) { return {}; }
    }

    bool ReadAt(HANDLE h, uint64_t offset, void* buffer, size_t bytes) noexcept {
        try {
            LARGE_INTEGER li;
            li.QuadPart = static_cast<LONGLONG>(offset);
            if (!::SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;

            auto* dst = static_cast<uint8_t*>(buffer);
            while (bytes > 0) {
                const DWORD chunk = static_cast<DWORD>(
                    std::min<size_t>(bytes, 64u * 1024u * 1024u));
                DWORD got = 0;
                if (!::ReadFile(h, dst, chunk, &got, nullptr) || got == 0) return false;
                dst += got;
                bytes -= got;
            }
            return true;
        }
        catch (...) { return false; }
    }

    std::vector<Extent> DecodeDataRuns(const uint8_t* runs, size_t runsMax,
        uint32_t clusterSize) {
        try {
            std::vector<Extent> extents;
            int64_t prevLcn = 0;
            size_t  i = 0;
            while (i < runsMax) {
                const uint8_t header = runs[i++];
                if (header == 0) break;

                const uint8_t lengthBytes = header & 0x0F;
                const uint8_t offsetBytes = (header >> 4) & 0x0F;
                if (lengthBytes == 0 || lengthBytes > 8 || offsetBytes > 8) break;
                if (i + lengthBytes + offsetBytes > runsMax) break;

                uint64_t length = 0;
                for (int b = 0; b < lengthBytes; ++b)
                    length |= static_cast<uint64_t>(runs[i + b]) << (b * 8);
                i += lengthBytes;

                Extent ex{};
                ex.LengthInBytes = length * clusterSize;
                if (offsetBytes == 0) {
                    ex.Sparse = true;
                    ex.DiskOffset = 0;
                }
                else {
                    int64_t deltaLcn = 0;
                    for (int b = 0; b < offsetBytes; ++b)
                        deltaLcn |= static_cast<int64_t>(runs[i + b]) << (b * 8);
                    if (runs[i + offsetBytes - 1] & 0x80) {
                        const int shift = 64 - offsetBytes * 8;
                        deltaLcn = (deltaLcn << shift) >> shift;
                    }
                    i += offsetBytes;
                    prevLcn += deltaLcn;
                    ex.DiskOffset = static_cast<uint64_t>(prevLcn) * clusterSize;
                }
                extents.push_back(ex);
            }
            return extents;
        }
        catch (...) { return {}; }
    }

    bool FindMftDataAttribute(std::span<const uint8_t> record,
        uint32_t clusterSize,
        MftDataAttr& out) noexcept {
        try {
            if (record.size() < sizeof(FileRecordHeader)) return false;
            const auto* hdr = reinterpret_cast<const FileRecordHeader*>(record.data());
            uint32_t fileSig = 0;
            std::memcpy(&fileSig, hdr->Signature, sizeof(fileSig));
            if (fileSig != kFileMagic) return false;

            size_t off = hdr->FirstAttributeOffset;
            while (off + 8 <= record.size()) {
                uint32_t type = 0, length = 0;
                std::memcpy(&type, record.data() + off, 4);
                std::memcpy(&length, record.data() + off + 4, 4);
                if (type == kAttrEnd) break;
                if (length < 16 || off + length > record.size()) return false;

                if (type == kAttrData) {
                    const auto* a = reinterpret_cast<const AttributeHeader*>(record.data() + off);
                    if (a->NonResident && a->NameLength == 0) {
                        if (off + sizeof(NonResidentAttribute) > record.size()) return false;
                        const auto* nr = reinterpret_cast<const NonResidentAttribute*>(
                            record.data() + off);
                        const size_t runsOffset = off + nr->DataRunsOffset;
                        if (runsOffset >= record.size()) return false;

                        out.Extents = DecodeDataRuns(record.data() + runsOffset,
                            record.size() - runsOffset,
                            clusterSize);
                        out.RealSize = static_cast<uint64_t>(nr->RealSize);
                        out.AllocatedSize = static_cast<uint64_t>(nr->AllocatedSize);
                        out.InitializedSize = static_cast<uint64_t>(nr->InitializedSize);
                        return true;
                    }
                }
                off += length;
            }
            return false;
        }
        catch (...) { return false; }
    }

    LoadResult ReadMftFromVolume(wchar_t driveLetter) {
        try {
            wchar_t path[16];
            swprintf_s(path, xorstr_(L"\\\\.\\%c:"), driveLetter);

            HandleOwner vol(::CreateFileW(path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS,
                nullptr));
            if (!vol.valid()) return {};

            alignas(4096) std::array<uint8_t, 4096> sectorBuf{};
            if (!ReadAt(vol.h, 0, sectorBuf.data(), sectorBuf.size())) return {};

            NtfsBootSector boot{};
            std::memcpy(&boot, sectorBuf.data(), sizeof(boot));
            uint64_t oemSig = 0;
            std::memcpy(&oemSig, boot.Oem, sizeof(oemSig));
            if (oemSig != kNtfsOem) return {};

            const uint16_t bps = boot.BytesPerSector;
            if (bps == 0 || (bps & (bps - 1)) != 0) return {};
            const uint32_t clusterSize = static_cast<uint32_t>(bps) * boot.SectorsPerCluster;
            if (clusterSize == 0) return {};

            uint32_t recordSize = 0;
            if (boot.ClustersPerMftRecord >= 0)
                recordSize = static_cast<uint32_t>(boot.ClustersPerMftRecord) * clusterSize;
            else
                recordSize = 1u << static_cast<uint32_t>(-boot.ClustersPerMftRecord);
            if (recordSize == 0 || recordSize > 64 * 1024) return {};

            const uint64_t mftFileRecordOffset = boot.MftLcn * clusterSize;
            const uint32_t readChunk = std::max(recordSize, static_cast<uint32_t>(bps));

            std::vector<uint8_t> mftRecord0Aligned(((readChunk + 4095u) & ~4095u));
            if (!ReadAt(vol.h, mftFileRecordOffset, mftRecord0Aligned.data(),
                mftRecord0Aligned.size())) return {};

            std::span<uint8_t> recSpan(mftRecord0Aligned.data(), recordSize);
            if (!ApplyUsaFixup(recSpan, bps)) return {};

            MftDataAttr dataAttr;
            if (!FindMftDataAttribute(recSpan, clusterSize, dataAttr)) return {};
            if (dataAttr.RealSize == 0 || dataAttr.Extents.empty())   return {};

            std::vector<uint8_t> mftBytes;
            try {
                mftBytes.assign(static_cast<size_t>(dataAttr.RealSize), 0);
            }
            catch (...) { return {}; }

            uint64_t cursor = 0;
            uint64_t bytesRead = 0;
            const uint64_t totalToRead = dataAttr.RealSize;

            constexpr size_t kBounceSize = 32 * 1024 * 1024;
            std::vector<uint8_t> bounce;
            bounce.resize(kBounceSize + 4096);
            uint8_t* alignedBounce = reinterpret_cast<uint8_t*>(
                (reinterpret_cast<uintptr_t>(bounce.data()) + 4095) & ~uintptr_t(4095));

            for (const Extent& ext : dataAttr.Extents) {
                if (cursor >= totalToRead) break;

                uint64_t remainingInExtent = ext.LengthInBytes;
                uint64_t diskCursor = ext.DiskOffset;

                if (ext.Sparse) {
                    const uint64_t take = std::min(remainingInExtent, totalToRead - cursor);
                    cursor += take;
                    bytesRead += take;
                    continue;
                }

                while (remainingInExtent > 0 && cursor < totalToRead) {
                    const uint64_t want = std::min<uint64_t>(
                        std::min<uint64_t>(remainingInExtent, totalToRead - cursor),
                        kBounceSize);
                    const uint64_t aligned = (want + bps - 1) & ~uint64_t(bps - 1);
                    if (!ReadAt(vol.h, diskCursor, alignedBounce,
                        static_cast<size_t>(aligned))) return {};
                    std::memcpy(mftBytes.data() + cursor, alignedBounce,
                        static_cast<size_t>(want));
                    cursor += want;
                    diskCursor += want;
                    remainingInExtent -= want;
                    bytesRead += want;
                }
            }

            LoadResult result;
            result.Ok = true;
            result.MftBytes = std::move(mftBytes);
            result.RecordSize = recordSize;
            result.ClusterSize = clusterSize;
            result.BytesPerSector = bps;
            result.Drive = driveLetter;
            return result;
        }
        catch (...) { return {}; }
    }

    std::vector<wchar_t> EnumerateNtfsDrives() {
        try {
            std::vector<wchar_t> drives;
            const DWORD mask = ::GetLogicalDrives();
            for (int i = 0; i < 26; ++i) {
                if ((mask & (1u << i)) == 0) continue;
                const wchar_t letter = static_cast<wchar_t>(L'A' + i);
                const wchar_t root[4] = { letter, L':', L'\\', 0 };
                if (::GetDriveTypeW(root) != DRIVE_FIXED) continue;
                wchar_t fsName[16] = {};
                if (!::GetVolumeInformationW(root, nullptr, 0, nullptr, nullptr, nullptr,
                    fsName, 16)) continue;
                if (_wcsicmp(fsName, xorstr_(L"NTFS")) == 0) drives.push_back(letter);
            }
            return drives;
        }
        catch (...) { return {}; }
    }

    void AnnotatePeInAds(std::vector<ParsedRecord>& records,
        const std::vector<std::wstring>& paths) noexcept {
        try {
            struct Target { size_t recordIdx; size_t streamIdx; };
            std::vector<Target> targets;
            targets.reserve(256);

            const size_t pathsN = paths.size();
            for (size_t i = 0; i < records.size(); ++i) {
                if (i >= pathsN || paths[i].empty()) continue;
                ParsedRecord& r = records[i];
                for (size_t s = 0; s < r.Streams.size(); ++s) {
                    const DataStream& ds = r.Streams[s];
                    if (ds.Name.empty())       continue;
                    if (!ds.NonResident)       continue;
                    if (ds.LogicalSize < 0x40) continue;
                    targets.push_back({ i, s });
                }
            }

            uint8_t buf[0x200];
            for (const Target& t : targets) {
                DataStream& s = records[t.recordIdx].Streams[t.streamIdx];

                std::wstring full;
                full.reserve(paths[t.recordIdx].size() + 5 + s.Name.size());
                full.append(xorstr_(L"\\\\?\\"));
                full.append(paths[t.recordIdx]);
                full.push_back(L':');
                full.append(s.Name);

                HANDLE h = ::CreateFileW(
                    full.c_str(), GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL |
                    FILE_FLAG_SEQUENTIAL_SCAN |
                    FILE_FLAG_BACKUP_SEMANTICS |
                    FILE_FLAG_OPEN_REPARSE_POINT,
                    nullptr);
                if (h == INVALID_HANDLE_VALUE) continue;

                DWORD got = 0;
                const BOOL ok = ::ReadFile(h, buf, sizeof(buf), &got, nullptr);
                ::CloseHandle(h);
                if (!ok) continue;
                if (got < 0x40) continue;
                if (LooksLikePeBytes(buf, got)) s.LooksLikePe = true;
            }
        }
        catch (...) {}
    }

    bool IsBuiltInSystemStream(const std::wstring& basePath,
        const std::wstring& streamName) noexcept {
        try {
            const wchar_t* tail = basePath.c_str();
            size_t         tailLen = basePath.size();
            if (tailLen >= 2 && basePath[1] == L':') {
                tail += 2;
                tailLen -= 2;
            }

            struct Entry { std::wstring path; std::wstring stream; };
            static const Entry kEntries[] = {
                { xorstr_(L"\\$Extend\\$UsnJrnl"),             xorstr_(L"$J")       },
                { xorstr_(L"\\$Extend\\$RmMetadata\\$Repair"), xorstr_(L"$Corrupt") },
                { xorstr_(L"\\$BadClus"),                      xorstr_(L"$Bad")     },
                { xorstr_(L"\\$Secure"),                       xorstr_(L"$SDS")     },
            };

            for (const Entry& e : kEntries) {
                if (_wcsicmp(tail, e.path.c_str()) == 0 &&
                    _wcsicmp(streamName.c_str(), e.stream.c_str()) == 0) {
                    return true;
                }
            }
            return false;
        }
        catch (...) { return false; }
    }

    std::string WideToUtf8(const std::wstring& w) noexcept {
        try {
            if (w.empty()) return {};
            const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                static_cast<int>(w.size()),
                nullptr, 0, nullptr, nullptr);
            if (n <= 0) return {};
            std::string s(static_cast<size_t>(n), '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                static_cast<int>(w.size()),
                s.data(), n, nullptr, nullptr);
            return s;
        }
        catch (...) { return {}; }
    }

    std::string FormatFileTime(uint64_t ft) {
        try {
            if (ft == 0) return {};
            FILETIME f;
            f.dwLowDateTime = static_cast<DWORD>(ft & 0xFFFFFFFFu);
            f.dwHighDateTime = static_cast<DWORD>(ft >> 32);
            SYSTEMTIME st{};
            if (!::FileTimeToSystemTime(&f, &st)) return {};
            char buf[32];
            sprintf_s(buf, xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond);
            return buf;
        }
        catch (...) { return {}; }
    }

    bool IsEmbeddedSigned(LPCWSTR filePath) noexcept {
        try {
            HANDLE hFile = ::CreateFileW(
                filePath, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                FILE_FLAG_SEQUENTIAL_SCAN |
                FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            if (hFile == INVALID_HANDLE_VALUE) return false;

            WINTRUST_FILE_INFO fi{};
            fi.cbStruct = sizeof(fi);
            fi.pcwszFilePath = filePath;
            fi.hFile = hFile;

            WINTRUST_DATA wd{};
            wd.cbStruct = sizeof(wd);
            wd.dwUIChoice = WTD_UI_NONE;
            wd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wd.dwUnionChoice = WTD_CHOICE_FILE;
            wd.pFile = &fi;
            wd.dwStateAction = WTD_STATEACTION_VERIFY;
            wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG status = ::WinVerifyTrust(nullptr, &action, &wd);

            wd.dwStateAction = WTD_STATEACTION_CLOSE;
            ::WinVerifyTrust(nullptr, &action, &wd);

            ::CloseHandle(hFile);
            return status == ERROR_SUCCESS;
        }
        catch (...) { return false; }
    }

    bool IsCatalogSigned(LPCWSTR filePath) noexcept {
        try {
            HANDLE hCatAdmin = nullptr;
            if (!::CryptCATAdminAcquireContext(&hCatAdmin, nullptr, 0))
                return false;

            HANDLE hFile = ::CreateFileW(
                filePath, GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL |
                FILE_FLAG_SEQUENTIAL_SCAN |
                FILE_FLAG_BACKUP_SEMANTICS |
                FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            if (hFile == INVALID_HANDLE_VALUE) {
                ::CryptCATAdminReleaseContext(hCatAdmin, 0);
                return false;
            }

            DWORD hashSize = 0;
            ::CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0);

            std::vector<BYTE> hash(hashSize);
            if (hashSize == 0 ||
                !::CryptCATAdminCalcHashFromFileHandle(hFile, &hashSize, hash.data(), 0)) {
                ::CloseHandle(hFile);
                ::CryptCATAdminReleaseContext(hCatAdmin, 0);
                return false;
            }
            ::CloseHandle(hFile);

            bool isCatSigned = false;
            HCATINFO hCatInfo = ::CryptCATAdminEnumCatalogFromHash(
                hCatAdmin, hash.data(), hashSize, 0, nullptr);

            while (hCatInfo) {
                CATALOG_INFO catInfo{};
                catInfo.cbStruct = sizeof(catInfo);

                if (::CryptCATCatalogInfoFromContext(hCatInfo, &catInfo, 0)) {
                    WINTRUST_CATALOG_INFO wtc{};
                    wtc.cbStruct = sizeof(wtc);
                    wtc.pcwszCatalogFilePath = catInfo.wszCatalogFile;
                    wtc.pbCalculatedFileHash = hash.data();
                    wtc.cbCalculatedFileHash = hashSize;
                    wtc.pcwszMemberFilePath = filePath;

                    WINTRUST_DATA wtd{};
                    wtd.cbStruct = sizeof(wtd);
                    wtd.dwUnionChoice = WTD_CHOICE_CATALOG;
                    wtd.pCatalog = &wtc;
                    wtd.dwUIChoice = WTD_UI_NONE;
                    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
                    wtd.dwStateAction = WTD_STATEACTION_VERIFY;

                    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
                    LONG res = ::WinVerifyTrust(nullptr, &action, &wtd);

                    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
                    ::WinVerifyTrust(nullptr, &action, &wtd);

                    if (res == ERROR_SUCCESS) {
                        isCatSigned = true;
                        break;
                    }
                }

                hCatInfo = ::CryptCATAdminEnumCatalogFromHash(
                    hCatAdmin, hash.data(), hashSize, 0, &hCatInfo);
            }

            if (hCatInfo)
                ::CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
            ::CryptCATAdminReleaseContext(hCatAdmin, 0);
            return isCatSigned;
        }
        catch (...) { return false; }
    }

    bool IsFileSigned(LPCWSTR filePath) noexcept {
        try {
            if (IsEmbeddedSigned(filePath)) return true;
            if (IsCatalogSigned(filePath))  return true;
            return false;
        }
        catch (...) { return false; }
    }

    void EmitFindings(const std::vector<ParsedRecord>& records,
        const std::vector<std::wstring>& paths) noexcept {
        try {
            for (size_t i = 0; i < records.size(); ++i) {
                if (i >= paths.size() || paths[i].empty()) continue;
                const auto& r = records[i];
                if (!IsInUse(r)) continue;

                for (const auto& s : r.Streams) {
                    if (s.Name.empty())                          continue;
                    if (!s.LooksLikePe)                          continue;
                    if (IsBuiltInSystemStream(paths[i], s.Name)) continue;

                    std::wstring full;
                    full.reserve(paths[i].size() + 1 + s.Name.size());
                    full.append(paths[i]);
                    full.push_back(L':');
                    full.append(s.Name);

                    if (IsFileSigned(full.c_str())) continue;

                    try {
                        LOG(WARNING, FormatFileTime(r.CreationTime)) << xorstr_("Suspicious Alternate Data Stream Found:") << WideToUtf8(full);
                    }
                    catch (...) {}
                }
            }
        }
        catch (...) {}
    }

    void ProcessLoadResult(const LoadResult& load) noexcept {
        try {
            if (!load.Ok) return;
            std::vector<uint8_t> bytes = load.MftBytes;
            auto records = ParseRecords(bytes, load.RecordSize, load.Drive);
            auto paths = ComputePaths(records, load.Drive);
            if (load.Drive) AnnotatePeInAds(records, paths);
            EmitFindings(records, paths);
        }
        catch (...) {}
    }

}

void SusAds::start_sus_ads() {
    try {
        try { ::SetConsoleOutputCP(CP_UTF8); }
        catch (...) {}
        const auto drives = EnumerateNtfsDrives();
        for (wchar_t d : drives) {
            try {
                auto load = ReadMftFromVolume(d);
                ProcessLoadResult(load);
            }
            catch (...) {}
        }
    }
    catch (...) {}
}