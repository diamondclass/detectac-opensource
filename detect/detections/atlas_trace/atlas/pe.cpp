#include "pe.h"

namespace atlas {
namespace {

bool ReadWholeFile(const std::wstring& path, std::vector<uint8_t>* out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (64ll << 20)) {
        CloseHandle(h);
        return false;
    }
    out->resize((size_t)sz.QuadPart);
    DWORD got = 0;
    BOOL ok = ReadFile(h, out->data(), (DWORD)out->size(), &got, nullptr);
    CloseHandle(h);
    if (!ok || got != out->size()) return false;
    return true;
}

template <typename T>
const T* At(const std::vector<uint8_t>& buf, size_t off) {
    if (off + sizeof(T) > buf.size()) return nullptr;
    return reinterpret_cast<const T*>(buf.data() + off);
}

}

bool LoadDiskImage(const std::wstring& path, uint64_t actualBase, DiskImage* out) {
    *out = DiskImage();
    if (!ReadWholeFile(path, &out->file)) return false;

    const IMAGE_DOS_HEADER* dos = At<IMAGE_DOS_HEADER>(out->file, 0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
    size_t ntOff = (size_t)dos->e_lfanew;

    const IMAGE_NT_HEADERS32* nt32 = At<IMAGE_NT_HEADERS32>(out->file, ntOff);
    if (!nt32 || nt32->Signature != IMAGE_NT_SIGNATURE) return false;

    WORD magic = nt32->OptionalHeader.Magic;
    out->is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    WORD numSections = 0, sizeOfOptional = 0;
    uint32_t sizeOfHeaders = 0;
    const IMAGE_DATA_DIRECTORY* dirs = nullptr;

    if (out->is64) {
        const IMAGE_NT_HEADERS64* nt = At<IMAGE_NT_HEADERS64>(out->file, ntOff);
        if (!nt) return false;
        out->preferredBase = nt->OptionalHeader.ImageBase;
        out->sizeOfImage   = nt->OptionalHeader.SizeOfImage;
        sizeOfHeaders      = nt->OptionalHeader.SizeOfHeaders;
        numSections        = nt->FileHeader.NumberOfSections;
        sizeOfOptional     = nt->FileHeader.SizeOfOptionalHeader;
        dirs               = nt->OptionalHeader.DataDirectory;
    } else {
        out->preferredBase = nt32->OptionalHeader.ImageBase;
        out->sizeOfImage   = nt32->OptionalHeader.SizeOfImage;
        sizeOfHeaders      = nt32->OptionalHeader.SizeOfHeaders;
        numSections        = nt32->FileHeader.NumberOfSections;
        sizeOfOptional     = nt32->FileHeader.SizeOfOptionalHeader;
        dirs               = nt32->OptionalHeader.DataDirectory;
    }
    if (out->sizeOfImage == 0 || out->sizeOfImage > (512u << 20)) return false;
    if (numSections == 0 || numSections > 96) return false;

    size_t secOff = ntOff + offsetof(IMAGE_NT_HEADERS32, OptionalHeader) + sizeOfOptional;
    const IMAGE_SECTION_HEADER* secs = At<IMAGE_SECTION_HEADER>(out->file, secOff);
    if (!secs) return false;
    if (secOff + sizeof(IMAGE_SECTION_HEADER) * numSections > out->file.size()) return false;

    out->mapped.assign((size_t)out->sizeOfImage, 0);
    size_t hdrCopy = (std::min)((size_t)sizeOfHeaders, out->file.size());
    memcpy(out->mapped.data(), out->file.data(), hdrCopy);

    for (WORD i = 0; i < numSections; ++i) {
        const IMAGE_SECTION_HEADER& s = secs[i];
        char nameBuf[9] = {};
        memcpy(nameBuf, s.Name, 8);

        Section sec;
        sec.name = nameBuf;
        sec.rva  = s.VirtualAddress;
        sec.size = s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        sec.characteristics = s.Characteristics;
        out->sections.push_back(sec);

        if (s.PointerToRawData == 0 || s.SizeOfRawData == 0) continue;
        if ((size_t)s.PointerToRawData + s.SizeOfRawData > out->file.size()) continue;
        if ((size_t)s.VirtualAddress >= out->mapped.size()) continue;
        size_t n = (std::min)((size_t)s.SizeOfRawData,
                              out->mapped.size() - (size_t)s.VirtualAddress);
        memcpy(out->mapped.data() + s.VirtualAddress, out->file.data() + s.PointerToRawData, n);
    }

    int64_t delta = (int64_t)(actualBase - out->preferredBase);
    const IMAGE_DATA_DIRECTORY& rel = dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (rel.VirtualAddress && rel.Size && rel.VirtualAddress + rel.Size <= out->sizeOfImage) {
        size_t off = rel.VirtualAddress;
        size_t end = (size_t)rel.VirtualAddress + rel.Size;
        while (off + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            const IMAGE_BASE_RELOCATION* br =
                reinterpret_cast<const IMAGE_BASE_RELOCATION*>(out->mapped.data() + off);
            if (br->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || off + br->SizeOfBlock > end)
                break;
            size_t count = (br->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            const WORD* entries =
                reinterpret_cast<const WORD*>(out->mapped.data() + off + sizeof(IMAGE_BASE_RELOCATION));
            for (size_t i = 0; i < count; ++i) {
                WORD type   = entries[i] >> 12;
                WORD offset = entries[i] & 0x0FFF;
                uint32_t rva = br->VirtualAddress + offset;
                if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
                if (type == IMAGE_REL_BASED_DIR64) {
                    if ((size_t)rva + 8 > out->mapped.size()) continue;
                    uint64_t v;
                    memcpy(&v, out->mapped.data() + rva, 8);
                    v = (uint64_t)((int64_t)v + delta);
                    memcpy(out->mapped.data() + rva, &v, 8);
                    for (uint32_t k = 0; k < 8; ++k) out->relocRvas.insert(rva + k);
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    if ((size_t)rva + 4 > out->mapped.size()) continue;
                    uint32_t v;
                    memcpy(&v, out->mapped.data() + rva, 4);
                    v = (uint32_t)((int32_t)v + (int32_t)delta);
                    memcpy(out->mapped.data() + rva, &v, 4);
                    for (uint32_t k = 0; k < 4; ++k) out->relocRvas.insert(rva + k);
                }
            }
            off += br->SizeOfBlock;
        }
    }

    out->ok = true;
    return true;
}

static const IMAGE_DATA_DIRECTORY* DataDirs(const DiskImage& img) {
    const IMAGE_DOS_HEADER* dos = At<IMAGE_DOS_HEADER>(img.mapped, 0);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    size_t ntOff = (size_t)dos->e_lfanew;
    if (img.is64) {
        const IMAGE_NT_HEADERS64* nt = At<IMAGE_NT_HEADERS64>(img.mapped, ntOff);
        return nt ? nt->OptionalHeader.DataDirectory : nullptr;
    }
    const IMAGE_NT_HEADERS32* nt = At<IMAGE_NT_HEADERS32>(img.mapped, ntOff);
    return nt ? nt->OptionalHeader.DataDirectory : nullptr;
}

bool ReadExports(const DiskImage& img, std::vector<ExportEntry>* out) {
    out->clear();
    const IMAGE_DATA_DIRECTORY* dirs = DataDirs(img);
    if (!dirs) return false;
    const IMAGE_DATA_DIRECTORY& d = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!d.VirtualAddress || !d.Size) return true;
    const IMAGE_EXPORT_DIRECTORY* ed = At<IMAGE_EXPORT_DIRECTORY>(img.mapped, d.VirtualAddress);
    if (!ed) return false;
    if (ed->NumberOfFunctions > 100000 || ed->NumberOfNames > 100000) return false;

    const uint32_t* funcs = At<uint32_t>(img.mapped, ed->AddressOfFunctions);
    const uint32_t* names = ed->AddressOfNames ? At<uint32_t>(img.mapped, ed->AddressOfNames) : nullptr;
    const uint16_t* ords  = ed->AddressOfNameOrdinals ? At<uint16_t>(img.mapped, ed->AddressOfNameOrdinals) : nullptr;
    if (!funcs) return false;
    if (ed->AddressOfFunctions + 4ull * ed->NumberOfFunctions > img.mapped.size()) return false;

    std::map<uint32_t, std::string> nameByIndex;
    if (names && ords &&
        ed->AddressOfNames + 4ull * ed->NumberOfNames <= img.mapped.size() &&
        ed->AddressOfNameOrdinals + 2ull * ed->NumberOfNames <= img.mapped.size()) {
        for (uint32_t i = 0; i < ed->NumberOfNames; ++i) {
            uint32_t nrva = names[i];
            if (nrva >= img.mapped.size()) continue;
            const char* s = reinterpret_cast<const char*>(img.mapped.data() + nrva);
            size_t maxLen = img.mapped.size() - nrva;
            size_t len = strnlen(s, maxLen);
            nameByIndex[ords[i]] = std::string(s, len);
        }
    }

    for (uint32_t i = 0; i < ed->NumberOfFunctions; ++i) {
        if (funcs[i] == 0) continue;
        ExportEntry e;
        e.rva     = funcs[i];
        e.ordinal = (uint16_t)(ed->Base + i);
        std::map<uint32_t, std::string>::iterator it = nameByIndex.find(i);
        if (it != nameByIndex.end()) e.name = it->second;
        if (e.rva >= d.VirtualAddress && e.rva < d.VirtualAddress + d.Size) {
            e.forwarder = true;
            if (e.rva < img.mapped.size()) {
                const char* s = reinterpret_cast<const char*>(img.mapped.data() + e.rva);
                e.forwardTo = std::string(s, strnlen(s, img.mapped.size() - e.rva));
            }
        }
        out->push_back(e);
    }
    return true;
}

bool ReadImports(const DiskImage& img, std::vector<ImportThunk>* out) {
    out->clear();
    const IMAGE_DATA_DIRECTORY* dirs = DataDirs(img);
    if (!dirs) return false;
    const IMAGE_DATA_DIRECTORY& d = dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!d.VirtualAddress || !d.Size) return true;

    size_t off = d.VirtualAddress;
    for (int guard = 0; guard < 4096; ++guard) {
        const IMAGE_IMPORT_DESCRIPTOR* imp = At<IMAGE_IMPORT_DESCRIPTOR>(img.mapped, off);
        if (!imp || imp->Name == 0 || imp->FirstThunk == 0) break;
        if (imp->Name >= img.mapped.size()) break;
        const char* dllName = reinterpret_cast<const char*>(img.mapped.data() + imp->Name);
        std::string dll(dllName, strnlen(dllName, img.mapped.size() - imp->Name));

        uint32_t intRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
        uint32_t iatRva = imp->FirstThunk;
        size_t   step   = img.is64 ? 8 : 4;

        for (int i = 0; i < 8192; ++i) {
            size_t tOff = intRva + (size_t)i * step;
            if (tOff + step > img.mapped.size()) break;
            uint64_t thunk = 0;
            memcpy(&thunk, img.mapped.data() + tOff, step);
            if (thunk == 0) break;

            ImportThunk t;
            t.dll    = dll;
            t.iatRva = iatRva + (uint64_t)i * step;
            uint64_t ordFlag = img.is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
            if (thunk & ordFlag) {
                t.ordinal = (uint16_t)(thunk & 0xFFFF);
            } else {
                uint32_t nameRva = (uint32_t)thunk;
                if ((size_t)nameRva + 2 < img.mapped.size()) {
                    const char* fn = reinterpret_cast<const char*>(img.mapped.data() + nameRva + 2);
                    t.func = std::string(fn, strnlen(fn, img.mapped.size() - nameRva - 2));
                }
            }
            out->push_back(t);
        }
        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return true;
}

PeProbe ProbeForPeImage(const uint8_t* data, size_t size) {
    PeProbe p;
    if (size < 0x400) return p;

    const IMAGE_DOS_HEADER* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
    if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
        (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) < size) {
        const IMAGE_NT_HEADERS32* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS32*>(data + dos->e_lfanew);
        if (nt->Signature == IMAGE_NT_SIGNATURE) {
            p.isPe = true;
            if (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                const IMAGE_NT_HEADERS64* nt64 =
                    reinterpret_cast<const IMAGE_NT_HEADERS64*>(data + dos->e_lfanew);
                p.sizeOfImage = nt64->OptionalHeader.SizeOfImage;
            } else {
                p.sizeOfImage = nt->OptionalHeader.SizeOfImage;
            }
            p.sectionCount = nt->FileHeader.NumberOfSections;
            return p;
        }
    }

    for (size_t off = 0; off + sizeof(IMAGE_SECTION_HEADER) * 3 <= (std::min)(size, (size_t)0x600); off += 8) {
        const IMAGE_SECTION_HEADER* s =
            reinterpret_cast<const IMAGE_SECTION_HEADER*>(data + off);
        int good = 0;
        uint32_t lastVa = 0;
        for (int i = 0; i < 8; ++i) {
            if (off + sizeof(IMAGE_SECTION_HEADER) * (i + 1) > size) break;
            const IMAGE_SECTION_HEADER& sh = s[i];
            if (sh.VirtualAddress == 0 || sh.VirtualAddress <= lastVa) break;
            if (sh.VirtualAddress > (256u << 20)) break;
            if ((sh.Characteristics & 0xE0000000u) == 0) break;
            bool nameOk = (sh.Name[0] == '.' || sh.Name[0] == 0 ||
                           (sh.Name[0] >= 'A' && sh.Name[0] <= 'z'));
            if (!nameOk) break;
            lastVa = sh.VirtualAddress;
            ++good;
        }
        if (good >= 3) {
            p.isPe = true;
            p.headerErased = true;
            p.sectionCount = good;
            return p;
        }
    }
    return p;
}

uint64_t DecodeDetour(const uint8_t* c, size_t avail, uint64_t va,
                      const Target& t) {
    if (avail >= 5 && c[0] == 0xE9) {
        int32_t rel;
        memcpy(&rel, c + 1, 4);
        return va + 5 + (int64_t)rel;
    }
    if (avail >= 5 && c[0] == 0xE8) {
        int32_t rel;
        memcpy(&rel, c + 1, 4);
        return va + 5 + (int64_t)rel;
    }
    if (avail >= 2 && c[0] == 0xEB) {
        int8_t rel = (int8_t)c[1];
        return va + 2 + (int64_t)rel;
    }
    if (avail >= 6 && c[0] == 0xFF && c[1] == 0x25) {
        int32_t disp;
        memcpy(&disp, c + 2, 4);
        uint64_t slot = va + 6 + (int64_t)disp;
        uint64_t dest = 0;
        if (t.Read(slot, &dest, sizeof(dest))) {
            return dest;
        }
        return 0;
    }
    if (avail >= 12 && c[0] == 0x48 && c[1] == 0xB8 &&
        c[10] == 0xFF && c[11] == 0xE0) {
        uint64_t dest;
        memcpy(&dest, c + 2, 8);
        return dest;
    }
    if (avail >= 13 && c[0] == 0x49 && c[1] == 0xBB &&
        c[10] == 0x41 && c[11] == 0xFF && c[12] == 0xE3) {
        uint64_t dest;
        memcpy(&dest, c + 2, 8);
        return dest;
    }
    if (avail >= 6 && c[0] == 0x68 && c[5] == 0xC3) {
        uint32_t d;
        memcpy(&d, c + 1, 4);
        return d;
    }
    return 0;
}

}
