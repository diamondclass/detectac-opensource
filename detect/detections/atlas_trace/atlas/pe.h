#pragma once
#include "common.h"
#include "target.h"

namespace atlas {

struct DiskImage {
    bool                 ok = false;
    std::vector<uint8_t> file;
    std::vector<uint8_t> mapped;
    uint64_t             preferredBase = 0;
    uint64_t             sizeOfImage   = 0;
    bool                 is64 = false;
    std::vector<Section> sections;
    std::set<uint32_t>   relocRvas;
};

bool LoadDiskImage(const std::wstring& path, uint64_t actualBase, DiskImage* out);

struct ExportEntry {
    std::string name;
    uint32_t    rva = 0;
    uint16_t    ordinal = 0;
    bool        forwarder = false;
    std::string forwardTo;
};

bool ReadExports(const DiskImage& img, std::vector<ExportEntry>* out);

struct ImportThunk {
    std::string dll;
    std::string func;
    uint16_t    ordinal = 0;
    uint64_t    iatRva  = 0;
};

bool ReadImports(const DiskImage& img, std::vector<ImportThunk>* out);

struct PeProbe {
    bool     isPe = false;
    bool     headerErased = false;
    uint64_t sizeOfImage = 0;
    int      sectionCount = 0;
    std::string reason;
};

PeProbe ProbeForPeImage(const uint8_t* data, size_t size);

uint64_t DecodeDetour(const uint8_t* code, size_t avail, uint64_t codeVa,
                      const Target& t);

}
