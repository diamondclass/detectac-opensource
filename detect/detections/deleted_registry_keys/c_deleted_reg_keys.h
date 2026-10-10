#pragma once

#include "../../pch.h"
#include <optional>

class del_reg_keys
{
public:
    static constexpr size_t kHbinsBase = 0x1000;
    static constexpr uint32_t kInvalidOffset = 0xFFFFFFFFu;
    static constexpr uint16_t kKeyCompName = 0x0020;
    static constexpr uint16_t kValueCompName = 0x0001;
    static constexpr uint32_t kResidentDataFlag = 0x80000000u;
    static constexpr uint32_t kDataSizeMask = 0x7FFFFFFFu;
    static constexpr uint32_t kRegBinary = 3;

    struct NkInfo {
        bool ok = false;
        uint16_t flags = 0;
        uint64_t lastWrite = 0;
        uint32_t parentOff = 0;
        uint32_t valueCount = 0;
        uint32_t valueListOff = 0;
        std::wstring name;
    };

    struct LogPage {
        uint32_t offset = 0;
        uint32_t size = 0;
        size_t dataPos = 0;
        const std::vector<uint8_t>* src = nullptr;
    };

    struct LogEntry {
        uint32_t seq = 0;
        std::vector<LogPage> pages;
    };

    struct Finding {
        std::string folder;
        std::string debugger;
        std::string ts;
    };

    static std::vector<uint8_t> s_hive;

    static bool inB(size_t off, size_t need);
    static uint16_t rd16(size_t o);
    static uint32_t rd32(size_t o);
    static int32_t rds32(size_t o);
    static uint64_t rd64(size_t o);
    static uint32_t readU32At(const std::vector<uint8_t>& b, size_t off);
    static size_t cellDataOffset(uint32_t cellRelOff);

    static std::string wideToUtf8(const std::wstring& w);
    static std::wstring asciiToWide(size_t off, size_t lenBytes);
    static std::wstring utf16ToWide(size_t off, size_t lenBytes);
    static bool iEqualsAsciiW(const std::wstring& a, const wchar_t* b);
    static std::string toLowerAscii(std::string s);
    static std::string trim(const std::string& s);
    static std::string formatLocalTime(uint64_t ft);

    static NkInfo parseNk(size_t sig);
    static std::optional<std::string> findDebuggerValue(const NkInfo& nk);
    static bool isBamLikeVk(size_t vkSig, std::string& nameOut);
    static std::vector<bool> markAllocatedCells();
    static void parseLogEntries(const std::vector<uint8_t>& lb, std::vector<LogEntry>& out);
    static bool examineIfeoNk(size_t off, Finding& f, bool& hasDebugger);
    static bool loadFile(const std::wstring& path, std::vector<uint8_t>& out);
    static void analyze(const std::wstring& hivePath, const std::wstring& log1Path,
                        const std::wstring& log2Path, std::vector<Finding>& ifeoResults,
                        std::vector<std::string>& bamNames);
    static void emit(const std::vector<Finding>& ifeoResults,
                     const std::vector<std::string>& bamNames);

    static bool isElevated();
    static bool acquireHives(std::wstring& outSoftware, std::wstring& outSystem);

    static void start_deleted_reg_keys_check();
};

inline auto c_delregkeys = std::make_unique<del_reg_keys>();
