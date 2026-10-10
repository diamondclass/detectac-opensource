#include "c_deleted_reg_keys.h"

std::vector<uint8_t> del_reg_keys::s_hive;

bool del_reg_keys::inB(size_t off, size_t need) {
    try {
        return need <= s_hive.size() && off <= s_hive.size() - need;
    }
    catch (...) { return false; }
}

uint16_t del_reg_keys::rd16(size_t o) {
    try {
        uint16_t v = 0;
        if (inB(o, 2)) std::memcpy(&v, &s_hive[o], 2);
        return v;
    }
    catch (...) { return 0; }
}

uint32_t del_reg_keys::rd32(size_t o) {
    try {
        uint32_t v = 0;
        if (inB(o, 4)) std::memcpy(&v, &s_hive[o], 4);
        return v;
    }
    catch (...) { return 0; }
}

int32_t del_reg_keys::rds32(size_t o) {
    try {
        int32_t v = 0;
        if (inB(o, 4)) std::memcpy(&v, &s_hive[o], 4);
        return v;
    }
    catch (...) { return 0; }
}

uint64_t del_reg_keys::rd64(size_t o) {
    try {
        uint64_t v = 0;
        if (inB(o, 8)) std::memcpy(&v, &s_hive[o], 8);
        return v;
    }
    catch (...) { return 0; }
}

uint32_t del_reg_keys::readU32At(const std::vector<uint8_t>& b, size_t off) {
    try {
        uint32_t v = 0;
        if (off + 4 <= b.size()) std::memcpy(&v, &b[off], 4);
        return v;
    }
    catch (...) { return 0; }
}

size_t del_reg_keys::cellDataOffset(uint32_t cellRelOff) {
    try {
        return kHbinsBase + static_cast<size_t>(cellRelOff) + 4;
    }
    catch (...) { return 0; }
}

std::string del_reg_keys::wideToUtf8(const std::wstring& w) {
    try {
        if (w.empty()) return std::string();
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr,
                                      0, nullptr, nullptr);
        if (len <= 0) return std::string();
        std::string out((size_t)len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), len,
                            nullptr, nullptr);
        return out;
    }
    catch (...) { return std::string(); }
}

std::wstring del_reg_keys::asciiToWide(size_t off, size_t lenBytes) {
    try {
        std::wstring w;
        w.reserve(lenBytes);
        for (size_t i = 0; i < lenBytes; ++i)
            w.push_back((wchar_t)(unsigned char)s_hive[off + i]);
        return w;
    }
    catch (...) { return std::wstring(); }
}

std::wstring del_reg_keys::utf16ToWide(size_t off, size_t lenBytes) {
    try {
        std::wstring w;
        w.reserve(lenBytes / 2);
        for (size_t i = 0; i + 1 < lenBytes; i += 2) {
            wchar_t ch = (wchar_t)(s_hive[off + i] | (s_hive[off + i + 1] << 8));
            if (ch == 0) break;
            w.push_back(ch);
        }
        return w;
    }
    catch (...) { return std::wstring(); }
}

bool del_reg_keys::iEqualsAsciiW(const std::wstring& a, const wchar_t* b) {
    try {
        size_t i = 0;
        for (; i < a.size() && b[i]; ++i) {
            wchar_t ca = a[i], cb = b[i];
            if (ca >= L'A' && ca <= L'Z') ca = (wchar_t)(ca - L'A' + L'a');
            if (cb >= L'A' && cb <= L'Z') cb = (wchar_t)(cb - L'A' + L'a');
            if (ca != cb) return false;
        }
        return i == a.size() && b[i] == 0;
    }
    catch (...) { return false; }
}

std::string del_reg_keys::toLowerAscii(std::string s) {
    try {
        for (char& c : s)
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        return s;
    }
    catch (...) { return s; }
}

std::string del_reg_keys::trim(const std::string& s) {
    try {
        size_t a = s.find_first_not_of(xorstr_(" \t\r\n"));
        if (a == std::string::npos) return std::string();
        size_t b = s.find_last_not_of(xorstr_(" \t\r\n"));
        return s.substr(a, b - a + 1);
    }
    catch (...) { return std::string(); }
}

std::string del_reg_keys::formatLocalTime(uint64_t ft) {
    try {
        if (ft == 0) return xorstr_("N/A");
        FILETIME f;
        f.dwLowDateTime = (DWORD)(ft & 0xFFFFFFFFu);
        f.dwHighDateTime = (DWORD)(ft >> 32);
        SYSTEMTIME utc, local;
        if (!FileTimeToSystemTime(&f, &utc)) return xorstr_("N/A");
        if (!SystemTimeToTzSpecificLocalTime(nullptr, &utc, &local)) local = utc;
        char buf[64];
        std::snprintf(buf, sizeof(buf), xorstr_("%04u-%02u-%02u %02u:%02u:%02u"),
                      local.wYear, local.wMonth, local.wDay, local.wHour,
                      local.wMinute, local.wSecond);
        return std::string(buf);
    }
    catch (...) { return xorstr_("N/A"); }
}

del_reg_keys::NkInfo del_reg_keys::parseNk(size_t sig) {
    NkInfo nk;
    try {
        if (!inB(sig, 0x4C)) return nk;
        if (!(s_hive[sig] == 'n' && s_hive[sig + 1] == 'k')) return nk;

        nk.flags = rd16(sig + 0x02);
        nk.lastWrite = rd64(sig + 0x04);
        nk.parentOff = rd32(sig + 0x10);
        nk.valueCount = rd32(sig + 0x24);
        nk.valueListOff = rd32(sig + 0x28);

        uint16_t nameLen = rd16(sig + 0x48);
        size_t nameOff = sig + 0x4C;
        if (nameLen == 0 || nameLen > 512 || !inB(nameOff, nameLen)) return nk;

        nk.name = (nk.flags & kKeyCompName) ? asciiToWide(nameOff, nameLen)
                                            : utf16ToWide(nameOff, nameLen);
        if (nk.name.empty()) return nk;
        nk.ok = true;
        return nk;
    }
    catch (...) { return NkInfo(); }
}

std::optional<std::string> del_reg_keys::findDebuggerValue(const NkInfo& nk) {
    try {
        if (nk.valueCount == 0 || nk.valueListOff == kInvalidOffset)
            return std::nullopt;

        size_t listData = cellDataOffset(nk.valueListOff);
        uint32_t count = nk.valueCount > 4096 ? 4096 : nk.valueCount;
        if (!inB(listData, 4)) return std::nullopt;

        for (uint32_t i = 0; i < count; ++i) {
            size_t entryOff = listData + (size_t)i * 4;
            if (!inB(entryOff, 4)) break;
            uint32_t vkOff = rd32(entryOff);
            if (vkOff == kInvalidOffset) continue;

            size_t vk = cellDataOffset(vkOff);
            if (!inB(vk, 0x14)) continue;
            if (!(s_hive[vk] == 'v' && s_hive[vk + 1] == 'k')) continue;

            uint16_t nameLen = rd16(vk + 0x02);
            uint32_t dataSizeRaw = rd32(vk + 0x04);
            uint32_t dataOffField = rd32(vk + 0x08);
            uint16_t vkFlags = rd16(vk + 0x10);
            size_t nameOff = vk + 0x14;

            if (nameLen == 0 || nameLen > 512 || !inB(nameOff, nameLen)) continue;
            std::wstring vname = (vkFlags & kValueCompName)
                                     ? asciiToWide(nameOff, nameLen)
                                     : utf16ToWide(nameOff, nameLen);
            if (!iEqualsAsciiW(vname, xorstr_(L"Debugger"))) continue;

            bool resident = (dataSizeRaw & kResidentDataFlag) != 0;
            uint32_t dataSize = dataSizeRaw & kDataSizeMask;

            std::wstring value;
            if (resident) {
                uint32_t n = dataSize > 4 ? 4 : dataSize;
                size_t fieldOff = vk + 0x08;
                for (uint32_t k = 0; k + 1 < n; k += 2) {
                    wchar_t ch = (wchar_t)(s_hive[fieldOff + k] |
                                           (s_hive[fieldOff + k + 1] << 8));
                    if (ch == 0) break;
                    value.push_back(ch);
                }
            }
            else {
                if (dataSize == 0) return std::string();
                if (dataSize > 0x4000) dataSize = 0x4000;
                size_t dataLoc = cellDataOffset(dataOffField);
                if (!inB(dataLoc, dataSize)) {
                    if (dataLoc >= s_hive.size()) continue;
                    dataSize = (uint32_t)(s_hive.size() - dataLoc);
                }
                value = utf16ToWide(dataLoc, dataSize);
            }
            return wideToUtf8(value);
        }
        return std::nullopt;
    }
    catch (...) { return std::nullopt; }
}

bool del_reg_keys::isBamLikeVk(size_t vkSig, std::string& nameOut) {
    try {
        if (!inB(vkSig, 0x14)) return false;
        if (!(s_hive[vkSig] == 'v' && s_hive[vkSig + 1] == 'k')) return false;

        uint16_t nameLen = rd16(vkSig + 0x02);
        uint32_t dataSizeRaw = rd32(vkSig + 0x04);
        uint32_t dataOffField = rd32(vkSig + 0x08);
        uint32_t type = rd32(vkSig + 0x0C);
        uint16_t vkFlags = rd16(vkSig + 0x10);
        size_t nameOff = vkSig + 0x14;

        if (type != kRegBinary) return false;

        bool resident = (dataSizeRaw & kResidentDataFlag) != 0;
        uint32_t dataSize = dataSizeRaw & kDataSizeMask;
        if (resident || dataSize < 8) return false;

        size_t dataLoc = cellDataOffset(dataOffField);
        if (!inB(dataLoc, 8)) return false;
        uint64_t ft = rd64(dataLoc);
        if (ft == 0) return false;
        FILETIME f;
        f.dwLowDateTime = (DWORD)(ft & 0xFFFFFFFFu);
        f.dwHighDateTime = (DWORD)(ft >> 32);
        SYSTEMTIME st;
        if (!FileTimeToSystemTime(&f, &st)) return false;
        if (st.wYear < 2000 || st.wYear > 2100) return false;

        if (nameLen == 0 || nameLen > 2048 || !inB(nameOff, nameLen)) return false;
        std::wstring w = (vkFlags & kValueCompName) ? asciiToWide(nameOff, nameLen)
                                                    : utf16ToWide(nameOff, nameLen);
        if (w.find(L'\\') == std::wstring::npos) return false;

        nameOut = wideToUtf8(w);
        return !nameOut.empty();
    }
    catch (...) { return false; }
}

std::vector<bool> del_reg_keys::markAllocatedCells() {
    try {
        std::vector<bool> allocated(s_hive.size(), false);
        size_t pos = kHbinsBase;
        while (inB(pos, 0x20)) {
            if (!(s_hive[pos] == 'h' && s_hive[pos + 1] == 'b' &&
                  s_hive[pos + 2] == 'i' && s_hive[pos + 3] == 'n'))
                break;
            uint32_t binSize = rd32(pos + 0x08);
            if (binSize < 0x20) break;
            size_t binEnd = pos + binSize;
            if (binEnd > s_hive.size()) binEnd = s_hive.size();
            size_t c = pos + 0x20;
            while (c + 4 <= binEnd) {
                int32_t sz = rds32(c);
                uint32_t cellSize = (sz < 0) ? (uint32_t)(-sz) : (uint32_t)sz;
                if (cellSize < 8 || c + cellSize > binEnd) break;
                if (sz < 0) {
                    size_t s = c + 4, e = c + cellSize;
                    for (size_t i = s; i < e && i < allocated.size(); ++i)
                        allocated[i] = true;
                }
                c += cellSize;
            }
            pos = binEnd;
        }
        return allocated;
    }
    catch (...) { return std::vector<bool>(); }
}

void del_reg_keys::parseLogEntries(const std::vector<uint8_t>& lb,
                                   std::vector<LogEntry>& out) {
    try {
        if (lb.size() < kHbinsBase) return;
        if (!(lb[0] == 'r' && lb[1] == 'e' && lb[2] == 'g' && lb[3] == 'f')) return;

        size_t pos = 512;
        while (pos + 40 <= lb.size()) {
            if (!(lb[pos] == 'H' && lb[pos + 1] == 'v' && lb[pos + 2] == 'L' &&
                  lb[pos + 3] == 'E'))
                break;
            uint32_t size = readU32At(lb, pos + 4);
            if (size < 512 || (size % 512) != 0 || pos + size > lb.size()) break;

            uint32_t cnt = readU32At(lb, pos + 20);
            size_t refOff = pos + 40;
            if (cnt <= 0x40000 && refOff + (size_t)cnt * 8 <= pos + size) {
                LogEntry e;
                e.seq = readU32At(lb, pos + 12);
                size_t dataOff = refOff + (size_t)cnt * 8;
                bool ok = true;
                for (uint32_t i = 0; i < cnt; ++i) {
                    uint32_t poff = readU32At(lb, refOff + i * 8);
                    uint32_t psize = readU32At(lb, refOff + i * 8 + 4);
                    if (dataOff + psize > pos + size) {
                        ok = false;
                        break;
                    }
                    LogPage pg;
                    pg.offset = poff;
                    pg.size = psize;
                    pg.dataPos = dataOff;
                    pg.src = &lb;
                    e.pages.push_back(pg);
                    dataOff += psize;
                }
                if (ok && !e.pages.empty()) out.push_back(std::move(e));
            }
            pos += size;
        }
    }
    catch (...) {}
}

bool del_reg_keys::examineIfeoNk(size_t off, Finding& f, bool& hasDebugger) {
    try {
        hasDebugger = false;
        NkInfo nk = parseNk(off);
        if (!nk.ok) return false;
        NkInfo parent = parseNk(cellDataOffset(nk.parentOff));
        if (!parent.ok ||
            !iEqualsAsciiW(parent.name, xorstr_(L"Image File Execution Options")))
            return false;

        f.folder = wideToUtf8(nk.name);
        f.ts = formatLocalTime(nk.lastWrite);

        std::optional<std::string> raw = findDebuggerValue(nk);
        if (raw) {
            hasDebugger = true;
            f.debugger = trim(*raw);
        }
        return true;
    }
    catch (...) { return false; }
}

bool del_reg_keys::loadFile(const std::wstring& path, std::vector<uint8_t>& out) {
    try {
        std::ifstream in(path, std::ios::binary);
        if (!in) return false;
        out.assign((std::istreambuf_iterator<char>(in)),
                   std::istreambuf_iterator<char>());
        return true;
    }
    catch (...) { return false; }
}

void del_reg_keys::analyze(const std::wstring& hivePath, const std::wstring& log1Path,
                           const std::wstring& log2Path,
                           std::vector<Finding>& ifeoResults,
                           std::vector<std::string>& bamNames) {
    try {
        if (!loadFile(hivePath, s_hive)) return;
        if (s_hive.size() < kHbinsBase + 0x20 ||
            !(s_hive[0] == 'r' && s_hive[1] == 'e' && s_hive[2] == 'g' &&
              s_hive[3] == 'f'))
            return;

        std::vector<uint8_t> log1, log2;
        std::vector<LogEntry> entries;
        if (loadFile(log1Path, log1)) parseLogEntries(log1, entries);
        if (loadFile(log2Path, log2)) parseLogEntries(log2, entries);
        std::sort(entries.begin(), entries.end(),
                  [](const LogEntry& a, const LogEntry& b) { return a.seq < b.seq; });

        std::vector<Finding> ifeoLogHits;
        std::set<std::string> seenHistIfeo;
        std::vector<std::string> bamSeen;
        std::set<std::string> bamSeenLower;
        for (const LogEntry& e : entries) {
            for (const LogPage& pg : e.pages) {
                size_t target = kHbinsBase + pg.offset;
                if (target + pg.size > s_hive.size())
                    s_hive.resize(target + pg.size, 0);
                if (pg.src && pg.dataPos + pg.size <= pg.src->size())
                    std::memcpy(&s_hive[target], &(*pg.src)[pg.dataPos], pg.size);
            }
            for (const LogPage& pg : e.pages) {
                size_t start = kHbinsBase + pg.offset;
                size_t end = start + pg.size;
                if (end > s_hive.size()) end = s_hive.size();
                for (size_t off = start; off + 2 <= end; ++off) {
                    uint8_t a = s_hive[off], b = s_hive[off + 1];
                    if (a == 'n' && b == 'k') {
                        Finding f;
                        bool hasDbg = false;
                        if (examineIfeoNk(off, f, hasDbg) && hasDbg) {
                            std::string key = toLowerAscii(f.folder) + xorstr_("|") + f.debugger;
                            if (seenHistIfeo.insert(key).second) ifeoLogHits.push_back(f);
                        }
                    }
                    else if (a == 'v' && b == 'k') {
                        std::string name;
                        if (isBamLikeVk(off, name) &&
                            bamSeenLower.insert(toLowerAscii(name)).second)
                            bamSeen.push_back(name);
                    }
                }
            }
        }

        std::vector<bool> allocated = markAllocatedCells();

        std::set<std::string> ifeoLive;
        std::set<std::string> seenIfeo;
        bool hasBamKey = false;
        std::set<std::string> bamLiveLower;
        std::vector<std::string> bamFree;
        std::set<std::string> bamFreeLower;

        for (size_t off = kHbinsBase; off + 2 <= s_hive.size(); ++off) {
            uint8_t a = s_hive[off], b = s_hive[off + 1];
            bool alloc = (off < allocated.size()) && allocated[off];

            if (a == 'n' && b == 'k') {
                NkInfo nk = parseNk(off);
                if (!nk.ok) continue;

                if (alloc && iEqualsAsciiW(nk.name, xorstr_(L"bam"))) {
                    NkInfo p = parseNk(cellDataOffset(nk.parentOff));
                    if (p.ok && iEqualsAsciiW(p.name, xorstr_(L"Services"))) hasBamKey = true;
                }

                NkInfo parent = parseNk(cellDataOffset(nk.parentOff));
                if (!parent.ok ||
                    !iEqualsAsciiW(parent.name, xorstr_(L"Image File Execution Options")))
                    continue;

                if (alloc) {
                    ifeoLive.insert(toLowerAscii(wideToUtf8(nk.name)));
                }
                else {
                    Finding f;
                    bool hasDbg = false;
                    if (examineIfeoNk(off, f, hasDbg) && hasDbg) {
                        std::string key = toLowerAscii(f.folder) + xorstr_("|") + f.debugger;
                        if (seenIfeo.insert(key).second) ifeoResults.push_back(f);
                    }
                }
            }
            else if (a == 'v' && b == 'k') {
                std::string name;
                if (!isBamLikeVk(off, name)) continue;
                std::string lo = toLowerAscii(name);
                if (alloc)
                    bamLiveLower.insert(lo);
                else if (bamFreeLower.insert(lo).second)
                    bamFree.push_back(name);
            }
        }

        for (Finding& f : ifeoLogHits) {
            if (ifeoLive.count(toLowerAscii(f.folder))) continue;
            std::string key = toLowerAscii(f.folder) + xorstr_("|") + f.debugger;
            if (seenIfeo.insert(key).second) ifeoResults.push_back(f);
        }

        bool bamPresent = hasBamKey || !bamLiveLower.empty();
        if (bamPresent) {
            std::set<std::string> outLower;
            auto consider = [&](const std::string& name) {
                std::string lo = toLowerAscii(name);
                if (bamLiveLower.count(lo)) return;
                if (outLower.insert(lo).second) bamNames.push_back(name);
            };
            for (const std::string& n : bamFree) consider(n);
            for (const std::string& n : bamSeen) consider(n);
        }
    }
    catch (...) {}
}

void del_reg_keys::emit(const std::vector<Finding>& ifeoResults,
                        const std::vector<std::string>& bamNames) {
    try {
        std::set<std::string> seenIfeo;
        for (const Finding& f : ifeoResults) {
            std::string key = toLowerAscii(f.folder) + xorstr_("|") + f.debugger;
            if (!seenIfeo.insert(key).second) continue;
            std::string ts = f.ts.empty() ? std::string(xorstr_("N/A")) : f.ts;
            LOG(WARNING, ts) << xorstr_("IFEO Bypass Found (IFEO Key Deleted):C:\\Windows\\System32\\")
                             << f.folder << xorstr_(" | ") << f.debugger;
        }
        std::set<std::string> seenBam;
        for (const std::string& name : bamNames) {
            if (!seenBam.insert(toLowerAscii(name)).second) continue;
            LOG(WARNING, xorstr_("N/A")) << xorstr_("Deleted BAM Key:") << name;
        }
    }
    catch (...) {}
}

bool del_reg_keys::isElevated() {
    try {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        TOKEN_ELEVATION elev{};
        DWORD sz = 0;
        bool ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev),
                                      &sz) &&
                  elev.TokenIsElevated != 0;
        CloseHandle(token);
        return ok;
    }
    catch (...) { return false; }
}

bool del_reg_keys::acquireHives(std::wstring& outSoftware, std::wstring& outSystem) {
    try {
        outSoftware.clear();
        outSystem.clear();

        wchar_t tempDir[MAX_PATH] = { 0 };
        if (!GetTempPathW(MAX_PATH, tempDir)) return false;
        DWORD pid = GetCurrentProcessId();
        std::wstring destSw =
            std::wstring(tempDir) + xorstr_(L"delregkeys_SOFTWARE_") + std::to_wstring(pid) + xorstr_(L".hiv");
        std::wstring destSys =
            std::wstring(tempDir) + xorstr_(L"delregkeys_SYSTEM_") + std::to_wstring(pid) + xorstr_(L".hiv");

        auto cleanup = [](const std::wstring& d) {
            DeleteFileW(d.c_str());
            DeleteFileW((d + xorstr_(L".LOG1")).c_str());
            DeleteFileW((d + xorstr_(L".LOG2")).c_str());
        };
        cleanup(destSw);
        cleanup(destSys);

        wchar_t windirBuf[MAX_PATH] = { 0 };
        UINT wdlen = GetSystemWindowsDirectoryW(windirBuf, MAX_PATH);
        if (wdlen == 0 || wdlen >= MAX_PATH) return false;
        std::wstring windir(windirBuf);
        if (windir.size() < 3 || windir[1] != L':') return false;
        std::wstring systemDrive = windir.substr(0, 3);
        std::wstring windowsSub  = windir.substr(2);
        while (!windowsSub.empty() && windowsSub.front() == L'\\')
            windowsSub.erase(0, 1);

        bool comInitialized = false;
        IWbemLocator*         pLoc         = nullptr;
        IWbemServices*        pSvc         = nullptr;
        IWbemClassObject*     pClass       = nullptr;
        IWbemClassObject*     pInParamsDef = nullptr;
        IWbemClassObject*     pInParams    = nullptr;
        IWbemClassObject*     pOutParams   = nullptr;
        IEnumWbemClassObject* pEnum        = nullptr;
        IWbemClassObject*     pShadow      = nullptr;
        BSTR                  shadowPath   = nullptr;

        auto collect_hives = [&]() -> bool {
            HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
            if (hr == RPC_E_CHANGED_MODE)
                hr = CoInitializeEx(0, COINIT_APARTMENTTHREADED);
            if (FAILED(hr) && hr != S_FALSE) return false;
            comInitialized = true;

            hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                nullptr, EOAC_NONE, nullptr);
            if (FAILED(hr) && hr != RPC_E_TOO_LATE) return false;

            hr = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                IID_IWbemLocator, (LPVOID*)&pLoc);
            if (FAILED(hr) || !pLoc) return false;

            _bstr_t ns(xorstr_(L"ROOT\\CIMV2"));
            hr = pLoc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &pSvc);
            if (FAILED(hr) || !pSvc) return false;

            CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

            _bstr_t clsName(xorstr_(L"Win32_ShadowCopy"));

#pragma push_macro("GetObject")
#undef GetObject
            hr = pSvc->GetObject(clsName, 0, nullptr, &pClass, nullptr);
#pragma pop_macro("GetObject")
            if (FAILED(hr) || !pClass) return false;

            _bstr_t createName(xorstr_(L"Create"));
            if (FAILED(pClass->GetMethod(createName, 0, &pInParamsDef, nullptr)) || !pInParamsDef) return false;
            if (FAILED(pInParamsDef->SpawnInstance(0, &pInParams)) || !pInParams) return false;

            VARIANT v;
            VariantInit(&v);
            v.vt = VT_BSTR;
            v.bstrVal = SysAllocString(systemDrive.c_str());
            HRESULT ph = pInParams->Put(xorstr_(L"Volume"), 0, &v, 0);
            VariantClear(&v);
            if (FAILED(ph)) return false;

            VariantInit(&v);
            v.vt = VT_BSTR;
            v.bstrVal = SysAllocString(xorstr_(L"ClientAccessible"));
            ph = pInParams->Put(xorstr_(L"Context"), 0, &v, 0);
            VariantClear(&v);
            if (FAILED(ph)) return false;

            hr = pSvc->ExecMethod(clsName, createName, 0, nullptr, pInParams, &pOutParams, nullptr);
            if (FAILED(hr) || !pOutParams) return false;

            DWORD returnValue = ~0u;
            std::wstring shadowId;

            VariantInit(&v);
            if (SUCCEEDED(pOutParams->Get(xorstr_(L"ReturnValue"), 0, &v, nullptr, nullptr))) {
                if      (v.vt == VT_I4)  returnValue = (DWORD)v.lVal;
                else if (v.vt == VT_UI4) returnValue = v.ulVal;
                else if (v.vt == VT_I2)  returnValue = (DWORD)v.iVal;
            }
            VariantClear(&v);
            if (returnValue != 0) return false;

            VariantInit(&v);
            if (SUCCEEDED(pOutParams->Get(xorstr_(L"ShadowID"), 0, &v, nullptr, nullptr)) &&
                v.vt == VT_BSTR && v.bstrVal)
                shadowId.assign(v.bstrVal, SysStringLen(v.bstrVal));
            VariantClear(&v);
            if (shadowId.empty()) return false;

            std::wstring queryStr =
                std::wstring(xorstr_(L"SELECT * FROM Win32_ShadowCopy WHERE ID='")) +
                shadowId + xorstr_(L"'");
            _bstr_t qLang(xorstr_(L"WQL"));
            _bstr_t qText(queryStr.c_str());
            hr = pSvc->ExecQuery(qLang, qText,
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnum);
            if (FAILED(hr) || !pEnum) return false;

            ULONG returned = 0;
            hr = pEnum->Next(WBEM_INFINITE, 1, &pShadow, &returned);
            if (FAILED(hr) || returned == 0 || !pShadow) return false;

            std::wstring deviceObject;

            VariantInit(&v);
            if (SUCCEEDED(pShadow->Get(xorstr_(L"DeviceObject"), 0, &v, nullptr, nullptr)) &&
                v.vt == VT_BSTR && v.bstrVal)
                deviceObject.assign(v.bstrVal, SysStringLen(v.bstrVal));
            VariantClear(&v);

            VariantInit(&v);
            if (SUCCEEDED(pShadow->Get(xorstr_(L"__PATH"), 0, &v, nullptr, nullptr)) &&
                v.vt == VT_BSTR && v.bstrVal)
                shadowPath = SysAllocString(v.bstrVal);
            VariantClear(&v);

            if (deviceObject.empty()) return false;

            std::wstring configDir =
                deviceObject + L'\\' + windowsSub + xorstr_(L"\\System32\\config\\");
            auto grab = [&](const wchar_t* name, const std::wstring& dest) {
                std::wstring src = configDir + name;
                CopyFileW(src.c_str(), dest.c_str(), FALSE);
                CopyFileW((src + xorstr_(L".LOG1")).c_str(), (dest + xorstr_(L".LOG1")).c_str(), FALSE);
                CopyFileW((src + xorstr_(L".LOG2")).c_str(), (dest + xorstr_(L".LOG2")).c_str(), FALSE);
            };
            grab(xorstr_(L"SOFTWARE"), destSw);
            grab(xorstr_(L"SYSTEM"),   destSys);
            return true;
        };

        try { collect_hives(); }
        catch (...) {}

        if (pSvc && shadowPath) {
            try { pSvc->DeleteInstance(shadowPath, 0, nullptr, nullptr); } catch (...) {}
        }
        if (shadowPath)     { try { SysFreeString(shadowPath); }  catch (...) {} }
        if (pShadow)        { try { pShadow->Release(); }         catch (...) {} }
        if (pEnum)          { try { pEnum->Release(); }           catch (...) {} }
        if (pOutParams)     { try { pOutParams->Release(); }      catch (...) {} }
        if (pInParams)      { try { pInParams->Release(); }       catch (...) {} }
        if (pInParamsDef)   { try { pInParamsDef->Release(); }    catch (...) {} }
        if (pClass)         { try { pClass->Release(); }          catch (...) {} }
        if (pSvc)           { try { pSvc->Release(); }            catch (...) {} }
        if (pLoc)           { try { pLoc->Release(); }            catch (...) {} }
        if (comInitialized) { try { CoUninitialize(); }           catch (...) {} }

        auto present = [](const std::wstring& d) {
            DWORD attr = GetFileAttributesW(d.c_str());
            return (attr != INVALID_FILE_ATTRIBUTES) &&
                   !(attr & FILE_ATTRIBUTE_DIRECTORY);
        };

        bool haveSw = present(destSw);
        bool haveSys = present(destSys);
        if (!haveSw) cleanup(destSw);
        if (!haveSys) cleanup(destSys);
        if (haveSw) outSoftware = destSw;
        if (haveSys) outSystem = destSys;

        return haveSw || haveSys;
    }
    catch (...) { return false; }
}

void del_reg_keys::start_deleted_reg_keys_check() {
    try {
        if (!isElevated()) return;

        std::wstring acquiredSw, acquiredSys;
        if (!acquireHives(acquiredSw, acquiredSys)) return;

        std::vector<Finding> ifeoResults;
        std::vector<std::string> bamNames;

        if (!acquiredSw.empty())
            analyze(acquiredSw, acquiredSw + xorstr_(L".LOG1"), acquiredSw + xorstr_(L".LOG2"),
                    ifeoResults, bamNames);
        if (!acquiredSys.empty())
            analyze(acquiredSys, acquiredSys + xorstr_(L".LOG1"), acquiredSys + xorstr_(L".LOG2"),
                    ifeoResults, bamNames);

        emit(ifeoResults, bamNames);

        auto cleanup = [](const std::wstring& d) {
            if (d.empty()) return;
            DeleteFileW(d.c_str());
            DeleteFileW((d + xorstr_(L".LOG1")).c_str());
            DeleteFileW((d + xorstr_(L".LOG2")).c_str());
        };
        cleanup(acquiredSw);
        cleanup(acquiredSys);

        s_hive.clear();
        s_hive.shrink_to_fit();
    }
    catch (...) {}
}
