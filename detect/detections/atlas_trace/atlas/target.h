#pragma once
#include "common.h"

namespace atlas {

enum class Trust {
    Unknown,
    PathTrusted,
    Signed,
    TrustedVendor,
};

const char* TrustName(Trust t);

struct Section {
    std::string name;
    uint64_t    rva  = 0;
    uint64_t    size = 0;
    DWORD       characteristics = 0;
    bool Executable() const { return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0; }
    bool Writable()   const { return (characteristics & IMAGE_SCN_MEM_WRITE) != 0; }
};

struct Module {
    std::wstring path;
    std::wstring name;
    uint64_t     base = 0;
    uint64_t     size = 0;
    bool         inLoaderList = false;
    bool         backedByFile  = false;
    Trust        trust = Trust::Unknown;
    std::string  signer;
    std::vector<Section> sections;

    bool Contains(uint64_t addr) const { return addr >= base && addr < base + size; }
    const Section* SectionOf(uint64_t addr) const;
};

struct Region {
    uint64_t base   = 0;
    uint64_t size   = 0;
    uint64_t allocBase = 0;
    DWORD    state  = 0;
    DWORD    protect = 0;
    DWORD    allocProtect = 0;
    DWORD    type   = 0;
    std::wstring mappedFile;

    bool Executable() const {
        return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    bool Writable() const {
        return (protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE |
                           PAGE_EXECUTE_WRITECOPY)) != 0;
    }
    bool Readable() const {
        return state == MEM_COMMIT && (protect & PAGE_NOACCESS) == 0 &&
               (protect & PAGE_GUARD) == 0;
    }
    bool Contains(uint64_t a) const { return a >= base && a < base + size; }
};

struct Reservation {
    uint64_t base = 0;
    uint64_t totalSize = 0;
    uint64_t committedExec = 0;
    uint64_t committedTotal = 0;
    bool     hasReserve = false;
    DWORD    type = 0;
    std::vector<const Region*> parts;
};

struct ThreadInfo {
    DWORD    tid = 0;
    uint64_t startAddress = 0;
    uint64_t tebAddress   = 0;
    FILETIME createTime{};
    bool     hiddenFromDebugger = false;
    bool     queryFailed = false;
};

enum class Launcher { Unknown, Vanilla, Forge, Optifine, Lunar, Badlion, Feather, Prism, Modrinth, Labymod };
const char* LauncherName(Launcher l);

class Target {
public:
    ~Target();

    bool Open(DWORD pid, std::string* err);
    void Close();

    DWORD  pid()    const { return pid_; }
    HANDLE handle() const { return h_; }
    const std::wstring& imagePath() const { return imagePath_; }
    const std::wstring& commandLine() const { return cmdLine_; }
    const std::wstring& currentDir()  const { return curDir_; }
    const std::vector<std::wstring>& environment() const { return env_; }
    std::wstring EnvValue(const wchar_t* name) const;
    Launcher launcher() const { return launcher_; }
    const std::string& javaVersion() const { return javaVersion_; }
    const std::string& gameVersion() const { return gameVersion_; }
    bool   is64()    const { return is64_; }
    size_t ptrSize() const { return is64_ ? 8u : 4u; }

    const std::vector<Region>& regions() const { return regions_; }
    const std::vector<Module>& modules() const { return modules_; }
    const std::vector<ThreadInfo>& threads() const { return threads_; }
    const std::vector<Reservation>& reservations() const { return reservations_; }

    const Module*  ModuleAt(uint64_t addr) const;
    const Module*  ModuleByName(const wchar_t* name) const;
    const Region*  RegionAt(uint64_t addr) const;
    const Reservation* ReservationAt(uint64_t addr) const;

    bool Read(uint64_t addr, void* buf, size_t n) const;
    bool ReadRegion(const Region& r, std::vector<uint8_t>& out, size_t cap) const;
    std::string ReadCString(uint64_t addr, size_t maxLen = 512) const;

    void MarkCodeCache(uint64_t allocBase) { codeCacheBases_.insert(allocBase); }
    bool IsCodeCache(uint64_t addr) const;

    bool IsUnbacked(uint64_t addr) const;

    const std::vector<std::wstring>& classpath() const { return classpath_; }
    const std::vector<std::wstring>& agentArgs() const { return agentArgs_; }

    bool RefreshRegions();
    bool RefreshThreads();

private:
    bool ReadPebStrings();
    bool EnumModules();
    bool EnumRegions();
    bool EnumThreads();
    void BuildReservations();
    void IdentifyLauncher();
    void IdentifyGameVersion();
    void LoadSections(Module& m);

    DWORD  pid_ = 0;
    HANDLE h_   = nullptr;
    bool   is64_ = true;
    std::wstring imagePath_, cmdLine_, curDir_;
    std::string  javaVersion_;
    std::string  gameVersion_;
    Launcher     launcher_ = Launcher::Unknown;
    std::vector<Region>      regions_;
    std::vector<Module>      modules_;
    std::vector<ThreadInfo>  threads_;
    std::vector<Reservation> reservations_;
    std::vector<std::wstring> env_;
    std::vector<std::wstring> classpath_;
    std::vector<std::wstring> agentArgs_;
    std::set<uint64_t>       codeCacheBases_;
};

std::vector<DWORD> FindMinecraftProcesses(std::string* note);

}
