#include "c_windb_urls.h"

namespace {

class AhoCorasick {
public:
    void Build(const std::vector<std::string>& patterns) noexcept {
        try {
            nodes_.clear();
            AddNode();
            for (int32_t p = 0; p < static_cast<int32_t>(patterns.size()); ++p) {
                int32_t cur = 0;
                for (unsigned char c : patterns[p]) {
                    if (nodes_[cur].next[c] < 0) {
                        nodes_[cur].next[c] = AddNode();
                    }
                    cur = nodes_[cur].next[c];
                }
                if (nodes_[cur].out < 0) nodes_[cur].out = p;
            }
            std::vector<int32_t> q;
            q.reserve(nodes_.size());
            for (int c = 0; c < 256; ++c) {
                int32_t v = nodes_[0].next[c];
                if (v > 0) { nodes_[v].fail = 0; q.push_back(v); }
                else       { nodes_[0].next[c] = 0; }
            }
            for (size_t i = 0; i < q.size(); ++i) {
                int32_t u = q[i];
                for (int c = 0; c < 256; ++c) {
                    int32_t v = nodes_[u].next[c];
                    if (v > 0) {
                        int32_t f = nodes_[nodes_[u].fail].next[c];
                        nodes_[v].fail = f;
                        nodes_[v].out_link = (nodes_[f].out >= 0) ? f : nodes_[f].out_link;
                        q.push_back(v);
                    } else {
                        nodes_[u].next[c] = nodes_[nodes_[u].fail].next[c];
                    }
                }
            }
        } catch (...) {}
    }

    template <typename Fn>
    void Scan(const char* data, size_t n, Fn&& cb) const noexcept {
        try {
            if (nodes_.empty()) return;
            const Node* nodes = nodes_.data();
            int32_t cur = 0;
            for (size_t i = 0; i < n; ++i) {
                cur = nodes[cur].next[static_cast<unsigned char>(data[i])];
                int32_t o = (nodes[cur].out >= 0) ? cur : nodes[cur].out_link;
                while (o >= 0) {
                    cb(nodes[o].out);
                    o = nodes[o].out_link;
                }
            }
        } catch (...) {}
    }

private:
    struct Node {
        int32_t next[256];
        int32_t fail = 0;
        int32_t out = -1;
        int32_t out_link = -1;
    };
    std::vector<Node> nodes_;

    int32_t AddNode() noexcept {
        try {
            Node n{};
            for (int i = 0; i < 256; ++i) n.next[i] = -1;
            nodes_.push_back(n);
            return static_cast<int32_t>(nodes_.size()) - 1;
        } catch (...) { return -1; }
    }
};

inline void to_lower_ascii(std::string& s) noexcept {
    try {
        for (auto& c : s) {
            unsigned char u = static_cast<unsigned char>(c);
            if (u >= 'A' && u <= 'Z') c = static_cast<char>(u | 0x20);
        }
    } catch (...) {}
}

bool TryCopyDb(const std::wstring& source, const std::wstring& dest) noexcept {
    try {
        HANDLE hSrc = CreateFileW(
            source.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (hSrc == INVALID_HANDLE_VALUE) return false;

        HANDLE hDst = CreateFileW(
            dest.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_ALWAYS,
            FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (hDst == INVALID_HANDLE_VALUE) {
            CloseHandle(hSrc);
            return false;
        }

        constexpr DWORD kBuf = 1u << 20;
        std::vector<uint8_t> buf(kBuf);
        DWORD got = 0;
        while (ReadFile(hSrc, buf.data(), kBuf, &got, nullptr) && got > 0) {
            DWORD written = 0;
            if (!WriteFile(hDst, buf.data(), got, &written, nullptr) || written != got) {
                CloseHandle(hDst);
                CloseHandle(hSrc);
                DeleteFileW(dest.c_str());
                return false;
            }
        }
        CloseHandle(hDst);
        CloseHandle(hSrc);
        return true;
    } catch (...) { return false; }
}

std::wstring MakeRandomTempPath() noexcept {
    try {
        wchar_t tempDir[MAX_PATH];
        DWORD n = GetTempPathW(MAX_PATH, tempDir);
        if (n == 0 || n >= MAX_PATH) return {};

        std::random_device rd;
        std::seed_seq seed{ rd(), rd(), rd(), rd(),
                            static_cast<unsigned>(GetTickCount64() & 0xFFFFFFFFu) };
        std::mt19937_64 rng(seed);
        std::uniform_int_distribution<int> dist(0, 35);
        const std::string alphabet = xorstr_("0123456789abcdefghijklmnopqrstuvwxyz");

        std::wstring out(tempDir);
        for (int i = 0; i < 16; ++i)
            out.push_back(static_cast<wchar_t>(alphabet[static_cast<size_t>(dist(rng))]));
        out.append(xorstr_(L".tmp"));
        return out;
    } catch (...) { return {}; }
}

void TunePragmas(sqlite3* db) noexcept {
    try {
        sqlite3_exec(db, xorstr_("PRAGMA query_only = 1;"),         nullptr, nullptr, nullptr);
        sqlite3_exec(db, xorstr_("PRAGMA temp_store = MEMORY;"),    nullptr, nullptr, nullptr);
        sqlite3_exec(db, xorstr_("PRAGMA cache_size = -65536;"),    nullptr, nullptr, nullptr);
        sqlite3_exec(db, xorstr_("PRAGMA mmap_size  = 268435456;"), nullptr, nullptr, nullptr);
        sqlite3_exec(db, xorstr_("PRAGMA synchronous = OFF;"),      nullptr, nullptr, nullptr);
    } catch (...) {}
}

bool TableExists(sqlite3* db, const std::string& name) noexcept {
    try {
        sqlite3_stmt* st = nullptr;
        std::string sql = xorstr_("SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1;");
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return false;
        sqlite3_bind_text(st, 1, name.c_str(), -1, SQLITE_TRANSIENT);
        bool exists = (sqlite3_step(st) == SQLITE_ROW);
        sqlite3_finalize(st);
        return exists;
    } catch (...) { return false; }
}

std::vector<std::string> SniffStringColumns(sqlite3* db, const std::string& table) noexcept {
    std::vector<std::string> out;
    try {
        std::string sql = xorstr_("PRAGMA table_info(\"");
        sql += table;
        sql += xorstr_("\");");
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return out;
        while (sqlite3_step(st) == SQLITE_ROW) {
            const unsigned char* nm = sqlite3_column_text(st, 1);
            const unsigned char* ty = sqlite3_column_text(st, 2);
            if (!nm) continue;
            std::string type = ty ? reinterpret_cast<const char*>(ty) : std::string();
            std::string typel = type;
            for (auto& c : typel) {
                unsigned char u = static_cast<unsigned char>(c);
                if (u >= 'a' && u <= 'z') c = static_cast<char>(u & 0xDF);
            }
            const bool wanted = type.empty() ||
                                typel.find(xorstr_("TEXT"))   != std::string::npos ||
                                typel.find(xorstr_("CLOB"))   != std::string::npos ||
                                typel.find(xorstr_("BLOB"))   != std::string::npos ||
                                typel.find(xorstr_("CHAR"))   != std::string::npos ||
                                typel.find(xorstr_("STRING")) != std::string::npos;
            if (!wanted) continue;
            std::string col = xorstr_("\"");
            col.append(reinterpret_cast<const char*>(nm));
            col.append(xorstr_("\""));
            out.push_back(std::move(col));
        }
        sqlite3_finalize(st);
    } catch (...) {}
    return out;
}

bool QueryWorkIdRange(sqlite3* db, const std::string& table, int64_t& lo, int64_t& hi) noexcept {
    try {
        lo = 0; hi = -1;
        std::string sql = xorstr_("SELECT MIN(WorkId), MAX(WorkId) FROM \"");
        sql += table;
        sql += xorstr_("\";");
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) return false;
        if (sqlite3_step(st) == SQLITE_ROW) {
            if (sqlite3_column_type(st, 0) != SQLITE_NULL) lo = sqlite3_column_int64(st, 0);
            if (sqlite3_column_type(st, 1) != SQLITE_NULL) hi = sqlite3_column_int64(st, 1);
        }
        sqlite3_finalize(st);
        return hi >= lo;
    } catch (...) { return false; }
}

constexpr size_t kMaxLogCellBytes = 4096;

void ScanRange(const std::wstring& dbPathW,
               const std::string& selectList,
               const std::string& table,
               int64_t lo,
               int64_t hi,
               const AhoCorasick& ac,
               const std::vector<std::vector<std::string>>& labelsPerPattern,
               size_t patternCount) noexcept
{
    try {
        std::string utf8;
        int needed = WideCharToMultiByte(CP_UTF8, 0, dbPathW.c_str(), -1,
                                         nullptr, 0, nullptr, nullptr);
        if (needed > 1) {
            utf8.assign(static_cast<size_t>(needed - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, dbPathW.c_str(), -1,
                                utf8.data(), needed, nullptr, nullptr);
        }
        if (utf8.empty()) return;

        sqlite3* db = nullptr;
        if (sqlite3_open_v2(utf8.c_str(), &db,
                            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                            nullptr) != SQLITE_OK) {
            if (db) sqlite3_close(db);
            return;
        }
        TunePragmas(db);

        std::string sql = xorstr_("SELECT ");
        sql += selectList;
        sql += xorstr_(" FROM \"");
        sql += table;
        sql += xorstr_("\" WHERE WorkId BETWEEN ? AND ?;");

        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            return;
        }
        sqlite3_bind_int64(st, 1, lo);
        sqlite3_bind_int64(st, 2, hi);

        std::string lower;
        std::string squeeze;
        std::vector<uint8_t> hitsThisCell(patternCount, 0);
        std::vector<int32_t> hitList;
        hitList.reserve(8);

        while (sqlite3_step(st) == SQLITE_ROW) {
            const int colCount = sqlite3_column_count(st);
            for (int i = 0; i < colCount; ++i) {
                const int t = sqlite3_column_type(st, i);
                if (t != SQLITE_TEXT && t != SQLITE_BLOB) continue;

                const uint8_t* bytes = nullptr;
                int bytesLen = 0;
                if (t == SQLITE_TEXT) {
                    bytes    = sqlite3_column_text(st, i);
                    bytesLen = sqlite3_column_bytes(st, i);
                } else {
                    bytes    = static_cast<const uint8_t*>(sqlite3_column_blob(st, i));
                    bytesLen = sqlite3_column_bytes(st, i);
                }
                if (!bytes || bytesLen <= 0) continue;

                lower.assign(reinterpret_cast<const char*>(bytes),
                             static_cast<size_t>(bytesLen));
                to_lower_ascii(lower);

                hitList.clear();
                ac.Scan(lower.data(), lower.size(),
                        [&](int32_t pat) {
                            if (!hitsThisCell[pat]) {
                                hitsThisCell[pat] = 1;
                                hitList.push_back(pat);
                            }
                        });

                if (t == SQLITE_BLOB && bytesLen >= 4) {
                    const size_t nProbe = std::min<size_t>(static_cast<size_t>(bytesLen), 64u);
                    size_t zeros = 0, total = 0;
                    for (size_t k = 1; k < nProbe; k += 2) {
                        if (bytes[k] == 0) ++zeros;
                        ++total;
                    }
                    if (total > 0 && zeros * 4 >= total * 3) {
                        const size_t squeezedLen = static_cast<size_t>(bytesLen) / 2u;
                        squeeze.resize(squeezedLen);
                        for (size_t k = 0; k < squeezedLen; ++k)
                            squeeze[k] = static_cast<char>(bytes[2 * k]);
                        to_lower_ascii(squeeze);
                        ac.Scan(squeeze.data(), squeeze.size(),
                                [&](int32_t pat) {
                                    if (!hitsThisCell[pat]) {
                                        hitsThisCell[pat] = 1;
                                        hitList.push_back(pat);
                                    }
                                });
                    }
                }

                if (!hitList.empty()) {
                    const size_t previewLen = std::min<size_t>(
                        static_cast<size_t>(bytesLen), kMaxLogCellBytes);
                    std::string preview(reinterpret_cast<const char*>(bytes), previewLen);
                    for (int32_t pat : hitList) {
                        for (const auto& label : labelsPerPattern[pat]) {
                            try {
                                LOG(WARNING, xorstr_("N/A")) << label << xorstr_(":") << preview;
                            } catch (...) {}
                        }
                        hitsThisCell[pat] = 0;
                    }
                }
            }
        }

        sqlite3_finalize(st);
        sqlite3_close(db);
    } catch (...) {}
}

const std::vector<std::pair<std::string, std::string>>& WindbKeywords() noexcept {
    static const std::vector<std::pair<std::string, std::string>> kKeywords = []() {
        std::vector<std::pair<std::string, std::string>> v;
        try {
            v = {

        #ifdef DETECT_FIVEM

        {xorstr_("skript.gg"), xorstr_("Found Trace of Skript Website On PC")},
        {xorstr_("tzproject.com"), xorstr_("Found Trace of TZ Project Website On PC")},
        {xorstr_("hxcheats.tech"), xorstr_("Found Trace of Hx Cheats Website On PC")},
        {xorstr_("gosth.gg"), xorstr_("Found Trace of Gosth Website On PC")},
        {xorstr_("ghostesportpanel.com"), xorstr_("Found Trace of Gosth Website On PC")},
        {xorstr_("eulencheats.com"), xorstr_("Found Trace of Eulen Website On PC")},
        {xorstr_("eulen.cc"), xorstr_("Found Trace of Eulen Website On PC")},
        {xorstr_("luamenu.xyz"), xorstr_("Found Trace of Lua (RedEngine) Website On PC")},
        {xorstr_("redengine.eu"), xorstr_("Found Trace of RedEngine Website On PC")},
        {xorstr_("redengine.net"), xorstr_("Found Trace of RedEngine Website On PC")},
        {xorstr_("susano.re"), xorstr_("Found Trace of Susano Website On PC")},
        {xorstr_("machocheats.com"), xorstr_("Found Trace of Macho Cheats Website On PC")},
        {xorstr_("88-cheats.xyz"), xorstr_("Found Trace of 88 Cheats Website On PC")},
        {xorstr_("testo.gg"), xorstr_("Found Trace of Testo Cheats Website On PC")},
        {xorstr_("blackout.wtf"), xorstr_("Found Trace of Blackout Cheats Website On PC")},
        {xorstr_("monstermenu.cc"), xorstr_("Found Trace of Monster Menu Website On PC")},
        {xorstr_("9zproject.xyz"), xorstr_("Found Trace of 9z Project Website On PC")},
        {xorstr_("sergiu.pro"), xorstr_("Found Trace of Spotless Website On PC")},
        {xorstr_("projectdow.com"), xorstr_("Found Trace of Dow Website On PC")},
        {xorstr_("api.shilav2.shop"), xorstr_("Found Trace of Wexless Website On PC")},
        {xorstr_("193.23.160.168"), xorstr_("Found Trace of Signer Website On PC")},
        {xorstr_("orbit.signer.cc"), xorstr_("Found Trace of Signer Website On PC")},
        {xorstr_("signer.cc"), xorstr_("Found Trace of Signer Website On PC")},
        {xorstr_("bypass.fun"), xorstr_("Found Trace of Bypass.Fun Website On PC")},
        {xorstr_("keyser-lts.com"), xorstr_("Found Trace of Keyser Website On PC")},
        {xorstr_("keyser.gg"), xorstr_("Found Trace of Keyser Website On PC")},
        {xorstr_("185.236.228.154"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("flkstore.com"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("flk-uhq.xyz"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("5.206.224.37"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("bebetter-fivem.space"), xorstr_("Found Trace of Be-better Website On PC")},
        {xorstr_("venacy.club"), xorstr_("Found Trace of Venacy Website On PC")},
        {xorstr_("antiecho.xyz"), xorstr_("Found Trace of Ant-Echo Website On PC")},
        {xorstr_("203.159.90.127"), xorstr_("Found Trace of Lethality Script Website On PC")},
        {xorstr_("leet-cheats.ru"), xorstr_("Found Trace of Leet Cheats Website On PC")},
        {xorstr_("hydrogen.ac"), xorstr_("Found Trace of Hydrogen Cheats Website On PC")},
        {xorstr_("trinitas.top"), xorstr_("Found Trace of Trinitas Cheats Website On PC")},
        {xorstr_("blurred.gg"), xorstr_("Found Trace of Blurred.gg Website On PC")},
        {xorstr_("captaindma.com"), xorstr_("Found Trace of Captain DMA Website On PC")},
        {xorstr_("pulsedma.com"), xorstr_("Found Trace of Pulse DMA Website On PC")},
        {xorstr_("makcu.com"), xorstr_("Found Trace of Makcu Website On PC")},
        {xorstr_("vanish-cheat.com"), xorstr_("Found Trace of Vanish Website On PC")},
        {xorstr_("91.218.66.77"), xorstr_("Found Trace of Forte Website On PC")},
        {xorstr_("uzuimarket.xyz"), xorstr_("Found Trace of Uzui Market Website On PC")},
        {xorstr_("spotless.gg"), xorstr_("Found Trace of Spotless Bypass Website On PC")},
        {xorstr_("traceless.wtf"), xorstr_("Found Trace of Traceless Bypass Website On PC")},
        {xorstr_("a.pomf.cat/UgdZcKh"), xorstr_("Found Trace of 9Z Bypass Website On PC")},
        {xorstr_("a.pomf.cat/glNyzpV"), xorstr_("Found Trace of 9Z Bypass Website On PC")},
        {xorstr_("serapi.mom"), xorstr_("Found Trace of Spotless/Binary Bypass Website On PC")},
        {xorstr_("freshbypass.xyz"), xorstr_("Found Trace of Fresh Bypass Website On PC")},
        {xorstr_("designcraft.xyz"), xorstr_("Found Trace of Response Bypass Website On PC")},
        {xorstr_("snowbp.xyz"), xorstr_("Found Trace of Snow Bypass Website On PC")},
        {xorstr_("club44.lol"), xorstr_("Found Trace of Club44 Bypass Website On PC")},
        {xorstr_("catatau.xyz"), xorstr_("Found Trace of XYZ DMA Website On PC")},
        {xorstr_("auis.binaryy.top"), xorstr_("Found Trace of Binary Bypass Website On PC")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co"), xorstr_("Found Trace Of Binary Bypass")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/auth-login"), xorstr_("Found Trace Of Binary Bypass Login Page")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co/functions/v1/vpn-check"), xorstr_("Found Trace Of Binary Bypass VPN Check Page")},
        {xorstr_("etezmdkyybdrsczqfjky.supabase.co/rest/v1/rpc/get_maintenance_mode"), xorstr_("Found Trace Of Binary Bypass Maintinence Page")},
        {xorstr_("serotonin.win"), xorstr_("Found Trace Of Serotonin Bypass")},
        {xorstr_("181.215.45.13"), xorstr_("Found Trace Of Club44 Bypass")},
        {xorstr_("93.127.215.67"), xorstr_("Found Trace Of Club44 Bypass")},
        {xorstr_("severance.today"), xorstr_("Found Trace Of Severance Bypass")},
        {xorstr_("gnomus.lol"), xorstr_("Found Trace Of FiveM Enjoyer")},
        {xorstr_("gnomus.lol/mefedron/ziolo/ukrainski_igraszki/"), xorstr_("Found Trace Of FiveM Enjoyer")},
        {xorstr_("pub-047df53bbd524128a2b8f1477ec0e316.r2.dev"), xorstr_("Found Trace Of Severance Bypass")},
        {xorstr_("45.156.87.118"), xorstr_("Found Trace Of Unknown Bypass")},
        {xorstr_("16.171.254.8"), xorstr_("Found Trace Of Bypass.fun Bypass")},
        {xorstr_("certificate.wtf"), xorstr_("Found Trace of certificate.wtf Website On PC")},
        {xorstr_("cosmos.pm"), xorstr_("Found Trace of Cosmos Website On PC")},
        {xorstr_("rxmenu.shop"), xorstr_("Found Trace of RX Menu Website On PC")},
        {xorstr_("omertasoftware.com"), xorstr_("Found Trace of Omerta Software Website On PC")},
        {xorstr_("xentro.xyz"), xorstr_("Found Trace of Xentro Website On PC")},
        {xorstr_("titanbypass.com"), xorstr_("Found Trace of Titan Bypass Website On PC")},
        {xorstr_("us1.phase.uno"), xorstr_("Found Trace of Phase Uno On PC")},
        {xorstr_("phase.uno"), xorstr_("Found Trace of Phase Uno On PC")},
        {xorstr_("104.21.82.227"), xorstr_("Found Trace of Phase Uno On PC")},
        {xorstr_("104.18.2.36"), xorstr_("Found Trace of Phase Uno On PC")},
        {xorstr_("wizardbypass.com"), xorstr_("Found Trace of Wizard Bypass Website On PC")},
        {xorstr_("loginlive.cloud"), xorstr_("Found Trace of Wizard Bypass On PC")},
        {xorstr_("54.39.67.23"), xorstr_("Found Trace Of Rolex Bypass")},
        {xorstr_("richh.lol"), xorstr_("Found Trace of Rolex Bypass Website On PC")},
        {xorstr_("antiscan.xyz"), xorstr_("Found Trace of Rolex Bypass Website On PC")},
        {xorstr_("evora.pw"), xorstr_("Found Trace of Evora Website On PC")},
        {xorstr_("45.143.196.213"), xorstr_("Found Trace of Bytecode Bypass On PC")},
        {xorstr_("Sirius.lv"), xorstr_("Found Trace of Sirius Bypass Website On PC")},

        #elif DETECT_MINECRAFT

        {xorstr_("drip.gg"), xorstr_("Found Trace of Drip Website On PC")},
        {xorstr_("karma.rip"), xorstr_("Found Trace of Karma Website On PC")},
        {xorstr_("bypassing.gg"), xorstr_("Found Trace of Cold Bypassing Website On PC")},
        {xorstr_("vape.gg"), xorstr_("Found Trace of Vape Website On PC")},
        {xorstr_("sunset.rip"), xorstr_("Found Trace of Sunset Website On PC")},
        {xorstr_("doomsdayclient.com"), xorstr_("Found Trace of Doomsday Website On PC")},
        {xorstr_("neverlack.in"), xorstr_("Found Trace of Drip Website On PC")},
        {xorstr_("akiraghost.com"), xorstr_("Found Trace of Akira Website On PC")},
        {xorstr_("entropy.club"), xorstr_("Found Trace of Entropy Website On PC")},
        {xorstr_("dreamclient.xyz"), xorstr_("Found Trace of Dream Website On PC")},
        {xorstr_("crypp.in"), xorstr_("Found Trace of Dream Website On PC")},
        {xorstr_("dopp.in"), xorstr_("Found Trace of Dopp Website On PC")},
        {xorstr_("slapp.in"), xorstr_("Found Trace of Slatt Website On PC")},
        {xorstr_("unicorn-hacks.net"), xorstr_("Found Trace of Unicorn Website On PC")},
        {xorstr_("prestigeclient.vip"), xorstr_("Found Trace of Prestigeclient Website On PC")},
        {xorstr_("api.prestigeclient.vip"), xorstr_("Found Trace of Prestigeclient API Website On PC")},
        {xorstr_("grimclient.eu"), xorstr_("Found Trace of Grim Website On PC")},
        {xorstr_("axen.lol"), xorstr_("Found Trace of Axen Website On PC")},
        {xorstr_("aristois.net"), xorstr_("Found Trace of Aristois Website On PC")},
        {xorstr_("catlean.su"), xorstr_("Found Trace of Catlean Website On PC")},
        {xorstr_("client-analytics.dev"), xorstr_("Found Trace of Cold Bypass Website On PC")},

        #elif DETECT_ROBLOX

        {xorstr_("robloxcheatz.com"), xorstr_("Found Trace of Robloxcheatz Website On PC")},
        {xorstr_("radiant.cc"), xorstr_("Found Trace of Radiant Website On PC")},
        {xorstr_("eternalproduct.com"), xorstr_("Found Trace of Eternal Product Website On PC")},
        {xorstr_("matrixhubs.shop"), xorstr_("Found Trace of Matrix Website On PC")},
        {xorstr_("buymtx.online"), xorstr_("Found Trace of Matrix Website On PC")},
        {xorstr_("mega.nz/folder/KehEhLzB#Cs0PiuqggmwItBIcAG4z6w"), xorstr_("Found Trace of Mooze MegaFolder On PC")},
        {xorstr_("mooze.fun"), xorstr_("Found Trace of Mooze Website On PC")},
        {xorstr_("hastebin.skyra.pw"), xorstr_("Found Trace of Config Website On PC")},
        {xorstr_("vapevoidware.xyz"), xorstr_("Found Trace of Voidware Website On PC")},
        {xorstr_("voxlis.net"), xorstr_("Found Trace of Voxlis Website On PC")},
        {xorstr_("voltbz.net"), xorstr_("Found Trace of Volt Website On PC")},
        {xorstr_("potassium.pro"), xorstr_("Found Trace of Potassium Website On PC")},
        {xorstr_("getwave.gg"), xorstr_("Found Trace of Wave Website On PC")},
        {xorstr_("z.synapse.do"), xorstr_("Found Trace of Synapse Z Website On PC")},
        {xorstr_("seliware.com"), xorstr_("Found Trace of Seliware Website On PC")},
        {xorstr_("getmadium.net"), xorstr_("Found Trace of Madium Website On PC")},
        {xorstr_("realvelocity.xyz"), xorstr_("Found Trace of Velocity Website On PC")},
        {xorstr_("sirhurt.net"), xorstr_("Found Trace of SirHurt Website On PC")},
        {xorstr_("getsolara.dev"), xorstr_("Found Trace of Solara Website On PC")},
        {xorstr_("xeno.now"), xorstr_("Found Trace of Xeno Website On PC")},
        {xorstr_("raptor.fun"), xorstr_("Found Trace of MacSploit Website On PC")},
        {xorstr_("deltaexploits.gg"), xorstr_("Found Trace of Delta Exploits Website On PC")},
        {xorstr_("getcryptic.net"), xorstr_("Found Trace of Cryptic Website On PC")},
        {xorstr_("vegax.gg"), xorstr_("Found Trace of Vega X Website On PC")},
        {xorstr_("codex.lol"), xorstr_("Found Trace of Codex Website On PC")},
        {xorstr_("serotonin.win"), xorstr_("Found Trace of Serotonin Website On PC")},
        {xorstr_("matcha-latte.win"), xorstr_("Found Trace of Matcha Website On PC")},
        {xorstr_("photonsys.sellpass.io"), xorstr_("Found Trace of Photon Website On PC")},
        {xorstr_("cultofintellect.com"), xorstr_("Found Trace of DX9WARE V2 Website On PC")},

        #elif DETECT_RUST

        {xorstr_("onestopcheats.com"), xorstr_("Found Trace of Onestopcheats Website On PC")},
        {xorstr_("blurred.gg"), xorstr_("Found Trace of Blurred.gg Website On PC")},
        {xorstr_("captaindma.com"), xorstr_("Found Trace of Captain DMA Website On PC")},
        {xorstr_("pulsedma.com"), xorstr_("Found Trace of Pulse DMA Website On PC")},
        {xorstr_("makcu.com"), xorstr_("Found Trace of Makcu Website On PC")},

        #elif DETECT_FORTNITE

        {xorstr_("SkyCheats.com"), xorstr_("Found Trace of SkyCheats Website On PC")},
        {xorstr_("battlelog.co"), xorstr_("Found Trace of battlelog Website On PC")},
        {xorstr_("aimclub.io"), xorstr_("Found Trace of aimclub Website On PC")},
        {xorstr_("uniquehacks.store"), xorstr_("Found Trace of uniquehacks Website On PC")},
        {xorstr_("privatecheatz.com"), xorstr_("Found Trace of privatecheatz Website On PC")},
        {xorstr_("colossalcheats.com"), xorstr_("Found Trace of colossalcheats Website On PC")},
        {xorstr_("hackerbot.net"), xorstr_("Found Trace of hackerbot Website On PC")},
        {xorstr_("army-cheats.com"), xorstr_("Found Trace of army-cheats Website On PC")},
        {xorstr_("spycheats.net"), xorstr_("Found Trace of spycheats Website On PC")},
        {xorstr_("santana-tech.com/"), xorstr_("Found Trace of santana-tech Website On PC")},
        {xorstr_("aimhax.net"), xorstr_("Found Trace of aimhax Website On PC")},
        {xorstr_("kernelcheats.to"), xorstr_("Found Trace of kernelcheats Website On PC")},
        {xorstr_("infinitycheats.net"), xorstr_("Found Trace of infinitycheats Website On PC")},
        {xorstr_("xera-cheats.com"), xorstr_("Found Trace of xera-cheats Website On PC")},
        {xorstr_("zeta-cheats.com"), xorstr_("Found Trace of zeta-cheats Website On PC")},
        {xorstr_("neo-cheats.com"), xorstr_("Found Trace of neo-cheats Website On PC")},
        {xorstr_("Lavicheats.com"), xorstr_("Found Trace of Lavicheats Website On PC")},
        {xorstr_("cheating.gg"), xorstr_("Found Trace of Cheating Website On PC")},
        {xorstr_("ventro.tech"), xorstr_("Found Trace of Solaris Website On PC")},
        {xorstr_("sceptre.pro"), xorstr_("Found Trace of Sceptre Website On PC")},
        {xorstr_("185.236.228.154"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("flkstore.com"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("flk-uhq.xyz"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("5.206.224.37"), xorstr_("Found Trace of FLK Website On PC")},
        {xorstr_("blurred.gg"), xorstr_("Found Trace of Blurred.gg Website On PC")},
        {xorstr_("captaindma.com"), xorstr_("Found Trace of Captain DMA Website On PC")},
        {xorstr_("pulsedma.com"), xorstr_("Found Trace of Pulse DMA Website On PC")},
        {xorstr_("makcu.com"), xorstr_("Found Trace of Makcu Website On PC")},
        {xorstr_("keyser-lts.com"), xorstr_("Found Trace of Keyser Website On PC")},
        {xorstr_("keyser.gg"), xorstr_("Found Trace of Keyser Website On PC")},
        {xorstr_("zombiecheats.com"), xorstr_("Found Trace of Zombie Cheats Website On PC")},
        {xorstr_("hypervision.gg"), xorstr_("Found Trace of Hypervision Website On PC")},
        {xorstr_("elocarry.net"), xorstr_("Found Trace of Elocarry Website On PC")},
        {xorstr_("engineowning.su"), xorstr_("Found Trace of EngineOwning Website On PC")},
        {xorstr_("uzuimarket.xyz"), xorstr_("Found Trace of Uzui Market Website On PC")},
        {xorstr_("exodus.fun"), xorstr_("Found Trace of Exodus Cheats Website On PC")},
        {xorstr_("195.59.67.101"), xorstr_("Found Trace of ICanHaZip On PC")},
        {xorstr_("icanhazip.com"), xorstr_("Found Trace of ICanHaZip On PC")},
        {xorstr_("udsoftwares.com"), xorstr_("Found Trace of UD Softwares On PC")},
        {xorstr_("crythosbackend-production.up.railway.app"), xorstr_("Found Trace of Crythos On PC")},

        #elif DETECT_DAYZ

        {xorstr_("stugware.com"), xorstr_("Found Trace of Stugwware Website On PC")},
        {xorstr_("cheatseller.com"), xorstr_("Found Trace of Cheatseller Website On PC")},
        {xorstr_("elitehacks.ru"), xorstr_("Found Trace of Elite Hacks Website On PC")},

        #elif DETECT_SIEGE

        {xorstr_("skreechware.com"), xorstr_("Found Trace of Skreechware Website On PC")},
        {xorstr_("cosmocheats.com"), xorstr_("Found Trace of Cosmocheats Website On PC")},
        {xorstr_("nyronai.com"), xorstr_("Found Trace of Nyronai Website On PC")},
        {xorstr_("aptitude.pub"), xorstr_("Found Trace of Aptitude Website On PC")},
        {xorstr_("visuals.gg"), xorstr_("Found Trace of Visuals Website On PC")},
        {xorstr_("battlelog.com"), xorstr_("Found Trace of Battlelog Website On PC")},
        {xorstr_("blurred.gg"), xorstr_("Found Trace of Blurred.gg Website On PC")},
        {xorstr_("captaindma.com"), xorstr_("Found Trace of Captain DMA Website On PC")},
        {xorstr_("pulsedma.com"), xorstr_("Found Trace of Pulse DMA Website On PC")},
        {xorstr_("makcu.com"), xorstr_("Found Trace of Makcu Website On PC")},
        {xorstr_("connerzon.com"), xorstr_("Found Trace of Connerzon Website On PC")},
        {xorstr_("r6needs.store"), xorstr_("Found Trace of R6Needs Website On PC")},
        {xorstr_("edaters.store"), xorstr_("Found Trace of Edaters Website On PC")},
        {xorstr_("beatbct.com"), xorstr_("Found Trace of BeatBCT Website On PC")},
        {xorstr_("xerus.cc"), xorstr_("Found Trace of Xerus Website On PC")},
        {xorstr_("overdose.support"), xorstr_("Found Trace of Overdose Website On PC")},
        {xorstr_("veylo.io"), xorstr_("Found Trace of Veylo Website On PC")},
        {xorstr_("chudvision.net"), xorstr_("Found Trace of Chudvision Website On PC")},
        {xorstr_("exloader.net"), xorstr_("Found Trace of ExLoader Website On PC")},
        {xorstr_("battlelog.co"), xorstr_("Found Trace of Battlelog CO Website On PC")},
        {xorstr_("sinfulexp.net"), xorstr_("Found Trace of SinfulExp Website On PC")},
        {xorstr_("ancient.su"), xorstr_("Found Trace of Ancient Website On PC")},
        {xorstr_("enhancedsolutions.cc"), xorstr_("Found Trace of Enhanced Solutions Website On PC")},
        {xorstr_("closetware.store"), xorstr_("Found Trace of Closetware Website On PC")},
        {xorstr_("ghostware.cc"), xorstr_("Found Trace of Ghostware Website On PC")},
        {xorstr_("deception.gg"), xorstr_("Found Trace of Deception Website On PC")},
        {xorstr_("hexdma.com"), xorstr_("Found Trace of HexDMA Website On PC")},
        {xorstr_("aquacheats.cc"), xorstr_("Found Trace of AquaCheats Website On PC")},
        {xorstr_("calamari.lol"), xorstr_("Found Trace of Calamari Website On PC")},
        {xorstr_("elocarry.net"), xorstr_("Found Trace of EloCarry Website On PC")},
        {xorstr_("lavicheats.com"), xorstr_("Found Trace of LaviCheats Website On PC")},
        {xorstr_("gear5.sellpass.io"), xorstr_("Found Trace of Gear5 Website On PC")},
        {xorstr_("reportedcheats.com"), xorstr_("Found Trace of ReportedCheats Website On PC")},
        {xorstr_("outkastcheats.com"), xorstr_("Found Trace of OutkastCheats Website On PC")},
        {xorstr_("kernelsight.com"), xorstr_("Found Trace of KernelSight Website On PC")},
        {xorstr_("klar.gg"), xorstr_("Found Trace of Klar Website On PC")},
        {xorstr_("lethalcheats.net"), xorstr_("Found Trace of LethalCheats Website On PC")},
        {xorstr_("lynxtech.pro"), xorstr_("Found Trace of LynxTech Website On PC")},
        {xorstr_("unknowncheats.me"), xorstr_("Found Trace of UnknownCheats Website On PC")},
        {xorstr_("playsharp.io"), xorstr_("Found Trace of PlaySharp Website On PC")},
        {xorstr_("1nvituscheats.com"), xorstr_("Found Trace of 1nvitus Cheats Website On PC")},
        {xorstr_("shopring1nvitus.com"), xorstr_("Found Trace of ShopRing 1nvitus Website On PC")},
        {xorstr_("red-xservices.com"), xorstr_("Found Trace of Red X Services Website On PC")},

        #elif DETECT_COD

        {xorstr_("streckaio.com"), xorstr_("Found Trace of Strecka.io Website On PC")},

        #elif DETECT_CS

        {xorstr_("memesense.gg"), xorstr_("Found Trace of Memesense Website On PC")},
        {xorstr_("midnight.im"), xorstr_("Found Trace of Midnight Website On PC")},
        {xorstr_("gamesense.vip"), xorstr_("Found Trace of GameSense Website On PC")},

        #endif

        {xorstr_("auth.gg"), xorstr_("Found Trace of Auth.gg Website On PC")},
        {xorstr_("keyauth.com"), xorstr_("Found Trace of KeyAuth Website On PC")},
        {xorstr_("elitepvpers.com"), xorstr_("Found Trace of ElitePVPers Website On PC")},
        {xorstr_("aimjunkies.com"), xorstr_("Found Trace of AimJunkies Website On PC")},
        {xorstr_("systemcheats.net"), xorstr_("Found Trace of SystemCheats Website On PC")},
        {xorstr_("engineowning.to"), xorstr_("Found Trace of EngineOwning Website On PC")},
        {xorstr_("clutch-solution.com"), xorstr_("Found Trace of Clutch Solution Website On PC")},
        {xorstr_("skeet.cc"), xorstr_("Found Trace of Skeet Website On PC")},
        {xorstr_("gamesense.pub"), xorstr_("Found Trace of GameSense Website On PC")},
        {xorstr_("primordial.dev"), xorstr_("Found Trace of Primordial Website On PC")},
        {xorstr_("neverlose.cc"), xorstr_("Found Trace of Neverlose Website On PC")},
        {xorstr_("fatality.win"), xorstr_("Found Trace of Fatality Website On PC")},
        {xorstr_("onetap.com"), xorstr_("Found Trace of OneTap Website On PC")},
        {xorstr_("onetap.su"), xorstr_("Found Trace of OneTap Website On PC")},
        {xorstr_("skreech.gg"), xorstr_("Found Trace of Skreech Website On PC")},
        {xorstr_("cheatsense.sellhub.cx"), xorstr_("Found Trace of CheatSense Website On PC")},
        {xorstr_("r6hibania.cc"), xorstr_("Found Trace of R6 Hibania Website On PC")},
        {xorstr_("chair.wtf"), xorstr_("Found Trace of Chair Website On PC")},
        {xorstr_("tomware.cc"), xorstr_("Found Trace of Tomware Website On PC")},
        {xorstr_("rankuen.com"), xorstr_("Found Trace of Rankuen Website On PC")},
        {xorstr_("shop.deception.gg"), xorstr_("Found Trace of Deception Shop Website On PC")},
        {xorstr_("phoenixlabstore.com"), xorstr_("Found Trace of Phoenix Lab Website On PC")},
        {xorstr_("oxxscheats.com"), xorstr_("Found Trace of OxxsCheats Website On PC")},
        {xorstr_("vega.sell.app"), xorstr_("Found Trace of Vega Website On PC")},
        {xorstr_("cheats.love"), xorstr_("Found Trace of Cheats.love Website On PC")},
        {xorstr_("chamscheats.com"), xorstr_("Found Trace of ChamsCheats Website On PC")},
        {xorstr_("whyyoucheating.sellhub.cx"), xorstr_("Found Trace of WhyYouCheating Website On PC")},
        {xorstr_("tgmodz.com"), xorstr_("Found Trace of TGModz Website On PC")},
        {xorstr_("ezmod.vip"), xorstr_("Found Trace of EzMod Website On PC")},
        {xorstr_("ssz.gg"), xorstr_("Found Trace of SSZ Website On PC")},
        {xorstr_("download.antarcticacheats.xyz"), xorstr_("Found Trace of Antarctica Cheats Website On PC")},
        {xorstr_("antarctica.sellpass.io"), xorstr_("Found Trace of Antarctica Cheats Website On PC")},
        {xorstr_("antarcticacheats.xyz"), xorstr_("Found Trace of Antarctica Cheats Website On PC")},
        {xorstr_("perc.gg"), xorstr_("Found Trace of Perc Website On PC")},
        {xorstr_("pcileech.com"), xorstr_("Found Trace of PCILeech Website On PC")},
        {xorstr_("memprocfs.com"), xorstr_("Found Trace of MemProcFS Website On PC")},
        {xorstr_("dma-shop.com"), xorstr_("Found Trace of DMA Shop Website On PC")},
        {xorstr_("fpgacheats.com"), xorstr_("Found Trace of FPGA Cheats Website On PC")},
        {xorstr_("dmastore.gg"), xorstr_("Found Trace of DMA Store Website On PC")},
        {xorstr_("squirreldma.com"), xorstr_("Found Trace of Squirrel DMA Website On PC")},
        {xorstr_("leechcore.com"), xorstr_("Found Trace of LeechCore Website On PC")},
        {xorstr_("kmboxb.com"), xorstr_("Found Trace of KMBox B Website On PC")},
        {xorstr_("kmbox.pro"), xorstr_("Found Trace of KMBox Website On PC")},
        {xorstr_("arduino-cheat.com"), xorstr_("Found Trace of Arduino Cheat Website On PC")},
        {xorstr_("guided-hacking.com"), xorstr_("Found Trace of Guided Hacking Website On PC")},
        {xorstr_("hackforums.net"), xorstr_("Found Trace of HackForums Website On PC")},
        {xorstr_("mpgh.net"), xorstr_("Found Trace of MPGH Website On PC")},
        {xorstr_("cheatautomation.com"), xorstr_("Found Trace of Cheat Automation Website On PC")},
        {xorstr_("aimware.net"), xorstr_("Found Trace of Aimware Website On PC")},
        {xorstr_("interwebz.cc"), xorstr_("Found Trace of Interwebz Website On PC")},
        {xorstr_("lmaobox.net"), xorstr_("Found Trace of LMAOBox Website On PC")},
        {xorstr_("streamline-cheats.com"), xorstr_("Found Trace of Streamline Cheats Website On PC")},
        {xorstr_("nixware.cc"), xorstr_("Found Trace of Nixware Website On PC")},
        {xorstr_("pandora-cheats.com"), xorstr_("Found Trace of Pandora Cheats Website On PC")},
        {xorstr_("hyperion-cheats.com"), xorstr_("Found Trace of Hyperion Cheats Website On PC")},
        {xorstr_("cobracheats.com"), xorstr_("Found Trace of Cobra Cheats Website On PC")},
        {xorstr_("sellpass.io"), xorstr_("Found Trace of Sellpass Website On PC")},
        {xorstr_("whop.com"), xorstr_("Found Trace of Whop Website On PC")},
        {xorstr_("enigmadma.com"), xorstr_("Found Trace of Enigma DMA Website On PC")},
        {xorstr_("dma-fw.com"), xorstr_("Found Trace of DMA Firmware Website On PC")},
        {xorstr_("fpga-cheats.com"), xorstr_("Found Trace of FPGA Cheats Website On PC")},
        {xorstr_("lambdaconcept.com"), xorstr_("Found Trace of LambdaConcept Website On PC")},
        {xorstr_("squirreldma.gg"), xorstr_("Found Trace of Squirrel DMA Website On PC")},
        {xorstr_("pcileech.io"), xorstr_("Found Trace of PCILeech Website On PC")},
        {xorstr_("dmatools.net"), xorstr_("Found Trace of DMA Tools Website On PC")},
        {xorstr_("hwid-spoofer.com"), xorstr_("Found Trace of HWID Spoofer Website On PC")},
        {xorstr_("hwid-ban.com"), xorstr_("Found Trace of HWID Ban Website On PC")},
        {xorstr_("rena.lol"), xorstr_("Found Trace of Rena Website On PC")},
        {xorstr_("keyauth.win"), xorstr_("Found Trace of KeyAuth Website On PC")},
        {xorstr_("keyauth.cc"), xorstr_("Found Trace of KeyAuth Website On PC")},
        {xorstr_("2.56.246.3"), xorstr_("Found Trace of Revuelto Website On PC")},

            };
        } catch (...) {}
        return v;
    }();
    return kKeywords;
}

}

void windows_db_parser::parse_db(const std::string& db_path) {
    try {
        if (db_path.empty()) return;

        std::wstring src;
        {
            int n = MultiByteToWideChar(CP_UTF8, 0, db_path.c_str(), -1, nullptr, 0);
            if (n > 1) {
                src.assign(static_cast<size_t>(n - 1), L'\0');
                MultiByteToWideChar(CP_UTF8, 0, db_path.c_str(), -1, src.data(), n);
            }
        }
        if (src.empty()) return;
        if (GetFileAttributesW(src.c_str()) == INVALID_FILE_ATTRIBUTES) return;

        std::wstring tmp = MakeRandomTempPath();
        if (tmp.empty()) return;
        if (!TryCopyDb(src, tmp)) {
            DeleteFileW(tmp.c_str());
            return;
        }
        struct TempCleanup {
            std::wstring path;
            ~TempCleanup() { try { DeleteFileW(path.c_str()); } catch (...) {} }
        } cleanup{tmp};

        std::string utf8Tmp;
        {
            int n = WideCharToMultiByte(CP_UTF8, 0, tmp.c_str(), -1,
                                         nullptr, 0, nullptr, nullptr);
            if (n > 1) {
                utf8Tmp.assign(static_cast<size_t>(n - 1), '\0');
                WideCharToMultiByte(CP_UTF8, 0, tmp.c_str(), -1,
                                    utf8Tmp.data(), n, nullptr, nullptr);
            }
        }
        if (utf8Tmp.empty()) return;

        sqlite3* probe = nullptr;
        if (sqlite3_open_v2(utf8Tmp.c_str(), &probe,
                            SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX,
                            nullptr) != SQLITE_OK) {
            if (probe) sqlite3_close(probe);
            return;
        }
        TunePragmas(probe);

        const std::string kTable = xorstr_("SystemIndex_1_PropertyStore");
        if (!TableExists(probe, kTable)) {
            sqlite3_close(probe);
            return;
        }

        std::vector<std::string> cols = SniffStringColumns(probe, kTable);
        if (cols.empty()) cols.push_back(xorstr_("*"));

        std::string selectList;
        for (size_t i = 0; i < cols.size(); ++i) {
            if (i) selectList.push_back(',');
            selectList += cols[i];
        }

        int64_t lo = 0, hi = -1;
        if (!QueryWorkIdRange(probe, kTable, lo, hi) || hi < lo) {
            sqlite3_close(probe);
            return;
        }
        sqlite3_close(probe);

        const auto& kws = WindbKeywords();
        std::vector<std::string>              uniqueKeysLower;
        std::vector<std::vector<std::string>> labels;
        std::unordered_map<std::string, size_t> idx;
        uniqueKeysLower.reserve(kws.size());
        labels.reserve(kws.size());
        idx.reserve(kws.size() * 2);
        for (auto& kv : kws) {
            std::string key = kv.first;
            to_lower_ascii(key);
            if (key.empty()) continue;
            auto it = idx.find(key);
            if (it == idx.end()) {
                idx.emplace(key, uniqueKeysLower.size());
                uniqueKeysLower.push_back(std::move(key));
                labels.push_back({ kv.second });
            } else {
                labels[it->second].push_back(kv.second);
            }
        }
        if (uniqueKeysLower.empty()) return;

        AhoCorasick ac;
        ac.Build(uniqueKeysLower);

        unsigned int hw = std::thread::hardware_concurrency();
        if (hw == 0) hw = 4;
        const unsigned int kThreads = std::min<unsigned int>(hw, 6u);
        const int64_t total = hi - lo + 1;
        const int64_t chunk = (total + static_cast<int64_t>(kThreads) - 1)
                              / static_cast<int64_t>(kThreads);
        if (chunk <= 0) return;

        const size_t patternCount = uniqueKeysLower.size();

        std::vector<std::thread> workers;
        workers.reserve(kThreads);
        for (unsigned int t = 0; t < kThreads; ++t) {
            const int64_t s = lo + static_cast<int64_t>(t) * chunk;
            const int64_t e = std::min<int64_t>(hi, s + chunk - 1);
            if (s > e) break;
            workers.emplace_back([tmp, selectList, kTable, s, e, &ac, &labels, patternCount]() {
                ScanRange(tmp, selectList, kTable, s, e, ac, labels, patternCount);
            });
        }
        for (auto& th : workers) {
            try { if (th.joinable()) th.join(); } catch (...) {}
        }
    } catch (...) {}
}

void windows_db_parser::start_windb_urls() {
    try {
        windows_db_parser::parse_db(
            xorstr_("C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.db"));
    } catch (...) {}
}
