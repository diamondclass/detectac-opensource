#pragma once

#include <fstream>
#include <string>
#include <vector>
#include <mutex>
#include <ctime>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/buffer.h>
#include "../../vars.h"
#include "../detection/utils.h"
#include "../crypt/xorstr.h"
#include "../../scan_api/telemetry_v2.hpp"
#include "../../scan_api/telemetry_v2_keys.hpp"
#include "../protection/protection.h"
#include "../protection/anti_debug.h"
#include "../protection/integrity_snapshot.hpp"
#include "../protection/hardware_trust.hpp"
#include "../protection/hook_scanner.hpp"
#include "../protection/tamper_response.hpp"
#include "log_tamper_guard.hpp"

class Logger
{
public:
    enum class LogLevel { INFO , WARNING , CRITICAL , DETECTION };

    class LogEntry
    {
    public:
        LogEntry ( Logger& logger , LogLevel level , const std::string& timestamp )
            : logger_ ( logger ) , level_ ( level ) , original_timestamp_ ( timestamp ) {
        }
        ~LogEntry ( ) { logger_.log ( level_ , original_timestamp_ , message_ ); }

        template<typename T>
        LogEntry& operator<<( const T& value ) {
            message_ += to_string ( value );
            return *this;
        }

        static std::string convert_to_iso ( const std::string& timestamp ) {
            if ( timestamp == xorstr_ ( "N/A" ) ) {
                return xorstr_ ( "N/A" );
            }

            std::tm tm = {};
            std::istringstream ss ( timestamp );

            bool parsed = ( ss >> std::get_time ( &tm , xorstr_("%Y-%m-%d %H:%M:%S") ) ) ||
                ( ss.clear ( ) , ss.str ( timestamp ) , ss >> std::get_time ( &tm , xorstr_("%Y/%m/%d %H:%M:%S") ) ) ||
                ( ss.clear ( ) , ss.str ( timestamp ) , ss >> std::get_time ( &tm , xorstr_("%m-%d-%Y %H:%M:%S") ) ) ||
                ( ss.clear ( ) , ss.str ( timestamp ) , ss >> std::get_time ( &tm , xorstr_("%Y-%m-%dT%H:%M:%SZ") ) );

            if ( parsed ) {
                std::ostringstream iso_stream;
                iso_stream << std::put_time ( &tm , xorstr_("%Y-%m-%dT%H:%M:%SZ") );
                return iso_stream.str ( );
            }

            return timestamp;
        }

    private:
        Logger& logger_;
        LogLevel level_;
        std::string message_;
        std::string original_timestamp_;

        template<typename T>
        static std::string to_string ( const T& value )
        {
            if constexpr ( std::is_arithmetic_v<T> )
            {
                return std::to_string ( value );
            }
            else
            {
                std::ostringstream oss;
                oss << value;
                return oss.str ( );
            }
        }

        static std::string to_string(const std::string& value) {
            return sanitize_string(value);
        }

        static std::string to_string(const char* value) {
            return sanitize_string(std::string(value));
        }

        static std::string to_string(const wchar_t* value) {
            return sanitize_wchar(value);
        }

        static std::string to_string(wchar_t* value) {
            return sanitize_wchar(value);
        }

        static std::string to_string(const std::wstring& value) {
            return sanitize_wstring(value);
        }
    };

    static std::string sanitize_string(const std::string& str) {
        std::string result;
        for (unsigned char c : str) {
            if (c >= 32 && c <= 126) {
                result += c;
            }
            else {
                result += '?';
            }
        }
        return result;
    }

    static std::string sanitize_wstring(const std::wstring& wstr) {
        std::string result;
        for (wchar_t wc : wstr) {
            if (wc >= 32 && wc <= 126) {
                result += static_cast<char>(wc);
            }
            else {
                result += '?';
            }
        }
        return result;
    }

    static std::string sanitize_wchar(const wchar_t* wstr) {
        if (!wstr) return {};
        return sanitize_wstring(std::wstring(wstr));
    }

    static Logger& instance ( ) {
        static Logger logger_instance ( "" );
        return logger_instance;
    }

    LogEntry operator()( LogLevel level , const std::string& timestamp = xorstr_ ( "N/A" ) ) {
        return LogEntry ( *this , level , timestamp );
    }

    void ensure_guard_seeded() noexcept {
        std::lock_guard<std::mutex> lock ( log_mutex );
        ensure_guard_seeded_locked();
    }

    void flush_logs()
    {
        {
            const auto hook = hook_scanner::run_full_scan();
            if (tamper_response::should_trigger_on(hook.bits))
            {
                tamper_response::trigger(xorstr_(L"flush_logs: hook signals detected"));
            }
        }

        cap_logs_per_flag();

        nlohmann::json log_json;
        log_json[xorstr_("logs")] = nlohmann::json::array();

        for (const auto& [pin, logs] : log_buffer_)
            for (const auto& log_entry : logs)
                log_json[xorstr_("logs")].push_back(log_entry);

        std::string pin = detect.pin;
        const auto payload_str = log_json.dump();

        bool v2_delivered = false;
        auto& v2 = telemetry_v2::shared_session();
        const bool v2_attempted = v2.is_open();
        auto& guard = log_tamper_guard::instance();
        const bool guard_was_seeded = guard.seeded();

        if (v2_attempted)
        {
            const auto ints_snap = integrity_snapshot::capture();
            telemetry_v2::integrity_signals sigs{};
            const unsigned dbg = protection::antidebug::RunAllChecks();
            sigs.debugger_present    = (dbg != 0) || ((ints_snap.bits & integrity_snapshot::bit_debugger_present) != 0);
            sigs.detected_bits       = dbg | ints_snap.bits;
            sigs.image_hash_mismatch = protection::IsCompromised();
            sigs.admin_context       = (ints_snap.bits & integrity_snapshot::bit_admin_dropped) == 0;
            sigs.syscall_stubs_ok    = (ints_snap.bits & integrity_snapshot::bit_syscall_stubs_bad) == 0;
            sigs.module_count        = ints_snap.module_count;
            sigs.boot_time_seconds   = ints_snap.boot_time_seconds;

            log_tamper_guard::batch sealed_batch{};
            guard.take_batch(sealed_batch);

            const std::string sid = v2.session_id();
            uint8_t hw_challenge[32] = {};
            {
                std::vector<uint8_t> buf;
                buf.reserve(sid.size() + 32 + 4);
                buf.insert(buf.end(), sid.begin(), sid.end());
                buf.insert(buf.end(), sealed_batch.terminal_tag, sealed_batch.terminal_tag + 32);
                const uint32_t lcc = sealed_batch.log_call_count;
                buf.push_back(uint8_t((lcc >> 24) & 0xFF));
                buf.push_back(uint8_t((lcc >> 16) & 0xFF));
                buf.push_back(uint8_t((lcc >> 8)  & 0xFF));
                buf.push_back(uint8_t( lcc        & 0xFF));
                Cng::Sha256Once(buf.data(), buf.size(), hw_challenge);
            }
            const auto hw = hardware_trust::capture(hw_challenge);

            static const std::string H_storage = xorstr_("0123456789abcdef"); static const char* const H = H_storage.c_str();
            auto to_hex = [&](const uint8_t* buf, size_t n) {
                std::string out;
                out.resize(n * 2);
                for (size_t i = 0; i < n; ++i) {
                    out[i * 2]     = H[(buf[i] >> 4) & 0xF];
                    out[i * 2 + 1] = H[buf[i] & 0xF];
                }
                return out;
            };

            nlohmann::json enriched = nlohmann::json::object();
            enriched[xorstr_("logs")]           = log_json[xorstr_("logs")];
            enriched[xorstr_("entry_count")]    = uint32_t(sealed_batch.entries.size());
            enriched[xorstr_("terminal_tag")]   = to_hex(sealed_batch.terminal_tag, log_tamper_guard::chain_tag_len);
            enriched[xorstr_("log_call_count")] = sealed_batch.log_call_count;
            enriched[xorstr_("append_drops")]   = sealed_batch.drops_on_append;
            enriched[xorstr_("flush_epoch")]    = sealed_batch.flush_epoch;
            enriched[xorstr_("integrity_bits")] = ints_snap.bits;
            enriched[xorstr_("integrity")] = {
                { xorstr_("module_count"),        ints_snap.module_count },
                { xorstr_("driver_count"),        ints_snap.driver_count },
                { xorstr_("bad_modules"),         ints_snap.bad_modules },
                { xorstr_("bad_drivers"),         ints_snap.bad_drivers },
                { xorstr_("module_list_hash"),    to_hex(ints_snap.module_list_hash, 32) },
                { xorstr_("driver_list_hash"),    to_hex(ints_snap.driver_list_hash, 32) },
                { xorstr_("boot_time_seconds"),   ints_snap.boot_time_seconds },
                { xorstr_("debugger_present"),    sigs.debugger_present },
                { xorstr_("admin_context"),       sigs.admin_context },
                { xorstr_("syscall_stubs_ok"),    sigs.syscall_stubs_ok },
                { xorstr_("image_hash_ok"),       !sigs.image_hash_mismatch },
                { xorstr_("ntdll_prologue_diff"), ints_snap.ntdll_prologue_diffs },
                { xorstr_("syscall_stub_bad"),    ints_snap.syscall_stub_bad },
                { xorstr_("hardware_bp_threads"), ints_snap.hardware_bp_threads },
                { xorstr_("modules_iat_hooked"),  ints_snap.modules_iat_hooked },
            };
            enriched[xorstr_("hardware_trust")] = {
                { xorstr_("bits"),               hw.bits },
                { xorstr_("fingerprint"),        to_hex(hw.fingerprint, 32) },
                { xorstr_("tpm_pub_key"),        to_hex(hw.tpm_pub_key_blob.data(), hw.tpm_pub_key_blob.size()) },
                { xorstr_("tpm_quote"),          to_hex(hw.tpm_quote.data(), hw.tpm_quote.size()) },
                { xorstr_("boot_time_registry"), hw.boot_time_registry },
                { xorstr_("boot_time_perf"),     hw.boot_time_perf },
                { xorstr_("install_time"),       hw.install_time },
            };

            nlohmann::json sealed_arr = nlohmann::json::array();
            for (const auto& se : sealed_batch.entries) {
                nlohmann::json j = nlohmann::json::object();
                j[xorstr_("seq")]        = se.seq;
                j[xorstr_("chain_tag")]  = to_hex(se.chain_tag, log_tamper_guard::chain_tag_len);
                j[xorstr_("ciphertext")] = to_hex(se.ciphertext.data(), se.ciphertext.size());
                sealed_arr.push_back(std::move(j));
            }
            enriched[xorstr_("sealed_entries")] = std::move(sealed_arr);

            const auto batch_str = enriched.dump(-1, ' ', false,
                                                 nlohmann::json::error_handler_t::replace);

            for (int attempt = 0; attempt < 3 && !v2_delivered; ++attempt)
            {
                const auto int_rc = v2.send_integrity(sigs);
                if (int_rc != telemetry_v2::error::none)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1 + attempt));
                    continue;
                }
                const auto batch_rc = v2.send_log_batch(batch_str);
                if (batch_rc != telemetry_v2::error::none)
                {
                    std::this_thread::sleep_for(std::chrono::seconds(1 + attempt));
                    continue;
                }
                nlohmann::json summary = nlohmann::json::object();
                summary[xorstr_("build_id")]       = telemetry_v2::build_id();
                summary[xorstr_("log_count")]      = log_json[xorstr_("logs")].size();
                summary[xorstr_("sealed_count")]   = uint32_t(sealed_batch.entries.size());
                summary[xorstr_("log_call_count")] = sealed_batch.log_call_count;
                summary[xorstr_("integrity_bits")] = sigs.detected_bits;
                summary[xorstr_("image_ok")]       = !sigs.image_hash_mismatch;
                summary[xorstr_("terminal_tag")]   = to_hex(sealed_batch.terminal_tag, log_tamper_guard::chain_tag_len);
                const auto final_rc = v2.finalize(summary.dump());
                v2_delivered = (final_rc == telemetry_v2::error::none);
                if (!v2_delivered) std::this_thread::sleep_for(std::chrono::seconds(1 + attempt));
            }

            guard.finalize();
        }

        bool legacy_delivered = false;
        if (!v2_delivered)
            legacy_delivered = send_legacy_payload(log_json, pin);

        detect.sent_data = v2_delivered || legacy_delivered;

        log_buffer_.clear();
        seen_entries_.clear();
    }

    static std::string html_escape(const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '&':  out += "&amp;";  break;
                case '<':  out += "&lt;";   break;
                case '>':  out += "&gt;";   break;
                case '"':  out += "&quot;"; break;
                default:   out += c;        break;
            }
        }
        return out;
    }

    std::string save_local_html_report()
    {
        struct report_row { std::string ts, type, msg, sha1; };
        std::vector<report_row> rows;
        {
            std::lock_guard<std::mutex> lock ( log_mutex );
            for ( const auto& [pin , logs] : log_buffer_ ) {
                for ( const auto& e : logs ) {
                    report_row r;
                    r.ts   = e.value ( xorstr_ ( "timestamp" ) , std::string{} );
                    r.type = e.value ( xorstr_ ( "type" ) , std::string{} );
                    r.msg  = e.value ( xorstr_ ( "message" ) , std::string{} );
                    r.sha1 = e.value ( xorstr_ ( "sha1" ) , std::string{} );
                    rows.push_back ( std::move ( r ) );
                }
            }
        }

        const char* game_name =
#if defined(DETECT_MINECRAFT)
            "minecraft";
#elif defined(DETECT_SIEGE)
            "siege";
#elif defined(DETECT_GMOD)
            "gmod";
#elif defined(DETECT_FIVEM)
            "fivem";
#elif defined(DETECT_FREEFIRE)
            "freefire";
#elif defined(DETECT_ROBLOX)
            "roblox";
#elif defined(DETECT_FORTNITE)
            "fortnite";
#elif defined(DETECT_COD)
            "cod";
#elif defined(DETECT_RUST)
            "rust";
#elif defined(DETECT_DAYZ)
            "dayz";
#elif defined(DETECT_CS)
            "cs";
#else
            "unknown";
#endif

        size_t n_info = 0, n_warn = 0, n_crit = 0, n_det = 0;
        for (const auto& r : rows) {
            if (r.type == "DETECTION") ++n_det;
            else if (r.type == "CRITICAL") ++n_crit;
            else if (r.type == "WARNING") ++n_warn;
            else ++n_info;
        }

        std::time_t now = std::time(nullptr);
        std::tm tmv{};
        localtime_s(&tmv, &now);
        char stamp[32] = {};
        std::strftime(stamp, sizeof(stamp), "%Y%m%d-%H%M%S", &tmv);
        char pretty[64] = {};
        std::strftime(pretty, sizeof(pretty), "%Y-%m-%d %H:%M:%S", &tmv);

        std::string dir;
        {
            char exe_path[MAX_PATH] = {};
            if (GetModuleFileNameA(NULL, exe_path, MAX_PATH) != 0) {
                std::string full(exe_path);
                size_t sep = full.find_last_of("\\/");
                if (sep != std::string::npos) dir = full.substr(0, sep);
            }
        }
        if (dir.empty()) {
            char tmp[MAX_PATH] = {};
            if (GetTempPathA(MAX_PATH, tmp) != 0) dir = tmp;
        }
        if (dir.empty()) return {};
        while (!dir.empty() && (dir.back() == '\\' || dir.back() == '/')) dir.pop_back();

        std::string path = dir + "\\detect-report-" + game_name + "-" + stamp + ".html";

        std::ostringstream html;
        html << "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n";
        html << "<title>detect " << game_name << " scan report</title>\n";
        html << "<style>body{font-family:Consolas,monospace;background:#111;color:#ddd;margin:24px;}"
                "h1{font-size:20px}table{border-collapse:collapse;width:100%;font-size:12px}"
                "th,td{border:1px solid #444;padding:4px 8px;text-align:left;vertical-align:top}"
                "th{background:#222}.det{background:#3a0d0d}.crit{background:#3a240d}"
                ".warn{background:#33330d}.summary{margin:12px 0}</style>\n";
        html << "</head>\n<body>\n";
        html << "<h1>detect " << game_name << " scan report</h1>\n";
        html << "<div class=\"summary\">Finished: " << pretty
             << " | entries: " << rows.size()
             << " | DETECTION: " << n_det
             << " | CRITICAL: " << n_crit
             << " | WARNING: " << n_warn
             << " | INFO: " << n_info << "</div>\n";
        html << "<table>\n<tr><th>#</th><th>timestamp</th><th>level</th><th>message</th><th>sha1</th></tr>\n";
        for (size_t i = 0; i < rows.size(); ++i) {
            const auto& r = rows[i];
            const char* cls = (r.type == "DETECTION") ? " class=\"det\""
                : (r.type == "CRITICAL") ? " class=\"crit\""
                : (r.type == "WARNING") ? " class=\"warn\"" : "";
            html << "<tr" << cls << "><td>" << i
                 << "</td><td>" << html_escape(r.ts)
                 << "</td><td>" << html_escape(r.type)
                 << "</td><td>" << html_escape(r.msg)
                 << "</td><td>" << html_escape(r.sha1) << "</td></tr>\n";
        }
        html << "</table>\n</body>\n</html>\n";

        std::ofstream ofs(path, std::ios::out | std::ios::trunc);
        if (!ofs) return {};
        ofs << html.str();
        ofs.close();
        if (!ofs) return {};
        return path;
    }

private:
    Logger ( const std::string& file_path ) : file_path ( file_path ) { }

    void log ( LogLevel level , const std::string& original_timestamp , const std::string& message ) {
        log_tamper_guard::instance().increment_call_counter();

        std::lock_guard<std::mutex> lock ( log_mutex );

        std::pair<std::string , std::string> extracted = extract_file_hash ( message );
        const std::string& clean_message = extracted.first;
        const std::string& sha1_hash = extracted.second;

        std::string iso_timestamp = LogEntry::convert_to_iso ( original_timestamp );
        std::string level_str = log_level_to_string ( level );

        std::string dedup_key = iso_timestamp + xorstr_("|") + level_str + xorstr_("|") + clean_message + xorstr_("|") + sha1_hash;
        if ( level != LogLevel::DETECTION && level != LogLevel::CRITICAL ) {
            if ( !seen_entries_.insert ( dedup_key ).second )
                return;
        } else {
            seen_entries_.insert ( dedup_key );
        }

        nlohmann::json log_entry;
        log_entry [ xorstr_ ( "timestamp" ) ] = iso_timestamp;
        log_entry [ xorstr_ ( "type" ) ] = level_str;
        log_entry [ xorstr_ ( "message" ) ] = clean_message;
        if ( !sha1_hash.empty ( ) )
            log_entry [ xorstr_ ( "sha1" ) ] = sha1_hash;

        ensure_guard_seeded_locked();

        auto& g = log_tamper_guard::instance();
        if (g.seeded()) {
            const auto canonical = log_entry.dump(-1, ' ', false,
                                                  nlohmann::json::error_handler_t::replace);
            uint32_t seq = 0;
            uint8_t  tag[log_tamper_guard::chain_tag_len] = {};
            if (!g.append(canonical, seq, tag)) {
                return;
            }
            log_entry[xorstr_("seq")] = seq;
            char hex[log_tamper_guard::chain_tag_len * 2 + 1] = {};
            static const std::string H_storage = xorstr_("0123456789abcdef"); static const char* const H = H_storage.c_str();
            for (size_t i = 0; i < log_tamper_guard::chain_tag_len; ++i) {
                hex[i * 2]     = H[(tag[i] >> 4) & 0xF];
                hex[i * 2 + 1] = H[tag[i] & 0xF];
            }
            log_entry[xorstr_("ct")] = std::string(hex);
        }

        std::string pin = detect.pin;
        log_buffer_ [ pin ].push_back ( log_entry );
    }

    void ensure_guard_seeded_locked() noexcept {
        if (guard_seeded_ || guard_seed_attempted_) return;
        auto& v2 = telemetry_v2::shared_session();
        if (!v2.is_open()) return;

        uint8_t chain_key[log_tamper_guard::chain_state_len] = {};
        uint8_t seal_key[log_tamper_guard::seal_key_len]     = {};
        uint8_t sbind[log_tamper_guard::sid_bind_len]        = {};
        if (!telemetry_v2::derive_log_chain_key(chain_key))    return;
        if (!telemetry_v2::derive_log_entry_seal_key(seal_key)) {
            SecureZeroMemory(chain_key, sizeof(chain_key));
            return;
        }
        if (!telemetry_v2::session_bind_material(sbind)) {
            SecureZeroMemory(chain_key, sizeof(chain_key));
            SecureZeroMemory(seal_key, sizeof(seal_key));
            return;
        }

        uint64_t bind = (uint64_t(GetTickCount()) << 32) | uint64_t(GetCurrentProcessId());
        auto& g = log_tamper_guard::instance();
        const bool ok = g.seed(chain_key, seal_key, sbind, bind);

        SecureZeroMemory(chain_key, sizeof(chain_key));
        SecureZeroMemory(seal_key, sizeof(seal_key));
        SecureZeroMemory(sbind, sizeof(sbind));

        guard_seed_attempted_ = true;
        guard_seeded_         = ok;
    }

    static constexpr size_t kMaxLogsPerFlag = 500;

    static std::string derive_flag_key ( const std::string& type , const std::string& message ) {
        size_t colon = message.find ( ':' );

        size_t path = std::string::npos;
        for ( size_t i = 0; i + 2 < message.size ( ); ++i ) {
            char c = message[ i ];
            bool is_alpha = ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' );
            if ( is_alpha && message[ i + 1 ] == ':' &&
                 ( message[ i + 2 ] == '\\' || message[ i + 2 ] == '/' ) ) {
                path = i;
                break;
            }
        }

        size_t cut = ( colon < path ) ? colon : path;
        std::string category = ( cut == std::string::npos ) ? message : message.substr ( 0 , cut );
        if ( category.size ( ) < 2 ) category = message;

        std::string normalized;
        normalized.reserve ( category.size ( ) );
        for ( char c : category ) {
            if ( c >= '0' && c <= '9' ) normalized += '#';
            else if ( c >= 'A' && c <= 'Z' ) normalized += static_cast< char >( c + 32 );
            else normalized += c;
        }
        while ( !normalized.empty ( ) && normalized.back ( ) == ' ' )
            normalized.pop_back ( );

        return type + xorstr_("|") + normalized;
    }

    void cap_logs_per_flag ( ) {
        std::lock_guard<std::mutex> lock ( log_mutex );

        for ( auto& [ pin , logs ] : log_buffer_ ) {
            if ( logs.size ( ) <= kMaxLogsPerFlag ) continue;

            std::unordered_map<std::string , std::vector<size_t>> groups;
            groups.reserve ( logs.size ( ) );
            for ( size_t i = 0; i < logs.size ( ); ++i ) {
                const auto& entry = logs[ i ];
                std::string type = entry.value ( xorstr_ ( "type" ) , std::string{} );
                std::string message = entry.value ( xorstr_ ( "message" ) , std::string{} );
                groups[ derive_flag_key ( type , message ) ].push_back ( i );
            }

            std::vector<char> keep ( logs.size ( ) , 1 );
            const std::string na = xorstr_ ( "N/A" );

            for ( auto& [ key , indices ] : groups ) {
                if ( indices.size ( ) <= kMaxLogsPerFlag ) continue;

                std::sort ( indices.begin ( ) , indices.end ( ) ,
                    [ & ] ( size_t a , size_t b ) {
                        std::string ta = logs[ a ].value ( xorstr_ ( "timestamp" ) , std::string{} );
                        std::string tb = logs[ b ].value ( xorstr_ ( "timestamp" ) , std::string{} );
                        if ( ta == na ) ta.clear ( );
                        if ( tb == na ) tb.clear ( );
                        if ( ta != tb ) return ta > tb;
                        return a > b;
                    } );

                for ( size_t k = kMaxLogsPerFlag; k < indices.size ( ); ++k )
                    keep[ indices[ k ] ] = 0;
            }

            std::vector<nlohmann::json> filtered;
            filtered.reserve ( logs.size ( ) );
            for ( size_t i = 0; i < logs.size ( ); ++i )
                if ( keep[ i ] )
                    filtered.push_back ( std::move ( logs[ i ] ) );

            logs = std::move ( filtered );
        }
    }

    static std::string compute_file_sha1 ( const std::string& path ) noexcept {
        static constexpr LONGLONG kMaxFileSize = 200LL * 1024 * 1024;

        static std::unordered_map<std::string, std::string> cache;
        static std::mutex                                   cache_mtx;

        try {
            if ( path.empty ( ) ) return {};

            {
                std::lock_guard<std::mutex> lk ( cache_mtx );
                auto it = cache.find ( path );
                if ( it != cache.end ( ) ) return it->second;
            }

            HANDLE hFile = CreateFileA (
                path.c_str ( ) ,
                GENERIC_READ ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE ,
                nullptr ,
                OPEN_EXISTING ,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN ,
                nullptr );
            if ( hFile == INVALID_HANDLE_VALUE ) {
                std::lock_guard<std::mutex> lk ( cache_mtx );
                cache.emplace ( path , std::string{} );
                return {};
            }

            LARGE_INTEGER size{};
            if ( GetFileSizeEx ( hFile , &size ) ) {
                if ( size.QuadPart <= 0 || size.QuadPart > kMaxFileSize ) {
                    CloseHandle ( hFile );
                    std::lock_guard<std::mutex> lk ( cache_mtx );
                    cache.emplace ( path , std::string{} );
                    return {};
                }
            }

            EVP_MD_CTX* ctx = EVP_MD_CTX_new ( );
            if ( !ctx ) {
                CloseHandle ( hFile );
                return {};
            }
            if ( EVP_DigestInit_ex ( ctx , EVP_sha1 ( ) , nullptr ) != 1 ) {
                EVP_MD_CTX_free ( ctx );
                CloseHandle ( hFile );
                return {};
            }

            std::vector<unsigned char> buffer ( 64 * 1024 );
            DWORD                       got = 0;
            while ( ReadFile ( hFile , buffer.data ( ) , static_cast< DWORD >( buffer.size ( ) ) , &got , nullptr ) && got > 0 ) {
                if ( EVP_DigestUpdate ( ctx , buffer.data ( ) , got ) != 1 ) {
                    EVP_MD_CTX_free ( ctx );
                    CloseHandle ( hFile );
                    return {};
                }
            }
            CloseHandle ( hFile );

            unsigned char hash[ EVP_MAX_MD_SIZE ]{};
            unsigned int  len = 0;
            if ( EVP_DigestFinal_ex ( ctx , hash , &len ) != 1 || len == 0 ) {
                EVP_MD_CTX_free ( ctx );
                return {};
            }
            EVP_MD_CTX_free ( ctx );

            auto nibble_to_hex = [ ] ( unsigned char nib ) -> char {
                return static_cast< char >( nib < 10 ? ( '0' + nib ) : ( 'a' + ( nib - 10 ) ) );
            };

            std::string out;
            out.reserve ( static_cast< size_t >( len ) * 2 );
            for ( unsigned int i = 0; i < len; ++i ) {
                out.push_back ( nibble_to_hex ( ( hash[ i ] >> 4 ) & 0xF ) );
                out.push_back ( nibble_to_hex ( hash[ i ] & 0xF ) );
            }

            {
                std::lock_guard<std::mutex> lk ( cache_mtx );
                cache[ path ] = out;
            }
            return out;
        }
        catch ( ... ) {
            return {};
        }
    }

    static std::pair<std::string , std::string> extract_file_hash ( const std::string& message ) noexcept {
        try {
            if ( message.empty ( ) ) return { message , std::string{} };

            const std::string sha1_marker = xorstr_ ( " | SHA1=" );
            const std::string sha256_marker = xorstr_ ( " | SHA256=" );

            auto to_lower_ascii = [ ] ( std::string& s ) {
                for ( auto& c : s ) {
                    if ( c >= 'A' && c <= 'Z' ) c = static_cast< char >( c + 32 );
                }
                };

            auto try_marker = [ & ] ( const std::string& marker , size_t expected_hex_len )
                -> std::pair<std::string , std::string> {
                size_t pos = message.find ( marker );
                if ( pos == std::string::npos ) return { std::string{} , std::string{} };

                size_t hash_start = pos + marker.size ( );
                size_t hash_end = hash_start;
                while ( hash_end < message.size ( ) &&
                        hash_end - hash_start < expected_hex_len ) {
                    char c = message[ hash_end ];
                    bool is_hex = ( c >= '0' && c <= '9' ) ||
                                  ( c >= 'a' && c <= 'f' ) ||
                                  ( c >= 'A' && c <= 'F' );
                    if ( !is_hex ) break;
                    ++hash_end;
                }
                if ( hash_end - hash_start != expected_hex_len )
                    return { std::string{} , std::string{} };

                std::string hash = message.substr ( hash_start , expected_hex_len );
                to_lower_ascii ( hash );

                std::string cleaned;
                cleaned.reserve ( message.size ( ) - ( marker.size ( ) + expected_hex_len ) );
                cleaned.append ( message , 0 , pos );
                cleaned.append ( message , hash_end , std::string::npos );
                return { cleaned , hash };
                };

            auto explicit_sha1 = try_marker ( sha1_marker , 40 );
            if ( !explicit_sha1.second.empty ( ) ) return explicit_sha1;
            auto explicit_sha256 = try_marker ( sha256_marker , 64 );
            if ( !explicit_sha256.second.empty ( ) ) return explicit_sha256;

            if ( message.size ( ) < 4 ) return { message , std::string{} };

            size_t bestPos = std::string::npos;
            for ( size_t i = 0; i + 2 < message.size ( ); ++i ) {
                char c = message[ i ];
                if ( !( ( c >= 'A' && c <= 'Z' ) || ( c >= 'a' && c <= 'z' ) ) ) continue;
                if ( message[ i + 1 ] != ':' ) continue;
                char c2 = message[ i + 2 ];
                if ( c2 != '\\' && c2 != '/' ) continue;
                if ( i > 0 ) {
                    char prev = message[ i - 1 ];
                    if ( ( prev >= 'A' && prev <= 'Z' ) ||
                         ( prev >= 'a' && prev <= 'z' ) ||
                         ( prev >= '0' && prev <= '9' ) ) {
                        continue;
                    }
                }
                bestPos = i;
            }
            if ( bestPos == std::string::npos ) return { message , std::string{} };

            size_t end = bestPos;
            while ( end < message.size ( ) ) {
                char c = message[ end ];
                if ( c == '\r' || c == '\n' || c == '\t' ||
                     c == '|'  || c == '*'  || c == '?'  ||
                     c == '<'  || c == '>'  || c == '"' ) break;
                ++end;
            }

            std::string path ( message , bestPos , end - bestPos );
            while ( !path.empty ( ) ) {
                char back = path.back ( );
                if ( back == ' '  || back == '.' || back == ',' ||
                     back == ';'  || back == ')' || back == ']' ||
                     back == '}'  || back == '\'' ) {
                    path.pop_back ( );
                }
                else break;
            }
            if ( path.size ( ) < 4 ) return { message , std::string{} };

            DWORD attr = GetFileAttributesA ( path.c_str ( ) );
            if ( attr == INVALID_FILE_ATTRIBUTES ) return { message , std::string{} };
            if ( attr & FILE_ATTRIBUTE_DIRECTORY ) return { message , std::string{} };

            std::string sha1 = compute_file_sha1 ( path );
            if ( sha1.empty ( ) ) return { message , std::string{} };

            return { message , sha1 };
        }
        catch ( ... ) {
            return { message , std::string{} };
        }
    }

    std::string log_level_to_string ( LogLevel level ) {
        switch ( level ) {
            case LogLevel::INFO: return xorstr_ ( "INFO" );
            case LogLevel::WARNING: return xorstr_ ( "WARNING" );
            case LogLevel::CRITICAL: return xorstr_ ( "CRITICAL" );
            case LogLevel::DETECTION: return xorstr_ ( "DETECTION" );
            default: return xorstr_ ( "UNKNOWN" );
        }
    }

    std::string base64_encode(const unsigned char* data, size_t length)
    {
        BIO* bio, * b64;
        BUF_MEM* bufferPtr;

        b64 = BIO_new(BIO_f_base64());
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); 
        bio = BIO_new(BIO_s_mem());
        BIO_push(b64, bio);

        BIO_write(b64, data, length);
        BIO_flush(b64);

        BIO_get_mem_ptr(bio, &bufferPtr);
        std::string encoded(bufferPtr->data, bufferPtr->length);

        BIO_free_all(b64);
        return encoded;
    }

    bool send_legacy_payload(const nlohmann::json& log_json, const std::string& pin)
    {
        unsigned char key[32] = {};
        const size_t key_len = (std::min)(pin.size(), sizeof(key));
        std::memcpy(key, pin.data(), key_len);

        unsigned char iv[16] = {};
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            SecureZeroMemory(key, sizeof(key));
            return false;
        }

        const std::string plaintext = log_json.dump();
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            SecureZeroMemory(key, sizeof(key));
            SecureZeroMemory(iv, sizeof(iv));
            return false;
        }

        std::vector<unsigned char> ciphertext(
            plaintext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
        int written = 0;
        int total = 0;
        bool encrypted = EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv) == 1;
        if (encrypted) {
            encrypted = EVP_EncryptUpdate(
                ctx,
                ciphertext.data(),
                &written,
                reinterpret_cast<const unsigned char*>(plaintext.data()),
                static_cast<int>(plaintext.size())) == 1;
            total = written;
        }
        if (encrypted) {
            encrypted = EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &written) == 1;
            total += written;
        }
        EVP_CIPHER_CTX_free(ctx);
        SecureZeroMemory(key, sizeof(key));

        if (!encrypted) {
            SecureZeroMemory(iv, sizeof(iv));
            if (!ciphertext.empty()) SecureZeroMemory(ciphertext.data(), ciphertext.size());
            return false;
        }

        const std::string payload = base64_encode(iv, sizeof(iv)) + xorstr_(":") +
            base64_encode(ciphertext.data(), static_cast<size_t>(total));
        SecureZeroMemory(iv, sizeof(iv));
        if (!ciphertext.empty()) SecureZeroMemory(ciphertext.data(), ciphertext.size());

        unsigned char request_nonce[16] = {};
        if (RAND_bytes(request_nonce, sizeof(request_nonce)) != 1) return false;

        nlohmann::json request = nlohmann::json::object();
        request[xorstr_("GetCurrentProcess")] = base64_encode(request_nonce, sizeof(request_nonce));
        request[xorstr_("data")] = payload;
        SecureZeroMemory(request_nonce, sizeof(request_nonce));

        const std::string url = xorstr_("https://detect.ac/auth/api/sessions/upload/") + pin;
        const std::string post_data = request.dump();
        const std::string content_type = xorstr_("Content-Type: application/json");
        const std::string accept = xorstr_("Accept: application/json");
        const std::string no_proxy = xorstr_("*");
        const std::string https_only = xorstr_("https");
        const std::string spki = telemetry_v2::spki_pin();

        CURL* curl = curl_easy_init();
        if (!curl) return false;

        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, content_type.c_str());
        headers = curl_slist_append(headers, accept.c_str());

        std::string response;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(post_data.size()));
        curl_easy_setopt(curl, CURLOPT_COPYPOSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_call);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, static_cast<long>(CURLSSLOPT_NATIVE_CA));
        curl_easy_setopt(curl, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
        curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, spki.c_str());
        curl_easy_setopt(curl, CURLOPT_PROXY, "");
        curl_easy_setopt(curl, CURLOPT_NOPROXY, no_proxy.c_str());
        curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, https_only.c_str());
        curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, https_only.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

        const CURLcode rc = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK || status != 200) return false;

        const auto parsed = nlohmann::json::parse(response.begin(), response.end(), nullptr, false);
        return !parsed.is_discarded() && parsed.is_object() &&
            parsed.value(xorstr_("status"), std::string{}) == xorstr_("success");
    }


    static size_t write_call ( void* contents , size_t size , size_t nmemb , std::string* userp ) {
        userp->append ( static_cast< char* >( contents ) , size * nmemb );
        return size * nmemb;
    }

    std::string file_path;
    std::mutex log_mutex;
    std::unordered_map<std::string , std::vector<nlohmann::json>> log_buffer_;
    std::unordered_set<std::string> seen_entries_;
    bool guard_seeded_ = false;
    bool guard_seed_attempted_ = false;
};

#define LOG(level, timestamp) Logger::instance()(Logger::LogLevel::level, timestamp)
