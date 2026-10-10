#include "detection_root.h"
#include <thread>
#include <future>
#include <vector>
#include <queue>
#include <functional>
#include <mutex>
#include <condition_variable>
#include "../utils/logger/logger.h"
#include "../utils/crypt/crypto_init.h"
#include "../scan_api/telemetry_v2.hpp"
#include "../scan_api/telemetry_v2_keys.hpp"
#include "../utils/protection/integrity_heartbeat.hpp"
#include <shellapi.h>

static void open_local_report ( const std::string& path ) {
    if ( path.empty ( ) ) return;
    std::wstring wpath;
    wpath.reserve ( path.size ( ) );
    for ( char c : path ) wpath.push_back ( static_cast<wchar_t> ( static_cast<unsigned char> ( c ) ) );
    ShellExecuteW ( NULL , L"open" , wpath.c_str ( ) , NULL , NULL , SW_SHOWNORMAL );
}

std::unique_ptr<c_scanapi> c_detection::scan_api = nullptr;

class thread_pool
{
public:
    explicit thread_pool ( size_t threads )
    {
        for ( size_t i = 0; i < threads; ++i )
        {
            workers.emplace_back ( [this] {
                for ( ;;)
                {
                    std::function<void ( )> task;

                    {
                        std::unique_lock<std::mutex> lock ( queue_mutex );
                        condition.wait ( lock , [this] { return stop || !tasks.empty ( ); } );
                        if ( stop && tasks.empty ( ) ) return;
                        task = std::move ( tasks.front ( ) );
                        tasks.pop ( );
                    }

                    task ( );
                }
            } );
        }
    }

    ~thread_pool ( )
    {
        {
            std::unique_lock<std::mutex> lock ( queue_mutex );
            stop = true;
        }
        condition.notify_all ( );
        for ( std::thread& worker : workers ) worker.join ( );
    }

    template<class F>
    std::future<void> enqueue ( F&& f )
    {
        auto task = std::make_shared<std::packaged_task<void ( )>> ( std::forward<F> ( f ) );
        std::future<void> res = task->get_future ( );
        {
            std::unique_lock<std::mutex> lock ( queue_mutex );
            tasks.emplace ( [ task ] ( ) { ( *task )( ); } );
        }
        condition.notify_one ( );
        return res;
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void ( )>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop = false;
};

std::string c_detection::get_stage_message ( int stage_number ) {
    static const std::string messages [ 13 ]
    {
         ( xorstr_("Initializing scan...")),
         ( xorstr_("Scanning file paths, Windows Artifacts...")),
         ( xorstr_("Analysing data for cheat traces...") ),
         ( xorstr_("Checking Windows Artifacts for bypass method traces...") ),
         ( xorstr_("Checking accessible memory for cheat traces...") ),
         ( xorstr_("Scanning for custom strings...") ),
         ( xorstr_("Authenticating devices in Windows Artifacts...") ),
         ( xorstr_("Checking system safety...") ),
         ( xorstr_("Checking Windows Artifacts for application usage traces...") ),
         ( xorstr_("Performing game specific checks...") ),
         ( xorstr_("Analysing all the gathered data for cheats, bypasses... This may take a while...") ),
         ( xorstr_("Completing scan, generating & uploading results")),
         ( xorstr_("Uploading logs, please wait..."))
    };
    if ( stage_number >= 1 && stage_number <= 13 ) return messages [ stage_number - 1 ];
    return  ( xorstr_("Scanning...") );
}

void c_detection::heartbeat_thread ( const std::string& pin , std::atomic<bool>& running )
{
    auto& v2 = telemetry_v2::shared_session ( );

    CURL* curl = nullptr;
    const std::string url  = xorstr_("https://detect.ac/auth/api/scanning/ping/") + pin;
    const std::string spki = telemetry_v2::spki_pin ( );

    auto make_legacy_handle = [ & ] ( ) -> CURL* {
        CURL* h = curl_easy_init ( );
        if ( !h ) return nullptr;
        curl_easy_setopt ( h , CURLOPT_URL , url.c_str ( ) );
        curl_easy_setopt ( h , CURLOPT_POST , 1L );
        curl_easy_setopt ( h , CURLOPT_POSTFIELDS , "" );
        curl_easy_setopt ( h , CURLOPT_SSL_VERIFYPEER , 1L );
        curl_easy_setopt ( h , CURLOPT_SSL_VERIFYHOST , 2L );
        curl_easy_setopt ( h , CURLOPT_SSL_OPTIONS , ( long ) CURLSSLOPT_NATIVE_CA );
        curl_easy_setopt ( h , CURLOPT_SSLVERSION , ( long ) CURL_SSLVERSION_TLSv1_2 );
        curl_easy_setopt ( h , CURLOPT_PINNEDPUBLICKEY , spki.c_str ( ) );
        curl_easy_setopt ( h , CURLOPT_PROTOCOLS_STR , xorstr_("https") );
        curl_easy_setopt ( h , CURLOPT_REDIR_PROTOCOLS_STR , xorstr_("https") );
        curl_easy_setopt ( h , CURLOPT_FOLLOWLOCATION , 0L );
        curl_easy_setopt ( h , CURLOPT_MAXREDIRS , 0L );
        curl_easy_setopt ( h , CURLOPT_PROXY , "" );
        curl_easy_setopt ( h , CURLOPT_NOPROXY , xorstr_("*") );
        curl_easy_setopt ( h , CURLOPT_CONNECTTIMEOUT , 10L );
        curl_easy_setopt ( h , CURLOPT_TIMEOUT , 15L );
        curl_easy_setopt ( h , CURLOPT_NOSIGNAL , 1L );
        return h;
    };

    while ( running )
    {
        if ( v2.is_open ( ) )
        {
            ( void ) v2.send_heartbeat ( );
        }
        else
        {
            if ( !curl ) curl = make_legacy_handle ( );
            if ( curl ) ( void ) curl_easy_perform ( curl );
        }

        for ( int i = 0; i < 10 && running; ++i ) std::this_thread::sleep_for ( std::chrono::seconds ( 1 ) );
    }
    if ( curl ) curl_easy_cleanup ( curl );
}

void c_detection::start_scan ( )
{
    CryptoInit::EnsureInitialized ( );

    detect.scan_started = true;

    auto running = std::make_shared<std::atomic<bool>>(true);

    struct stop_heartbeat_guard {
        std::shared_ptr<std::atomic<bool>> flag;
        ~stop_heartbeat_guard() {
            if (flag) flag->store(false, std::memory_order_release);
        }
    } _hb_guard{ running };

    std::thread hb_thread ( [ running ] ( )
    {
        heartbeat_thread ( detect.pin , *running );
    } );
    hb_thread.detach ( );

    if ( !scan_api ) scan_api = std::make_unique<c_scanapi> ( xorstr_("https://detect.ac/auth") , detect.pin );

    // Best effort: the scan continues offline (local HTML report) when the
    // server is unreachable, so a failed handshake must not abort the scan.
    scan_api->start_scan ( );

    Logger::instance ( ).ensure_guard_seeded ( );

    {
        const auto seed_snap = integrity_snapshot::capture ( );
        char seed_buf[512];
        int n = _snprintf_s ( seed_buf , _TRUNCATE ,
            xorstr_("{\"type\":\"INTEGRITY_SEED\",\"bits\":%u,\"bad_mods\":%u,\"bad_drv\":%u,\"mod_count\":%u,\"drv_count\":%u,\"boot\":%llu}") ,
            seed_snap.bits , seed_snap.bad_modules , seed_snap.bad_drivers ,
            seed_snap.module_count , seed_snap.driver_count ,
            static_cast<unsigned long long> ( seed_snap.boot_time_seconds ) );
        if ( n > 0 ) {
            uint32_t seed_seq = 0;
            uint8_t  seed_tag[log_tamper_guard::chain_tag_len] = {};
            log_tamper_guard::instance ( ).append (
                std::string_view ( seed_buf , static_cast<size_t> ( n ) ) , seed_seq , seed_tag );
        }
    }

    integrity_heartbeat::instance ( ).start ( 5 );

    size_t num_threads = std::thread::hardware_concurrency ( );
    thread_pool pool ( num_threads > 0 ? num_threads : 8 );
    std::vector<std::future<void>> futures;

    // No-PIN / offline mode: nothing below depends on the server, so skip the
    // blocking server-status check (it could stall the scan for minutes).
    std::atomic<size_t> completed_tasks { 0 };

    if ( !detect.scanned )
    {
        if ( c_test->is_test_signing_enabled ( ) )
        {
            LOG ( DETECTION , xorstr_("N/A") ) << xorstr_("Test Signing Is Enabled");
            LOG ( INFO , xorstr_("N/A") ) << xorstr_("Scan will not proceed; critical detections found");
            detect.report_path = Logger::instance ( ).save_local_html_report ( );
            Logger::instance ( ).flush_logs ( );
            detect.scanned = true;
            open_local_report ( detect.report_path );
            return;
        }

    #ifdef DETECT_MINECRAFT
        detect.i_total_stages = 81;
    #elif DETECT_FIVEM
        detect.i_total_stages = 78;
    #elif DETECT_ROBLOX
        detect.i_total_stages = 75;
    #elif DETECT_FORTNITE
        detect.i_total_stages = 51;
    #elif DETECT_FREEFIRE
        detect.i_total_stages = 73;
    #elif DETECT_DAYZ
        detect.i_total_stages = 71;
    #elif DETECT_SIEGE
        detect.i_total_stages = 72;
    #elif DETECT_RUST
        detect.i_total_stages = 72;
    #elif DETECT_COD
        detect.i_total_stages = 72;
    #elif DETECT_CS
        detect.i_total_stages = 72;
    #endif
    
#ifndef DETECT_FORTNITE

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_usn_journal_size->start_usn_journal_size_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_powershell_commands_ran->start_powershell_evtx_commands(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_diffd->start_diff_drive_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_club->start_club44_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_asar->asar_checks(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_wmi->start_wmi(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_task2->start_taskschedule_checks(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_sus_threads->start_suspeced_threads_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cleared_evt->start_cleared_eventlog(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_bam->start_bam_state_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_mod_check->start_modified_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_injdll->start_opensavemidlmru_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_res_ser->start_restarted_services_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_term_ser->StartTerminationCheck(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_usnjrnl2->start_usn_modified2(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_time->start_timechange(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_dllh->start_dllh_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_peinj->start_pe_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_peinj2->start_pe_injection_2_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_h_and_p->start_hosts_and_prefetch(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_powershell_logsize->start_powershell_logsize_check(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_powershell_profiles->checkProfiles(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_regscan->start_Regsitry_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_prefbp->start_prefetch_bypass_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_prefint->start_prefetch_integrity(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_evt_byp->start_eventlog_bypass(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cpl->CheckCPLBypass(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_msi->CheckMSIBypass(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_reg->CheckREGBypass(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_inf->CheckINFBypass(); utils->increment_progress(); ++completed_tasks; }));
         
    #endif

    #ifdef DETECT_MINECRAFT

        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_atlas->start_atlas_trace_scan ( ); utils->increment_progress(); ++completed_tasks; } ) );

    #endif

    #if defined(DETECT_MINECRAFT) || defined(DETECT_FIVEM)

        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_fat32_2->start_fat32_2_modification_check ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_fat32->start_fat32_modification_check ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_junc->start_junc_scan(); utils->increment_progress(); ++completed_tasks; }));

    #endif

        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_usn_journal_modified->start_usn_journal_modified_check ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_executed_files->start_executed_file_checks ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_device_rm->start_dev_rm_checks ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_created_disk_part->start_created_part_checks ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_deleted_disk_part->start_deleted_part_checks ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_recycle_bin_modified->start_recycle_bin_modified_checks ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_service->start_service_checks ( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_ahk->start_ahk_bypass_detections( ); utils->increment_progress(); ++completed_tasks; } ) );
        futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_prefcheck->start_enableprefetcherdeletion(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_letvol->start_letterless_volume_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_usbbypass->start_usb_bypass_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_usnbypasschecks->start_usn_bypass_checks(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_vpn->start_vpn_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_install->print_install_date_and_elapsed_time(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_pc_start->start_pc_start_time_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_sy->start_systeminfo_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_tone->term_onedrive(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cb->start_cmd_and_bat_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_py_ex->start_python_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_vbs->start_vbs_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_dma_pads->start_dma_pads(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_dma_protection->start_dma_protection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_nvidia_patch->CheckNvidiaDriverPatch(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_browsers->start_browser_checks(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_bam_install->detect_bam_cleaned(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cpowershell->start_powershell_scans(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_delbam->start_del_bam(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_delregkeys->start_deleted_reg_keys_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cfg_check->start_cfg_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_discacc->ScanForDiscordUsernames(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cdump->start_crashdump_checks(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_efidet->start_efi_detections(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_efi_mb->start_efi_measured_boot(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_prefdel->start_deleted_prefetch(); utils->increment_progress(); ++completed_tasks; }));
        
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_lsass->start_lsass_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_pcasvc->start_pca_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_usnjrnl_ex->start_scan_ex(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_evt_exp->start_eventlog_exploit_check(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_yara->start_yara_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_prefinj->start_prefetch_injections(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_adminran->start_files_ran_with_admin(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_commands3->start_commands_3(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_ads->start_sus_ads(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_autoruns->start_autoruns_detection(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_dns->start_dns_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_compilation->compilation_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_usnjrnl->start_usn_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_exe_pf->start_exe_pf_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_explorer_strings->start_explorer_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_amc->start_amcache_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_ss->start_ss_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_dbu->start_windb_urls(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_windef->QueryDefenderHistory(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_vhd->start_vhd_detection(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_luascripts->start_luascripts_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_commands2->start_commands2(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_anydesk->start_anydesk_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_saved->start_saved_files(); utils->increment_progress(); ++completed_tasks; }));

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cdps->start_dps_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cdiag->start_diag_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_csys->start_sysmain_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_csgrm->start_sgrm_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_sgrm2->start_sgrm2_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cschedule->start_schedule_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_capp->start_appinfo_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_mps->start_mps_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cmsmpeng->start_mpssvc_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_ccrypt->start_cryptsvc_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cdusm->start_dusm_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_clogi->start_clogitech_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_discord->start_discord_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_chrome->start_chrome_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_edge->start_edge_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_brave->start_brave_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_opera->start_opera_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_vivaldi->start_vivaldi_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_firefox->start_firefox_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cfivem->start_cfivem_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cevt->start_evt_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_ctask->start_task_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_csi->start_si_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_crtb->start_runtimebroker_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_camcache->ProcessAmcache(); utils->increment_progress(); ++completed_tasks; }));

#ifdef DETECT_MINECRAFT

        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_cjavaw->start_cjavaw_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_winmg->start_winmg_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_jvmarg->start_jvm_arg_scan(); utils->increment_progress(); ++completed_tasks; }));
        futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_javainj->start_java_injection_scan(); utils->increment_progress(); ++completed_tasks; }));
#endif

    #if defined(DETECT_FORTNITE) || defined(DETECT_FIVEM) || defined(DETECT_SIEGE) || defined(DETECT_FREEFIRE)

            futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_fusers->start_hdmifuser_scan(); utils->increment_progress(); ++completed_tasks; }));
            futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_ddc->start_ddc_scan(); utils->increment_progress(); ++completed_tasks; }));
            futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_dma->start_pci_scanning(); utils->increment_progress(); ++completed_tasks; }));

    #endif

    #ifdef DETECT_SIEGE

            futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_r6alts->start_r6alt_scan(); utils->increment_progress(); ++completed_tasks; }));

    #endif

    #ifdef DETECT_FORTNITE

            futures.emplace_back(pool.enqueue([this, &completed_tasks] { c_epicalts->start_epic_alt_scan(); utils->increment_progress(); ++completed_tasks; }));

    #endif

    #ifdef DETECT_RUST

            futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_steam_alt->start_steam_alt_detection ( ); utils->increment_progress(); ++completed_tasks;  } ) );

    #endif

    #ifdef DETECT_MINECRAFT

            futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_game_instance->start_game_instance_detection ( ); utils->increment_progress(); ++completed_tasks; } ) );
            futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_mc_alts->start_mc_alts ( ); utils->increment_progress(); ++completed_tasks; } ) );

    #elif defined(DETECT_FIVEM) || defined(DETECT_SIEGE) || defined(DETECT_DAYZ) || defined(DETECT_CS)

            futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_steam_alt->start_steam_alt_detection ( ); utils->increment_progress(); ++completed_tasks;  } ) );
            futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_ai->scan_ai ( ); utils->increment_progress(); ++completed_tasks; } ) );

    #elif DETECT_ROBLOX

            futures.emplace_back ( pool.enqueue ( [this, &completed_tasks] { c_rblx->start_croblox_scan( ); utils->increment_progress(); ++completed_tasks;  } ) ); 

    #endif

        size_t total_futures = futures.size ( );
        size_t stages = 12;

        for ( size_t stage = 1; stage <= stages; ++stage ) {
            size_t next_stage_threshold = ( stage == stages )
                ? total_futures
                : ( total_futures * stage ) / stages;

            while ( completed_tasks.load ( ) < next_stage_threshold ) {
                std::this_thread::sleep_for ( std::chrono::milliseconds ( 100 ) );
            }

            std::string msg = get_stage_message ( static_cast< int >( stage ) );

            detect.current_stage_index.store ( static_cast< int >( stage ) , std::memory_order_release );
            if ( scan_api ) scan_api->update_stage ( static_cast< int >( stage ) , msg );
        }

        integrity_heartbeat::instance ( ).stop ( );

        {
            const int upload_stage = 13;
            const std::string upload_msg = get_stage_message ( upload_stage );
            detect.current_stage_index.store ( upload_stage , std::memory_order_release );
            if ( scan_api ) scan_api->update_stage ( upload_stage , upload_msg );
        }

        // Snapshot the in-memory logs into a local HTML report BEFORE flush_logs,
        // which uploads (best effort) and then clears the buffer.
        detect.report_path = Logger::instance ( ).save_local_html_report ( );

        Logger::instance ( ).flush_logs ( );

        std::vector<std::string> results = { xorstr_ ( "Scan completed successfully" ) };
        if ( scan_api ) scan_api->complete_scan ( results );
        else MessageBoxA ( NULL , xorstr_ ( "Error" ) , xorstr_ ( "Error In 2" ) , MB_OK );

        detect.scanned = true;
        detect.scan_started = false;
        detect.output_log = xorstr_ ("Finished." );
        if ( !detect.report_path.empty ( ) ) {
            detect.output_log += xorstr_ ( " Report saved: " ) + detect.report_path;
            open_local_report ( detect.report_path );
        }

    }
    else
    {
        if ( !detect.self_scan_flagged )
            detect.server_offline_failure = true;
        detect.output_log = xorstr_ ( "Failed." );
    }
}
