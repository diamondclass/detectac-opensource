#include "c_deleted_bam.h"

void file_utils::start_del_bam() {
    try{
    std::string src = xorstr_("C:\\Windows\\System32\\config\\SYSTEM");
    char tempPathBuffer[MAX_PATH];
    DWORD tempPathLength = GetEnvironmentVariableA(xorstr_("TEMP"), tempPathBuffer, MAX_PATH);
    if (tempPathLength == 0 || tempPathLength > MAX_PATH) {
        return;
    }
    std::string tempPath(tempPathBuffer);
    std::string fileName = file_utils::get_file_name(src);
    std::string dst = tempPath + xorstr_("\\") + fileName;

    DeleteFileA(dst.c_str());

    struct dst_guard {
        const std::string& p;
        ~dst_guard() { try { DeleteFileA(p.c_str()); } catch (...) {} }
    } _guard{ dst };

    unsigned long result = file_utils::raw_copy(src, dst);
    if (result != ERROR_SUCCESS) return;

    WIN32_FILE_ATTRIBUTE_DATA fad;
    if (!GetFileAttributesExA(dst.c_str(), GetFileExInfoStandard, &fad)) return;

    std::vector<std::string> live_results = RegistryUtils::start_live_bam();
    std::vector<std::string> raw_results = HiveParser::start_raw_bam();

    for (const auto& raw_item : raw_results) {
        if (std::find(live_results.begin(), live_results.end(), raw_item) == live_results.end()) {
            LOG ( WARNING , xorstr_("N/A")) << xorstr_("Deleted BAM Key: ") << raw_item;
        }
    }
    }
    catch (...) {}
}