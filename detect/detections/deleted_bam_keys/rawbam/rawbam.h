#pragma once

#include "../c_deleted_bam.h"

#pragma pack(push, 1)

struct hive_header {
    char signature[4];
    uint32_t primary_sequence;
    uint32_t secondary_sequence;
    int64_t timestamp;
    uint32_t major_version;
    uint32_t minor_version;
    uint32_t type;
    uint32_t format;
    uint32_t root_cell_offset;
    uint32_t length;
    uint32_t checksum;
    char reserved1[0x398];
    char boot_type[0x200];
    char boot_id[0x200];
};

struct hbin_header {
    char signature[4];
    uint32_t offset;
    uint32_t size;
    int64_t reserved;
    int64_t timestamp;
    uint32_t spare;
};

struct cell_header {
    int32_t size;
};

struct nk_record {
    char signature[2];
    uint16_t flags;
    int64_t timestamp;
    uint32_t parent_offset;
    uint32_t subkey_count;
    uint32_t subkey_list_offset;
    uint32_t value_count;
    uint32_t value_list_offset;
    uint32_t security_offset;
    uint32_t class_name_offset;
};

struct vk_record {
    char signature[2];
    uint16_t name_length;
    uint32_t data_size;
    uint32_t data_offset;
    uint32_t data_type;
    uint16_t flags;
    uint16_t spare;
};

#pragma pack(pop)

struct nk_entry {
    size_t file_offset;
    size_t payload_size;
    std::string name;
    uint32_t parent_raw;
    int parent_index;
    uint32_t value_count;
    uint32_t value_list_raw;
};

struct vk_entry {
    size_t file_offset;
    size_t payload_size;
    std::string name;
    uint32_t data_size;
    uint32_t data_offset;
    uint32_t data_type;
};

class HiveParser {
public:
    static std::vector<std::string> start_raw_bam();
    static int hive_list_values_recursive(const char* hive_path, const char* target_path, std::vector<std::string>& results);
    static std::vector<std::string> enumerate_target_keys();

private:
    static uint16_t read_u16_le(const unsigned char* p);
    static uint32_t read_u32_le(const unsigned char* p);
    static std::string utf16le_to_utf8(const std::u16string& input);
    static bool likely_utf16_le(const unsigned char* p, size_t bytes);
    static std::string try_utf16_as_bytes(const unsigned char* p, size_t bytes);
    static std::string try_ascii_preview(const unsigned char* p, size_t len);
    static bool starts_with(const unsigned char* p, size_t remaining, const char* s, size_t n);
    static std::string extract_nk_name(const unsigned char* p, size_t payload_size);
    static std::string extract_vk_name(const unsigned char* cell_ptr, size_t payload_size);
    static std::vector<size_t> resolve_value_list_offsets(uint32_t vl_raw, uint32_t value_count,
        const unsigned char* data, size_t filesize, const std::vector<size_t>& vk_cell_offsets);
    static bool resolve_data_pointer(uint32_t data_raw, uint32_t want_size,
        const std::vector<size_t>& hbin_payload_starts,
        const unsigned char* data_base, size_t filesize,
        const std::vector<size_t>&, const unsigned char*& out_ptr, size_t& out_avail);
    static std::string device_path_to_dos(const std::string& device_path);
    static bool is_drive_path(const std::string& path);
    static void print_values_recursive(int nk_index,
        const std::vector<nk_entry>& nks,
        const std::vector<vk_entry>& vks,
        const std::vector<size_t>& vk_offsets,
        const std::vector<size_t>& hbin_payload_starts,
        const unsigned char* data,
        size_t filesize,
        const std::vector<size_t>& all_cell_offsets,
        const std::unordered_map<size_t, int>& vk_offset_to_index,
        int depth, std::vector<std::string>& results);
};
