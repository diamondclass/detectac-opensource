#pragma once

#include "../../pch.h"

inline bool read_file(const std::string& name, std::vector<char>& out) {
    try {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, name.data(),
                                       static_cast<int>(name.size()), nullptr, 0);
        std::wstring wpath;
        if (wlen > 0) {
            wpath.resize(static_cast<size_t>(wlen));
            MultiByteToWideChar(CP_UTF8, 0, name.data(),
                                static_cast<int>(name.size()),
                                wpath.data(), wlen);
        }

        HANDLE h = CreateFileW(
            wpath.empty() ? nullptr : wpath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER li{};
        if (!GetFileSizeEx(h, &li) || li.QuadPart < 0) {
            CloseHandle(h);
            return false;
        }
        // Prefetch files are always small; cap at 64 MB to guard
        // against a corrupted or hostile file reporting a huge size.
        if (li.QuadPart > (64ll << 20)) {
            CloseHandle(h);
            return false;
        }

        out.resize(static_cast<size_t>(li.QuadPart));

        size_t off = 0;
        while (off < out.size()) {
            DWORD want = static_cast<DWORD>(
                (std::min<size_t>)(out.size() - off, 1u << 20));
            DWORD got = 0;
            if (!ReadFile(h, out.data() + off, want, &got, nullptr)) {
                CloseHandle(h);
                return false;
            }
            if (got == 0) break;
            off += got;
        }
        CloseHandle(h);
        out.resize(off);
        return true;
    }
    catch (...) { return false; }
}

#define SETUP_VARIABLE( type, name, data, offset ) [[nodiscard]] type name const { type var; std::memcpy( &var,  ( data ) + ( offset ), sizeof( type ) ); return var; }

class prefetch_parser {
    std::vector<char> data;

public:
    explicit prefetch_parser(const std::string& file_path) {
        std::vector<char> content;
        if (!read_file(file_path, content) || content.size() < 0x100)
            return;

        if (content.at(0) == 'M' && content.at(1) == 'A' && content.at(2) == 'M') {
            using RtlDecompressBufferEx = NTSTATUS(__stdcall*)(
                USHORT CompressionFormat,
                PUCHAR UncompressedBuffer,
                ULONG UncompressedBufferSize,
                PUCHAR CompressedBuffer,
                ULONG CompressedBufferSize,
                PULONG FinalUncompressedSize,
                PVOID WorkSpace);
            using RtlGetCompressionWorkSpaceSize = NTSTATUS(__stdcall*)(
                USHORT CompressionFormatAndEngine,
                PULONG CompressBufferWorkSpaceSize,
                PULONG CompressFragmentWorkSpaceSize);

            static auto compression_workspace_size = reinterpret_cast<RtlGetCompressionWorkSpaceSize>(GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("RtlGetCompressionWorkSpaceSize")));
            static auto decompress_buffer_ex = reinterpret_cast<RtlDecompressBufferEx>(GetProcAddress(GetModuleHandleA(xorstr_("ntdll.dll")), xorstr_("RtlDecompressBufferEx")));

            std::span data_span(content.data(), 0x8);
            if (data_span.size() < static_cast<unsigned long long>(2) * 0x4)
                return;

            const auto signature = *reinterpret_cast<std::uint32_t*>(data_span.data());
            const auto decompressed_size = *reinterpret_cast<std::uint32_t*>(data_span.data() + 0x4);
            if ((signature & 0x00FFFFFF) != 0x004d414d)
                return;

            content.erase(content.begin(), content.begin() + 8);

            if ((signature & 0xF0000000) >> 28) {
                return;
            }

            const auto compression_format = (signature & 0x0F000000) >> 24;

            ULONG compressed_buffer_workspace_size = 0, compress_fragment_workspace_size = 0;
            if (compression_workspace_size(compression_format, reinterpret_cast<PULONG>(&compressed_buffer_workspace_size), reinterpret_cast<PULONG>(&compress_fragment_workspace_size)) != 0)
                return;


            std::vector<char> decompressed_data(decompressed_size);

            ULONG final_uncompressed_size;

            auto* const workspace = malloc(static_cast<size_t>(compressed_buffer_workspace_size));
            if (!workspace)
                return;

            if (decompress_buffer_ex(
                compression_format,
                reinterpret_cast<PUCHAR>(decompressed_data.data()),
                static_cast<ULONG>(decompressed_size),
                reinterpret_cast<PUCHAR>(content.data()),
                static_cast<ULONG>(content.size()),
                &final_uncompressed_size,
                workspace
            ) != 0) {
                free(workspace);
                return;
            }

            free(workspace);

            data = decompressed_data;
        }
        else if (content.at(4) == 'S' && content.at(5) == 'C' && content.at(6) == 'C' && content.at(7) == 'A')
            data = content;
    }

    SETUP_VARIABLE(int, version(), data.data(), 0x0)
        SETUP_VARIABLE(int, signature(), data.data(), 0x4)
        SETUP_VARIABLE(int, file_size(), data.data(), 0xC)
        SETUP_VARIABLE(int, file_name_strings_offset(), data.data(), 0x64)
        SETUP_VARIABLE(int, file_name_strings_size(), data.data(), 0x68)
        SETUP_VARIABLE(int, volume_information_offset(), data.data(), 0x6C)
        SETUP_VARIABLE(int, volumes_count(), data.data(), 0x70)
        SETUP_VARIABLE(int, volumes_information_size(), data.data(), 0x74)
        SETUP_VARIABLE(int, run_count(), data.data(), 0xd0)
        SETUP_VARIABLE(uintptr_t, executed_timestamp(), data.data(), 0x80)

        bool success() const {
        return !data.empty();
    }

    std::vector<std::wstring> get_filenames_strings() const {
        int offset = this->file_name_strings_offset();
        int size = this->file_name_strings_size();

        if (offset < 0 || size <= 0 ||
            static_cast<size_t>(offset) >= data.size() ||
            static_cast<size_t>(offset) + static_cast<size_t>(size) > data.size()) {
            return {};
        }

        std::vector<char> filenames;
        filenames.reserve(size);

        const auto begin = data.begin() + offset;
        std::copy_n(begin, size, std::back_inserter(filenames));

        std::vector<std::wstring> resources;
        std::wstring name;
        for (auto i = 0; i < filenames.size(); i += sizeof(wchar_t)) {
            const auto ch = *reinterpret_cast<const wchar_t*>(&filenames.at(i));
            if (ch == L'\0') {
                resources.push_back(name);
                name.clear();
                continue;
            }

            name.push_back(ch);
        }

        return resources;
    }

    std::array<time_t, 8> last_eight_execution_times() const {
        std::array<time_t, 8> times{};
        const auto filetime_to_timet = [](const FILETIME& ft) {
            ULARGE_INTEGER ull{};
            ull.LowPart = ft.dwLowDateTime;
            ull.HighPart = ft.dwHighDateTime;
            return static_cast<time_t>(ull.QuadPart / 10000000ULL - 11644473600ULL);
            };
        constexpr size_t execution_times_offset = 0x80;

        if (data.size() <= execution_times_offset) {
            return times;
        }

        size_t available_data = data.size() - execution_times_offset;
        size_t num_times = (std::min)(static_cast<size_t>(8), available_data / sizeof(ULARGE_INTEGER));

        for (size_t i = 0; i < num_times; ++i) {
            const size_t current_offset = execution_times_offset + (i * sizeof(ULARGE_INTEGER));

            if (current_offset + sizeof(ULARGE_INTEGER) <= data.size()) {
                ULARGE_INTEGER file_time{};
                std::memcpy(&file_time.QuadPart, data.data() + current_offset, sizeof(ULARGE_INTEGER));

                if (file_time.QuadPart != 0) {
                    const auto file_time_ptr = reinterpret_cast<const FILETIME*>(&file_time);
                    try {
                        times[i] = filetime_to_timet(*file_time_ptr);
                    }
                    catch (...) {
                    }
                }
            }
            else {
                break;
            }
        }

        return times;
    }


    time_t executed_time() const {
        const auto filetime_to_timet = [](const FILETIME& ft) -> time_t {
            ULARGE_INTEGER ull{};
            ull.LowPart = ft.dwLowDateTime;
            ull.HighPart = ft.dwHighDateTime;

            if (ull.QuadPart < 116444736000000000ULL) {
                return -1;
            }

            ULONGLONG seconds = ull.QuadPart / 10000000ULL - 11644473600ULL;
            if (seconds > 32535244799ULL) {
                return -1;
            }

            return static_cast<time_t>(seconds);
            };

        ULARGE_INTEGER file_time{};
        file_time.QuadPart = executed_timestamp();

        if (file_time.QuadPart == 0) {
            return -1;
        }

        const auto file_time_ptr = reinterpret_cast<const FILETIME*>(&file_time);
        return filetime_to_timet(*file_time_ptr);
    }
};