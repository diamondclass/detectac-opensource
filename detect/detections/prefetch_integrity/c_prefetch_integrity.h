#pragma once

#include "../../pch.h"

class PrefetchIntegrity {
public:
    static void start_prefetch_integrity();
    static void check_prefetch_registry();
    static bool HasMAMSignature(const std::string& filePath);

private:
    struct FileInfo {
        std::string   path;
        std::string   name;
        std::string   sha1;
        bool          readOnly;
        bool          hasMAMSig;
    };

    static std::string ComputeSHA1(const std::string& filePath);
    static bool IsReadOnly(const std::string& filePath);
};

inline auto c_prefint = std::make_unique<PrefetchIntegrity>();