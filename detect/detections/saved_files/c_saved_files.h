#pragma once

#include "../../pch.h"

class SavedFiles
{
public:
    struct SuspectFile {
        std::wstring path;
        bool onDisk;
        bool isSigned;
        std::wstring timestamp;
    };

    static void start_saved_files();

private:
    static bool IsPEExtension(const std::wstring& path);
    static bool HasMZHeader(const wchar_t* path);
    static bool IsSignedFile(const wchar_t* filePath);
    static std::wstring FileTimeToString(const FILETIME& ft);
    static std::vector<SuspectFile> GetSuspectPEFiles();
    static std::string ToNarrow(const std::wstring& ws);
};

inline auto c_saved = std::make_unique<SavedFiles>();
