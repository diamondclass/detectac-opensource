#pragma once

#include "../../pch.h"
#include "livebam/livebam.h"
#include "rawbam/rawbam.h"

class file_utils {
public:

    static void start_del_bam();

    static std::string get_file_name(const std::string& path) {
        try{
        size_t pos = path.find_last_of(xorstr_("\\/"));
        return (pos != std::string::npos) ? path.substr(pos + 1) : path;
        }
        catch (...) { return ""; }
    }

    static unsigned long raw_copy(std::string src, std::string dst) {
        try{
        unsigned long result = ERROR_SUCCESS;
        HANDLE hFile = CreateFileA(src.c_str(), FILE_READ_ATTRIBUTES,
            (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string szDrive = src.substr(0, 2);
            DWORD dwSectorPerCluster;
            DWORD dwBytesPerSector;
            if (GetDiskFreeSpaceA(szDrive.c_str(), &dwSectorPerCluster, &dwBytesPerSector, NULL, NULL)) {
                LARGE_INTEGER liFileSize;
                DWORD dwRead, dwWritten;
                DWORD dwClusterSize = (dwBytesPerSector * dwSectorPerCluster);
                liFileSize.LowPart = GetFileSize(hFile, (LPDWORD)&liFileSize.HighPart);
                DWORD dwClusters = (DWORD)(liFileSize.QuadPart / dwClusterSize);
                DWORD dwPointsSize = sizeof(RETRIEVAL_POINTERS_BUFFER) +
                    (dwClusters * (sizeof(LARGE_INTEGER) * 2));
                PRETRIEVAL_POINTERS_BUFFER pPoints =
                    (PRETRIEVAL_POINTERS_BUFFER) new BYTE[dwPointsSize];
                STARTING_VCN_INPUT_BUFFER vcnStart = { 0 };
                if (DeviceIoControl(hFile,
                    FSCTL_GET_RETRIEVAL_POINTERS,
                    &vcnStart,
                    sizeof(vcnStart),
                    pPoints,
                    dwPointsSize,
                    &dwWritten,
                    NULL)) {
                    szDrive = xorstr_("\\\\.\\") + szDrive;
                    HANDLE hDrive = CreateFileA(szDrive.c_str(),
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL,
                        OPEN_EXISTING,
                        0,
                        NULL);
                    if (hDrive != INVALID_HANDLE_VALUE) {
                        HANDLE hDst = CreateFileA(dst.c_str(),
                            GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_NEW,
                            0,
                            NULL);
                        if (hDst != INVALID_HANDLE_VALUE) {
                            if (SetFilePointer(hDst,
                                liFileSize.LowPart,
                                &liFileSize.HighPart,
                                FILE_BEGIN) != INVALID_SET_FILE_POINTER) {
                                if (SetEndOfFile(hDst)) {
                                    const DWORD CHUNK_CLUSTERS = 1024;
                                    const DWORD MAX_CHUNK_SIZE = CHUNK_CLUSTERS * dwClusterSize;
                                    LPBYTE lpChunkBuffer = new BYTE[MAX_CHUNK_SIZE];
                                    LARGE_INTEGER vcnPrev = pPoints->StartingVcn;
                                    for (DWORD dwExtent = 0; dwExtent < pPoints->ExtentCount; dwExtent++) {
                                        LARGE_INTEGER liSrcPos;
                                        LARGE_INTEGER liDstPos;
                                        DWORD dwLength = (DWORD)(pPoints->Extents[dwExtent].NextVcn.QuadPart -
                                            vcnPrev.QuadPart);
                                        liSrcPos.QuadPart = pPoints->Extents[dwExtent].Lcn.QuadPart *
                                            dwClusterSize;
                                        liDstPos.QuadPart = vcnPrev.QuadPart * dwClusterSize;
                                        DWORD clustersRemaining = dwLength;
                                        while (clustersRemaining > 0) {
                                            DWORD currentChunkClusters = (clustersRemaining > CHUNK_CLUSTERS)
                                                ? CHUNK_CLUSTERS
                                                : clustersRemaining;
                                            DWORD bytesToRead = currentChunkClusters * dwClusterSize;
                                            if (SetFilePointer(hDrive,
                                                liSrcPos.LowPart,
                                                &liSrcPos.HighPart,
                                                FILE_BEGIN) == INVALID_SET_FILE_POINTER
                                                && GetLastError() != NO_ERROR) {
                                                result = GetLastError();
                                                break;
                                            }
                                            if (!ReadFile(hDrive,
                                                lpChunkBuffer,
                                                bytesToRead,
                                                &dwRead,
                                                NULL)) {
                                                result = GetLastError();
                                                break;
                                            }
                                            if (SetFilePointer(hDst,
                                                liDstPos.LowPart,
                                                &liDstPos.HighPart,
                                                FILE_BEGIN) == INVALID_SET_FILE_POINTER
                                                && GetLastError() != NO_ERROR) {
                                                result = GetLastError();
                                                break;
                                            }
                                            if (!WriteFile(hDst,
                                                lpChunkBuffer,
                                                dwRead,
                                                &dwWritten,
                                                NULL)) {
                                                result = GetLastError();
                                                break;
                                            }
                                            liSrcPos.QuadPart += dwRead;
                                            liDstPos.QuadPart += dwRead;
                                            clustersRemaining -= currentChunkClusters;
                                            if (result != ERROR_SUCCESS)
                                                break;
                                        }
                                        if (result != ERROR_SUCCESS)
                                            break;
                                        vcnPrev = pPoints->Extents[dwExtent].NextVcn;
                                    }
                                    delete[] lpChunkBuffer;
                                }
                                else {
                                    result = GetLastError();
                                }
                            }
                            else {
                                result = GetLastError();
                            }
                            CloseHandle(hDst);
                        }
                        else {
                            result = GetLastError();
                        }
                        CloseHandle(hDrive);
                    }
                    else {
                        result = GetLastError();
                    }
                }
                else {
                    result = GetLastError();
                }
                delete[] pPoints;
            }
            else {
                result = GetLastError();
            }
            CloseHandle(hFile);
        }
        else {
            result = GetLastError();
        }
        return result;
        }
        catch (...) { return ERROR_UNHANDLED_EXCEPTION; }
    }    
};

inline auto c_delbam = std::make_unique<file_utils>();