#include "c_letterless_volumes.h"

static bool is_system_partition(const std::wstring& vol)
{
    static const GUID efi_guid =
        { 0xc12a7328, 0xf81f, 0x11d2, { 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b } };
    static const GUID recovery_guid =
        { 0xde94bba4, 0x06d1, 0x4d40, { 0xa1, 0x6a, 0xbf, 0xd5, 0x01, 0x79, 0xd6, 0xac } };
    static const GUID msr_guid =
        { 0xe3c9e316, 0x0b5c, 0x4db8, { 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae } };

    std::wstring device_path = vol;
    if (!device_path.empty() && device_path.back() == L'\\')
        device_path.pop_back();

    HANDLE hVol = CreateFileW(device_path.c_str(), 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol == INVALID_HANDLE_VALUE)
        return true;

    PARTITION_INFORMATION_EX part_info = {};
    DWORD bytes_returned = 0;
    BOOL ok = DeviceIoControl(hVol, IOCTL_DISK_GET_PARTITION_INFO_EX,
        nullptr, 0, &part_info, sizeof(part_info), &bytes_returned, nullptr);
    CloseHandle(hVol);

    if (!ok)
        return false;

    if (part_info.PartitionStyle == PARTITION_STYLE_GPT)
    {
        const GUID& type = part_info.Gpt.PartitionType;
        if (IsEqualGUID(type, efi_guid) ||
            IsEqualGUID(type, recovery_guid) ||
            IsEqualGUID(type, msr_guid))
            return true;
    }
    else if (part_info.PartitionStyle == PARTITION_STYLE_MBR)
    {
        BYTE mbr_type = part_info.Mbr.PartitionType;
        if (mbr_type == 0x27 || mbr_type == 0xEF || mbr_type == 0x12)
            return true;
    }

    return false;
}

void LetterlessVolumeChecker::start_letterless_volume_check()
{
    try
    {
        std::unordered_set<std::wstring> letteredVolumes;

        DWORD mask = GetLogicalDrives();
        for (wchar_t c = L'A'; c <= L'Z'; ++c, mask >>= 1)
        {
            if (!(mask & 1)) continue;
            std::wstring d{ c, L':', L'\\' };
            wchar_t volName[MAX_PATH] = {};
            if (GetVolumeNameForVolumeMountPointW(d.c_str(), volName, MAX_PATH))
                letteredVolumes.insert(volName);
        }

        wchar_t volBuf[MAX_PATH] = {};
        HANDLE hFind = FindFirstVolumeW(volBuf, MAX_PATH);
        if (hFind == INVALID_HANDLE_VALUE)
            return;

        do
        {
            std::wstring vol(volBuf);

            if (letteredVolumes.count(vol))
                continue;

            UINT t = GetDriveTypeW(vol.c_str());
            if (t == DRIVE_NO_ROOT_DIR || t == DRIVE_CDROM || t == DRIVE_RAMDISK)
                continue;

            wchar_t pathNames[MAX_PATH] = {};
            DWORD returned = 0;
            if (GetVolumePathNamesForVolumeNameW(vol.c_str(), pathNames, MAX_PATH, &returned))
            {
                if (pathNames[0] != L'\0')
                    continue;
            }

            if (is_system_partition(vol))
                continue;

            int len = WideCharToMultiByte(CP_UTF8, 0, vol.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string narrowVol(len > 0 ? len - 1 : 0, '\0');
            WideCharToMultiByte(CP_UTF8, 0, vol.c_str(), -1, &narrowVol[0], len, nullptr, nullptr);

            LOG(WARNING, xorstr_("N/A")) << xorstr_("Possible Bypass Method:Disk Volume Without Drive Letter | GUID: ") << narrowVol;
        } while (FindNextVolumeW(hFind, volBuf, MAX_PATH));

        FindVolumeClose(hFind);
    }
    catch (...) {}
}
