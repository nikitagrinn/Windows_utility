#include "FileSystemUtils.h"
#include <windows.h>
#include <winioctl.h>

bool FileExists(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

bool IsPathOnSSD(const wchar_t* path) {
    wchar_t volumePath[MAX_PATH] = {};
    if (!GetVolumePathNameW(path, volumePath, MAX_PATH)) return true;

    if (wcslen(volumePath) < 2 || volumePath[1] != L':') return true;
    wchar_t devPath[] = { L'\\',L'\\',L'.',L'\\', volumePath[0], L':', L'\0' };

    HANDLE hDev = CreateFileW(devPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) return true;

    STORAGE_PROPERTY_QUERY query = {};
    query.PropertyId = StorageDeviceSeekPenaltyProperty;
    query.QueryType  = PropertyStandardQuery;

    DEVICE_SEEK_PENALTY_DESCRIPTOR desc = {};
    DWORD bytesReturned = 0;
    bool isSSD = true;

    if (DeviceIoControl(hDev, IOCTL_STORAGE_QUERY_PROPERTY,
            &query, sizeof(query), &desc, sizeof(desc), &bytesReturned, NULL))
        isSSD = !desc.IncursSeekPenalty;

    CloseHandle(hDev);
    return isSSD;
}
