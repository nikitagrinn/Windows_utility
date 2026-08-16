#include "GenerateAllTxt.h"
#include <windows.h>
#include <vector>
#include <thread>
#include "Core/Globals/Globals.h"
#include "Core/Types/CoreTypes.h"
#include "Utils/FileSystem/FileSystemUtils.h"
#include "Utils/Strings/StringUtils.h"
#include "Utils/SIMD/SIMDUtils.h"

void GenerateAllTxt(const std::wstring& folderPath) {
    std::wstring baseStr = folderPath;
    if (!baseStr.empty() && baseStr.back() != L'\\') baseStr += L'\\';
    const DWORD baseLen = (DWORD)baseStr.length();

    OutBuf out;
    if (!out.open((baseStr + L"all.txt").c_str(), 8 * 1024 * 1024)) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }

    const bool ssd = IsPathOnSSD(baseStr.c_str());
    const int  numWorkers    = ssd ? max(4, (int)std::thread::hardware_concurrency()) : 1;
    const int  pathChanCap   = ssd ? 1024 : 16;
    const int  outChanCap    = ssd ? 128  : 16;

    Chan<std::wstring> pathChan(pathChanCap);
    Chan<std::string>  outChan(outChanCap);

    std::atomic<int> activeWorkers(numWorkers);

    auto workerFn = [&]() {
        std::wstring fullPath;
        char utf8Buf[MAX_PATH * 4 + 4];
        std::string  cleaned;

        while (pathChan.recv(fullPath)) {
            if (g_cancel.load(std::memory_order_relaxed)) continue;

            HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            LARGE_INTEGER fsz;
            if (!GetFileSizeEx(hFile, &fsz) || fsz.QuadPart == 0) { CloseHandle(hFile); continue; }

            DWORD sz = (DWORD)min(fsz.QuadPart, (LONGLONG)50 * 1024 * 1024);

            HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, sz, NULL);
            CloseHandle(hFile);
            if (!hMap) continue;

            const char* view = (const char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, sz);
            if (!view) { CloseHandle(hMap); continue; }

            if (HasNullByte(view, min((size_t)sz, (size_t)1024))) { UnmapViewOfFile(view); CloseHandle(hMap); continue; }

            int relWLen = (int)(fullPath.size() - (size_t)baseLen);
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0,
                fullPath.c_str() + baseLen, relWLen,
                utf8Buf, (int)sizeof(utf8Buf) - 4, NULL, NULL);
            if (utf8Len <= 0) { UnmapViewOfFile(view); CloseHandle(hMap); continue; }

            std::string chunk;
            chunk.reserve((size_t)utf8Len * 2 + 4 + sz);

            chunk.append(utf8Buf, (size_t)utf8Len);
            chunk += ":\n";
            chunk.append((size_t)utf8Len, '-');
            chunk += '\n';

            if (sz < 500000 && CleanHexArrays(view, sz, cleaned))
                chunk += cleaned;
            else
                chunk.append(view, sz);

            chunk += "\n\n";

            UnmapViewOfFile(view);
            CloseHandle(hMap);

            outChan.send(std::move(chunk));
        }

        if (--activeWorkers == 0)
            outChan.close();
    };

    std::thread outputThread([&]() {
        std::string chunk;
        while (outChan.recv(chunk))
            out.write(chunk.data(), (DWORD)chunk.size());
    });

    std::vector<std::thread> workers;
    workers.reserve(numWorkers);
    for (int i = 0; i < numWorkers; ++i)
        workers.emplace_back(workerFn);

    wchar_t pathBuf[32768];
    wmemcpy(pathBuf, baseStr.c_str(), baseLen + 1);
    DWORD pathLen = baseLen;

    WIN32_FIND_DATAW fd = {};
    std::vector<DirLevel> stk;
    stk.reserve(64);
    stk.push_back({ INVALID_HANDLE_VALUE, baseLen, true });

    int counter = 0;

    while (!stk.empty() && !g_cancel.load(std::memory_order_relaxed)) {
        DirLevel& cur = stk.back();

        if (cur.first) {
            cur.first = false;
            pathBuf[pathLen] = L'*'; pathBuf[pathLen + 1] = L'\0';
            cur.hFind = FindFirstFileExW(pathBuf, FindExInfoBasic, &fd,
                FindExSearchNameMatch, NULL,
                FIND_FIRST_EX_LARGE_FETCH | FIND_FIRST_EX_CASE_SENSITIVE);
            pathBuf[pathLen] = L'\0';
            if (cur.hFind == INVALID_HANDLE_VALUE) { pathLen = cur.pathEnd; stk.pop_back(); continue; }
        } else {
            if (!FindNextFileW(cur.hFind, &fd)) {
                FindClose(cur.hFind);
                pathLen = cur.pathEnd;
                stk.pop_back();
                continue;
            }
        }

        if (++counter >= 500) {
            counter = 0;
            std::lock_guard<std::mutex> lk(g_statusMutex);
            g_currentStatus = fd.cFileName;
        }

        const wchar_t* name = fd.cFileName;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (name[0] == L'.' && (name[1] == L'\0' || (name[1] == L'.' && name[2] == L'\0'))) continue;
            DWORD nl = (DWORD)wcslen(name);
            wmemcpy(pathBuf + pathLen, name, nl);
            pathBuf[pathLen + nl] = L'\\';
            DirLevel sub{ INVALID_HANDLE_VALUE, pathLen, true };
            pathLen += nl + 1;
            pathBuf[pathLen] = L'\0';
            stk.push_back(sub);
        } else {
            if (_wcsicmp(name, L"all.txt") == 0 || _wcsicmp(name, L"file_list.txt") == 0) continue;
            if (IsExcludedExtension(name)) continue;

            DWORD nl = (DWORD)wcslen(name);
            wmemcpy(pathBuf + pathLen, name, nl + 1);
            pathChan.send(std::wstring(pathBuf, pathLen + nl));
            pathBuf[pathLen] = L'\0';
        }
    }

    for (auto& lv : stk) if (lv.hFind != INVALID_HANDLE_VALUE) FindClose(lv.hFind);

    pathChan.close();

    for (auto& w : workers) w.join();
    outputThread.join();

    out.close();
    if (g_cancel.load()) DeleteFileW((baseStr + L"all.txt").c_str());
    PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
}
