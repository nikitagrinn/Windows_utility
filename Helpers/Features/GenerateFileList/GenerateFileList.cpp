#include "GenerateFileList.h"
#include <windows.h>
#include <vector>
#include "Core/Globals/Globals.h"
#include "Core/Types/CoreTypes.h"

void GenerateFileList(const std::wstring& folderPath) {
    std::wstring baseStr = folderPath;
    if (!baseStr.empty() && baseStr.back() != L'\\') baseStr += L'\\';
    const DWORD baseLen = (DWORD)baseStr.length();

    OutBuf out;
    if (!out.open((baseStr + L"file_list.txt").c_str(), 1 * 1024 * 1024)) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }

    wchar_t pathBuf[32768];
    wmemcpy(pathBuf, baseStr.c_str(), baseLen + 1);
    DWORD pathLen = baseLen;

    char utf8Buf[MAX_PATH * 4 + 2];
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
            if (_wcsicmp(name, L"file_list.txt") == 0 || _wcsicmp(name, L"all.txt") == 0) continue;
            DWORD nl = (DWORD)wcslen(name);
            wmemcpy(pathBuf + pathLen, name, nl + 1);
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0,
                pathBuf + baseLen, (int)(pathLen + nl - baseLen),
                utf8Buf, (int)sizeof(utf8Buf) - 2, NULL, NULL);
            if (utf8Len > 0) { utf8Buf[utf8Len] = '\n'; out.write(utf8Buf, (DWORD)utf8Len + 1); }
            pathBuf[pathLen] = L'\0';
        }
    }

    for (auto& lv : stk) if (lv.hFind != INVALID_HANDLE_VALUE) FindClose(lv.hFind);
    out.close();
    if (g_cancel.load()) DeleteFileW((baseStr + L"file_list.txt").c_str());
    PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
}
