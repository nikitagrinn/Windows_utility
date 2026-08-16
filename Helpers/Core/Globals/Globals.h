#pragma once
#include <windows.h>
#include <atomic>
#include <mutex>
#include <string>

extern std::atomic<bool> g_cancel;
extern HWND g_hProgressWnd;
extern HWND g_hProgressBar;
extern std::mutex g_statusMutex;
extern std::wstring g_currentStatus;
