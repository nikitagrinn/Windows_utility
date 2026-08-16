#include "Globals.h"

std::atomic<bool> g_cancel(false);
HWND g_hProgressWnd = NULL;
HWND g_hProgressBar = NULL;
std::mutex g_statusMutex;
std::wstring g_currentStatus = L"Инициализация...";
