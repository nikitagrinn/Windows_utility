#include "ProgressWindow.h"
#include <commctrl.h>
#include <thread>
#include "Core/Globals/Globals.h"
#include "Features/GenerateFileList/GenerateFileList.h"
#include "Features/GenerateAllTxt/GenerateAllTxt.h"

#pragma comment(lib, "comctl32.lib")

LRESULT CALLBACK ProgressWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    static HWND hBtnCancel, hStaticText;
    static HFONT hFont;
    switch (message) {
    case WM_CREATE: {
        INITCOMMONCONTROLSEX icex = { sizeof(icex), ICC_PROGRESS_CLASS };
        InitCommonControlsEx(&icex);
        NONCLIENTMETRICSW ncm = { sizeof(ncm) };
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        hFont = CreateFontIndirectW(&ncm.lfMessageFont);
        hStaticText = CreateWindowW(L"STATIC", L"Подготовка...",
            WS_VISIBLE | WS_CHILD | SS_LEFT | SS_PATHELLIPSIS,
            15, 15, 360, 20, hWnd, NULL, NULL, NULL);
        SendMessage(hStaticText, WM_SETFONT, (WPARAM)hFont, TRUE);
        g_hProgressBar = CreateWindowW(PROGRESS_CLASSW, NULL,
            WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
            15, 40, 360, 15, hWnd, NULL, NULL, NULL);
        SendMessage(g_hProgressBar, PBM_SETMARQUEE, TRUE, 30);
        hBtnCancel = CreateWindowW(L"BUTTON", L"Отмена",
            WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
            295, 65, 80, 25, hWnd, (HMENU)1, NULL, NULL);
        SendMessage(hBtnCancel, WM_SETFONT, (WPARAM)hFont, TRUE);
        SetTimer(hWnd, 1, 100, NULL);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wParam) == 1) {
            g_cancel = true;
            SetWindowTextW(hStaticText, L"Отмена...");
            EnableWindow(hBtnCancel, FALSE);
        }
        return 0;
    case WM_TIMER: {
        std::wstring status;
        { std::lock_guard<std::mutex> lock(g_statusMutex); status = g_currentStatus; }
        SetWindowTextW(hStaticText, status.c_str());
        return 0;
    }
    case WM_DESTROY:
        if (hFont) DeleteObject(hFont);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hWnd, message, wParam, lParam);
}

void ShowProgressAndRun(const std::wstring& folderPath, bool dumpMode) {
    static bool registered = false;
    if (!registered) {
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc   = ProgressWndProc;
        wc.hInstance     = GetModuleHandle(NULL);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"ModernProgressClass";
        wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
        RegisterClassW(&wc);
        registered = true;
    }
    int w = 410, h = 135;
    int x = (GetSystemMetrics(SM_CXSCREEN) - w) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - h) / 2;
    g_hProgressWnd = CreateWindowExW(WS_EX_TOPMOST, L"ModernProgressClass",
        dumpMode ? L"Генерация дампа (all.txt)" : L"Сканирование списка",
        WS_POPUP | WS_CAPTION | WS_SYSMENU, x, y, w, h, NULL, NULL, GetModuleHandle(NULL), NULL);
    ShowWindow(g_hProgressWnd, SW_SHOW);
    g_cancel = false;
    std::thread worker(dumpMode ? GenerateAllTxt : GenerateFileList, folderPath);
    worker.detach();
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
