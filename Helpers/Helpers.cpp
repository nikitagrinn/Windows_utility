#include <windows.h>
#include <commctrl.h>
#include <atlimage.h>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <stack>
#include <chrono>
#include <regex>
#include <unordered_set>
#include <algorithm>
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

namespace fs = std::filesystem;

// Глобальные переменные
std::atomic<bool> g_cancel(false);
HWND g_hProgressWnd = NULL;
HWND g_hProgressBar = NULL;

std::mutex g_statusMutex;
std::wstring g_currentStatus = L"Инициализация...";

// Исключаемые расширения для дампа
static const std::unordered_set<std::wstring> excludedExtensions = {
    L".sln", L".vcxproj", L".filters", L".user",
    L".lib", L".obj", L".dll", L".exe", L".pdb", L".suo",
    L".ncb", L".bin", L".iso", L".png", L".jpg", L".jpeg", L".bmp", L".gif",
    L".tlog", L".ipch", L".sdf", L".opensdf", L".db", L".sqlite"
};

// --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
bool FileExists(const std::wstring& path) {
    DWORD dwAttrib = GetFileAttributesW(path.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool IsExcludedExtension(const std::wstring& filename) {
    size_t dotPos = filename.rfind(L'.');
    if (dotPos == std::wstring::npos) return false;
    std::wstring ext = filename.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
    return excludedExtensions.find(ext) != excludedExtensions.end();
}

bool IsBinaryFile(const std::wstring& path) {
    HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return true;

    char buffer[1024];
    DWORD bytesRead;
    bool binary = false;
    if (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
        if (memchr(buffer, 0, bytesRead)) binary = true;
    }
    CloseHandle(hFile);
    return binary;
}

std::string CleanHexArrays(const std::string& content) {
    if (content.size() > 500000) return content;
    try {
        static const std::regex pattern(R"((=\s*\{[\s\da-fA-FxX,]{50,}?\};))", std::regex::optimize);
        return std::regex_replace(content, pattern, "= { /* HEX DATA HIDDEN */ };");
    }
    catch (...) { return content; }
}

// --- СТРУКТУРА ДЛЯ ИТЕРАТИВНОГО ОБХОДА (WinAPI) ---
struct DirectoryState {
    std::wstring path;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW fd = { 0 };
    bool first = true;
};

// --- ЯДРО СКАНИРОВАНИЯ file_list.txt (полный, следует по symlink/junction) ---
void GenerateFileList(const std::wstring& folderPath) {
    fs::path baseDir(folderPath);
    fs::path outputFile = baseDir / L"file_list.txt";

    std::vector<char> writeBuffer(1024 * 1024);
    std::ofstream f(outputFile, std::ios::binary);
    if (!f.is_open()) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }
    f.rdbuf()->pubsetbuf(writeBuffer.data(), writeBuffer.size());

    std::wstring baseStr = baseDir.wstring();
    if (!baseStr.empty() && baseStr.back() != L'\\') baseStr += L'\\';
    size_t baseLen = baseStr.length();

    int counter = 0;
    std::stack<DirectoryState> dirStack;
    DirectoryState root{ baseStr, INVALID_HANDLE_VALUE, {}, true };
    dirStack.push(root);

    while (!dirStack.empty() && !g_cancel.load()) {
        DirectoryState& current = dirStack.top();

        if (current.first) {
            current.first = false;
            std::wstring searchPath = current.path + L"*";
            current.hFind = FindFirstFileExW(searchPath.c_str(), FindExInfoBasic, &current.fd,
                FindExSearchNameMatch, NULL,
                FIND_FIRST_EX_LARGE_FETCH | FIND_FIRST_EX_CASE_SENSITIVE);
            if (current.hFind == INVALID_HANDLE_VALUE) {
                dirStack.pop();
                continue;
            }
        }
        else {
            if (!FindNextFileW(current.hFind, &current.fd)) {
                FindClose(current.hFind);
                dirStack.pop();
                continue;
            }
        }

        if (++counter % 100 == 0) {
            std::lock_guard<std::mutex> lock(g_statusMutex);
            g_currentStatus = current.fd.cFileName;
        }

        if (current.fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (current.fd.cFileName[0] == L'.' && (current.fd.cFileName[1] == L'\0' ||
                (current.fd.cFileName[1] == L'.' && current.fd.cFileName[2] == L'\0'))) continue;

            DirectoryState sub;
            sub.path = current.path + current.fd.cFileName + L'\\';
            sub.first = true;
            dirStack.push(sub);
        }
        else {
            if (_wcsicmp(current.fd.cFileName, L"file_list.txt") == 0 || _wcsicmp(current.fd.cFileName, L"all.txt") == 0) continue;

            std::wstring fullPath = current.path + current.fd.cFileName;
            std::wstring relPart = fullPath.substr(baseLen);

            int size_needed = WideCharToMultiByte(CP_UTF8, 0, relPart.c_str(), (int)relPart.length(), NULL, 0, NULL, NULL);
            std::string utf8rel(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, relPart.c_str(), (int)relPart.length(), &utf8rel[0], size_needed, NULL, NULL);

            f << utf8rel << "\n";
        }
    }

    while (!dirStack.empty()) {
        DirectoryState& cur = dirStack.top();
        if (cur.hFind != INVALID_HANDLE_VALUE) FindClose(cur.hFind);
        dirStack.pop();
    }

    f.close();
    if (g_cancel) { std::error_code ec; fs::remove(outputFile, ec); }
    PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
}

// --- ЯДРО ДАМПА all.txt (на WinAPI для полноты и скорости) ---
void GenerateAllTxt(const std::wstring& folderPath) {
    fs::path baseDir(folderPath);
    fs::path outputFile = baseDir / L"all.txt";

    std::vector<char> writeBuffer(4 * 1024 * 1024);
    std::ofstream f(outputFile, std::ios::binary);
    if (!f.is_open()) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }
    f.rdbuf()->pubsetbuf(writeBuffer.data(), writeBuffer.size());

    std::wstring baseStr = baseDir.wstring();
    if (!baseStr.empty() && baseStr.back() != L'\\') baseStr += L'\\';
    size_t baseLen = baseStr.length();

    int counter = 0;
    std::stack<DirectoryState> dirStack;
    DirectoryState root{ baseStr, INVALID_HANDLE_VALUE, {}, true };
    dirStack.push(root);

    while (!dirStack.empty() && !g_cancel.load()) {
        DirectoryState& current = dirStack.top();

        if (current.first) {
            current.first = false;
            std::wstring searchPath = current.path + L"*";
            current.hFind = FindFirstFileExW(searchPath.c_str(), FindExInfoBasic, &current.fd,
                FindExSearchNameMatch, NULL,
                FIND_FIRST_EX_LARGE_FETCH | FIND_FIRST_EX_CASE_SENSITIVE);
            if (current.hFind == INVALID_HANDLE_VALUE) {
                dirStack.pop();
                continue;
            }
        }
        else {
            if (!FindNextFileW(current.hFind, &current.fd)) {
                FindClose(current.hFind);
                dirStack.pop();
                continue;
            }
        }

        if (++counter % 20 == 0) {
            std::lock_guard<std::mutex> lock(g_statusMutex);
            g_currentStatus = current.fd.cFileName;
        }

        if (current.fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (current.fd.cFileName[0] == L'.' && (current.fd.cFileName[1] == L'\0' ||
                (current.fd.cFileName[1] == L'.' && current.fd.cFileName[2] == L'\0'))) continue;

            DirectoryState sub;
            sub.path = current.path + current.fd.cFileName + L'\\';
            sub.first = true;
            dirStack.push(sub);
        }
        else {
            if (_wcsicmp(current.fd.cFileName, L"all.txt") == 0 || _wcsicmp(current.fd.cFileName, L"file_list.txt") == 0) continue;
            if (IsExcludedExtension(current.fd.cFileName)) continue;

            std::wstring fullPath = current.path + current.fd.cFileName;
            if (IsBinaryFile(fullPath)) continue;

            std::string content;
            {
                std::ifstream in(fullPath, std::ios::binary);
                if (in) {
                    content.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                }
            }

            content = CleanHexArrays(content);

            std::wstring relPart = fullPath.substr(baseLen);
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, relPart.c_str(), (int)relPart.length(), NULL, 0, NULL, NULL);
            std::string utf8rel(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, relPart.c_str(), (int)relPart.length(), &utf8rel[0], size_needed, NULL, NULL);

            f << utf8rel << ":\n";
            f << std::string(utf8rel.size(), '-') << "\n";
            f << content << "\n\n";
        }
    }

    while (!dirStack.empty()) {
        DirectoryState& cur = dirStack.top();
        if (cur.hFind != INVALID_HANDLE_VALUE) FindClose(cur.hFind);
        dirStack.pop();
    }

    f.close();
    if (g_cancel) { std::error_code ec; fs::remove(outputFile, ec); }
    PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
}

// --- GUI: ОКНО ПРОГРЕССА ---
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
        {
            std::lock_guard<std::mutex> lock(g_statusMutex);
            status = g_currentStatus;
        }
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
        wc.lpfnWndProc = ProgressWndProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.lpszClassName = L"ModernProgressClass";
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
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

// --- ЛОГИКА ВСТАВКИ ИЗОБРАЖЕНИЯ ---
void PasteImage(const std::wstring& folderPath) {
    if (!OpenClipboard(NULL)) return;
    HBITMAP hBitmap = (HBITMAP)GetClipboardData(CF_BITMAP);
    if (hBitmap) {
        CImage image;
        image.Attach(hBitmap);
        std::wstring targetDir = folderPath;
        if (!targetDir.empty() && targetDir.back() != L'\\') targetDir += L'\\';
        std::wstring finalPath = targetDir + L"screenshot.png";
        for (int i = 2; FileExists(finalPath); ++i) {
            finalPath = targetDir + L"screenshot (" + std::to_wstring(i) + L").png";
        }
        image.Save(finalPath.c_str(), Gdiplus::ImageFormatPNG);
        image.Detach();
    }
    CloseClipboard();
}

// --- РЕГИСТРАЦИЯ В РЕЕСТРЕ ---
void CreateRegKey(const std::wstring& keyPath, const std::wstring& name, const std::wstring& icon, const std::wstring& cmd) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)name.c_str(), (DWORD)(name.length() + 1) * 2);
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)icon.c_str(), (DWORD)(icon.length() + 1) * 2);
        HKEY hCmd;
        if (RegCreateKeyExW(hKey, L"command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hCmd, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hCmd, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)(cmd.length() + 1) * 2);
            RegCloseKey(hCmd);
        }
        RegCloseKey(hKey);
    }
}

void RegisterMenu() {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    std::wstring p = L"\""; p += exe; p += L"\"";
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\PastePNG",
        L"Вставить как PNG", L"imageres.dll,-72", p + L" -paste \"%V\"");
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\GenList",
        L"Создать список файлов", L"shell32.dll,-152", p + L" -list \"%V\"");
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\GenDump",
        L"Создать полный дамп (all.txt)", L"shell32.dll,-264", p + L" -dump \"%V\"");
    MessageBoxW(NULL, L"Контекстное меню успешно обновлено!\nДобавлен пункт 'Создать полный дамп'", L"Успех", MB_OK | MB_ICONINFORMATION);
}

// --- ТОЧКА ВХОДА ---
int main() {
    int args;
    LPWSTR* argList = CommandLineToArgvW(GetCommandLineW(), &args);
    if (args >= 3) {
        std::wstring flag = argList[1];
        std::wstring path = argList[2];
        CoInitialize(NULL);
        if (flag == L"-paste") {
            PasteImage(path);
        }
        else if (flag == L"-list") {
            ShowProgressAndRun(path, false);
        }
        else if (flag == L"-dump") {
            ShowProgressAndRun(path, true);
        }
        CoUninitialize();
    }
    else {
        RegisterMenu();
    }
    if (argList) LocalFree(argList);
    return 0;
}