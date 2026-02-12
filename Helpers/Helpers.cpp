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
#include <array>
#include <regex>
#include <unordered_set>
#include <algorithm> // Добавлено для transform

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

namespace fs = std::filesystem;

// Глобальные переменные управления
std::atomic<bool> g_cancel(false);
HWND g_hProgressWnd = NULL;
HWND g_hProgressBar = NULL;

// Синхронизация статуса для GUI
std::mutex g_statusMutex;
std::wstring g_currentStatus = L"Инициализация...";

// --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
bool FileExists(const std::wstring& path) {
    DWORD dwAttrib = GetFileAttributesW(path.c_str());
    return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

// Оптимизированная проверка расширения
bool IsExcludedExtension(const std::wstring& filename) {
    // static делает список постоянным в памяти (инициализация 1 раз)
    static const std::unordered_set<std::wstring> excluded = {
        L".sln", L".vcxproj", L".filters", L".user",
        L".lib", L".obj", L".dll", L".exe", L".pdb", L".suo",
        L".ncb", L".bin", L".iso", L".png", L".jpg", L".jpeg", L".bmp", L".gif",
        L".tlog", L".ipch", L".sdf", L".opensdf", L".db", L".sqlite"
    };

    size_t dotPos = filename.rfind(L'.');
    if (dotPos == std::wstring::npos) return false;

    std::wstring ext = filename.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), towlower);

    return excluded.find(ext) != excluded.end();
}

// Проверка на бинарный файл (читаем первые 512 байт)
bool IsBinaryFile(const std::wstring& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) return true;

    char buffer[512];
    file.read(buffer, sizeof(buffer));
    size_t bytesRead = file.gcount();

    for (size_t i = 0; i < bytesRead; ++i) {
        // Если встретили 0-байта и это не UTF-16 BOM (грубая проверка), считаем бинарным
        if (buffer[i] == 0) return true;
    }
    return false;
}

// Очистка HEX массивов
std::string CleanHexArrays(const std::string& content) {
    if (content.size() > 500000) return content; // Пропускаем regex для огромных файлов во избежание зависания

    try {
        static const std::regex pattern(R"((=\s*\{[\s\da-fA-FxX,]{50,}?\};))", std::regex::optimize);
        return std::regex_replace(content, pattern, "= { /* HEX DATA HIDDEN */ };");
    }
    catch (...) {
        return content;
    }
}

// --- ЯДРО СКАНИРОВАНИЯ (ФАЙЛОВЫЙ ЛИСТИНГ) ---
void GenerateFileList(const std::wstring& folderPath) {
    fs::path baseDir(folderPath);
    fs::path outputFile = baseDir / L"file_list.txt";

    const size_t WRITE_BUFFER_SIZE = 1024 * 1024;
    std::vector<char> internalBuffer(WRITE_BUFFER_SIZE);

    std::ofstream f(outputFile, std::ios::binary);
    if (!f.is_open()) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }
    f.rdbuf()->pubsetbuf(internalBuffer.data(), internalBuffer.size());

    char utf8Buf[4096]; // Увеличим буфер для длинных путей
    int counter = 0;

    try {
        for (auto& p : fs::recursive_directory_iterator(baseDir, fs::directory_options::skip_permission_denied)) {
            if (g_cancel.load(std::memory_order_relaxed)) break;

            if (p.is_directory()) continue;

            // ПОЛУЧАЕМ ОТНОСИТЕЛЬНЫЙ ПУТЬ
            fs::path relativePath = fs::relative(p.path(), baseDir);
            std::wstring relPathStr = relativePath.wstring();

            // Пропускаем служебные файлы
            if (relPathStr == L"file_list.txt" || relPathStr == L"all.txt") continue;

            if (++counter % 100 == 0) {
                std::lock_guard<std::mutex> lock(g_statusMutex);
                g_currentStatus = relativePath.filename().wstring();
            }

            // Конвертируем относительный путь в UTF-8
            int bytes = WideCharToMultiByte(CP_UTF8, 0, relPathStr.c_str(), -1, utf8Buf, sizeof(utf8Buf), NULL, NULL);
            if (bytes > 1) {
                f.write(utf8Buf, bytes - 1);
                f.put('\n');
            }
        }
    }
    catch (...) {}

    f.close();
    if (g_cancel.load()) { std::error_code ec; fs::remove(outputFile, ec); }
    PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
}

// --- ЯДРО ГЕНЕРАЦИИ ДАМПА (all.txt) ---
void GenerateAllTxt(const std::wstring& folderPath) {
    fs::path baseDir(folderPath);
    fs::path outputFile = baseDir / L"all.txt";

    const size_t OUT_BUF_SIZE = 4 * 1024 * 1024;
    std::vector<char> outBuffer(OUT_BUF_SIZE);

    std::ofstream outfile(outputFile, std::ios::binary);
    if (!outfile.is_open()) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }
    outfile.rdbuf()->pubsetbuf(outBuffer.data(), OUT_BUF_SIZE);

    int counter = 0;
    std::string content;
    std::string pathUtf8;
    content.reserve(1024 * 1024);

    try {
        for (auto& p : fs::recursive_directory_iterator(baseDir, fs::directory_options::skip_permission_denied)) {
            if (g_cancel.load(std::memory_order_relaxed)) break;
            if (!p.is_regular_file()) continue;

            fs::path currentPath = p.path();
            // ПОЛУЧАЕМ ОТНОСИТЕЛЬНЫЙ ПУТЬ
            fs::path relativePath = fs::relative(currentPath, baseDir);
            std::wstring relPathStr = relativePath.wstring();

            if (relPathStr == L"all.txt" || relPathStr == L"file_list.txt") continue;
            if (relPathStr.size() > 4 && relPathStr.substr(relPathStr.size() - 4) == L".exe") continue;

            if (++counter % 20 == 0) {
                std::lock_guard<std::mutex> lock(g_statusMutex);
                g_currentStatus = L"Обработка: " + relativePath.filename().wstring();
            }

            if (IsExcludedExtension(currentPath.filename().wstring())) continue;
            if (IsBinaryFile(currentPath.wstring())) continue;

            std::ifstream infile(currentPath, std::ios::in | std::ios::binary);
            if (!infile) continue;

            infile.seekg(0, std::ios::end);
            size_t fileSize = (size_t)infile.tellg();
            infile.seekg(0, std::ios::beg);

            content.resize(fileSize);
            infile.read(content.data(), fileSize);
            infile.close();

            std::string finalContent = CleanHexArrays(content);

            // Конвертация относительного пути в UTF-8 для заголовка
            int reqLen = WideCharToMultiByte(CP_UTF8, 0, relPathStr.c_str(), -1, NULL, 0, NULL, NULL);
            if (reqLen > 0) {
                pathUtf8.resize(reqLen - 1);
                WideCharToMultiByte(CP_UTF8, 0, relPathStr.c_str(), -1, pathUtf8.data(), reqLen, NULL, NULL);
            }

            outfile << pathUtf8 << ":\n";
            outfile << finalContent << "\n\n";

            content.clear();
        }
    }
    catch (...) {}

    outfile.close();
    if (g_cancel.load()) { std::error_code ec; fs::remove(outputFile, ec); }
    PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
}

// --- GUI: ОКНО ПРОГРЕССА (Без изменений логики) ---
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

        SetTimer(hWnd, 1, 100, NULL); // Таймер обновления GUI
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
    // Регистрация класса окна только один раз
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

    g_cancel = false; // Сброс флага отмены перед запуском
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

    // Меню для вставки PNG
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\PastePNG",
        L"Вставить как PNG", L"imageres.dll,-72", p + L" -paste \"%V\"");

    // Меню для создания списка файлов
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\GenList",
        L"Создать список файлов", L"shell32.dll,-152", p + L" -list \"%V\"");

    // Меню для создания полного дампа (all.txt)
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\GenDump",
        L"Создать полный дамп (all.txt)", L"shell32.dll,-264", p + L" -dump \"%V\"");

    MessageBoxW(NULL, L"Контекстное меню успешно обновлено!\nДобавлен пункт 'Создать полный дамп'", L"Успех", MB_OK | MB_ICONINFORMATION);
}

// --- ТОЧКА ВХОДА ---
int main() {
    // Скрываем консоль, если запущено не из IDE (хотя SUBSYSTEM:windows это и так делает, но на всякий случай)

    int args;
    LPWSTR* argList = CommandLineToArgvW(GetCommandLineW(), &args);

    if (args >= 3) {
        std::wstring flag = argList[1];
        std::wstring path = argList[2];

        // Инициализация COM нужна для CImage и Shell
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
        // Запуск без аргументов -> Регистрация
        RegisterMenu();
    }

    if (argList) LocalFree(argList);
    return 0;
}