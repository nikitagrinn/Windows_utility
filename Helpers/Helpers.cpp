#include <windows.h>
#include <commctrl.h>
#include <atlimage.h>
#include <wincodec.h>
#pragma comment(lib, "windowscodecs.lib")
#include <string>
#include <vector>
#include <deque>
#include <thread>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <intrin.h>      // SSE2
#include <immintrin.h>   // AVX2
#include <winioctl.h>    // IOCTL_STORAGE_QUERY_PROPERTY
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

// --- ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ---
std::atomic<bool> g_cancel(false);
HWND g_hProgressWnd = NULL;
HWND g_hProgressBar = NULL;
std::mutex g_statusMutex;
std::wstring g_currentStatus = L"Инициализация...";

// --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---
static bool FileExists(const std::wstring& path) {
    DWORD a = GetFileAttributesW(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool IsExcludedExtension(const wchar_t* filename) {
    const wchar_t* dot = wcsrchr(filename, L'.');
    if (!dot) return false;
    static const wchar_t* const kExts[] = {
        L".bin",  L".bmp",   L".db",    L".dll",  L".exe",
        L".filters", L".gif",L".ipch",  L".iso",  L".jpg",
        L".jpeg", L".lib",   L".ncb",   L".obj",  L".opensdf",
        L".pdb",  L".png",   L".sdf",   L".sqlite",L".sln",
        L".suo",  L".tlog",  L".user",  L".vcxproj"
    };
    for (auto e : kExts)
        if (_wcsicmp(dot, e) == 0) return true;
    return false;
}

// --- SIMD ПОИСК НУЛЕВОГО БАЙТА ---
// SSE2 (гарантирован на x64) + AVX2 при наличии /arch:AVX2
static bool HasNullByte(const char* data, size_t len) {
    const char* p   = data;
    const char* end = data + len;

#if defined(__AVX2__)
    const __m256i z256 = _mm256_setzero_si256();
    for (; p + 32 <= end; p += 32) {
        __m256i v = _mm256_loadu_si256((const __m256i*)p);
        if (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v, z256))) return true;
    }
#endif
    const __m128i z128 = _mm_setzero_si128();
    for (; p + 16 <= end; p += 16) {
        __m128i v = _mm_loadu_si128((const __m128i*)p);
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(v, z128))) return true;
    }
    for (; p < end; ++p)
        if (!*p) return true;
    return false;
}

// --- ЗАМЕНА std::regex: РУЧНОЙ КОНЕЧНЫЙ АВТОМАТ ---
// Ищет паттерн:  =\s*\{[allowed_chars]{50,}\};
// allowed_chars: пробел, таб, \r, \n, 0-9, a-f, A-F, x, X, запятая
// В 10-50 раз быстрее std::regex; работает прямо по const char* без копий.
// Возвращает true если была замена; result содержит очищенный текст.
static bool CleanHexArrays(const char* src, size_t len, std::string& result) {
    if (len > 500000) return false;

    // Быстрый pre-check: есть ли вообще "= {" в файле?
    bool found = false;
    for (size_t i = 0; i + 2 < len; ++i) {
        if (src[i] == '=' && src[i+1] == ' ' && src[i+2] == '{') { found = true; break; }
        if (src[i] == '=' && src[i+1] == '{') { found = true; break; }
    }
    if (!found) return false;

    result.clear();
    result.reserve(len);

    const char* cur = src;
    const char* end = src + len;

    while (cur < end) {
        // Ищем '=' через memchr — vectorized в CRT
        const char* eq = (const char*)memchr(cur, '=', (size_t)(end - cur));
        if (!eq) { result.append(cur, end); break; }

        result.append(cur, (size_t)(eq - cur));
        cur = eq;

        // Пропускаем пробелы после '='
        const char* s = eq + 1;
        while (s < end && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) ++s;

        if (s >= end || *s != '{') { result += *cur++; continue; }
        ++s; // пропускаем '{'

        // Сканируем тело: только разрешённые символы
        const char* bodyStart = s;
        int  count = 0;
        bool valid = true;
        while (s < end) {
            unsigned char c = (unsigned char)*s;
            if (c == '}') break;
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
                c == 'x' || c == 'X'  || c == ',' ||
                c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                ++count; ++s;
            } else { valid = false; break; }
        }

        if (!valid || s >= end || *s != '}') { result += *cur++; continue; }
        ++s; // '}'
        if (s >= end || *s != ';')           { result += *cur++; continue; }
        ++s; // ';'

        if (count >= 50) {
            result += "= { /* HEX DATA HIDDEN */ };";
            cur = s;
        } else {
            result += *cur++;
        }
    }

    return true; // была хотя бы одна попытка замены
}

// --- БУФЕРИЗОВАННЫЙ ВЫВОД ЧЕРЕЗ WriteFile (без виртуальных вызовов ofstream) ---
struct OutBuf {
    HANDLE h   = INVALID_HANDLE_VALUE;
    char*  buf = nullptr;
    DWORD  cap = 0;
    DWORD  pos = 0;

    bool open(const wchar_t* path, DWORD bufSz) {
        buf = new char[bufSz];
        cap = bufSz;
        h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
        if (h == INVALID_HANDLE_VALUE) { delete[] buf; buf = nullptr; return false; }
        return true;
    }

    // Большие блоки (контент файлов) идут напрямую, минуя внутренний буфер
    __forceinline void write(const char* data, DWORD len) {
        if (len >= cap) { flush(); DWORD w; WriteFile(h, data, len, &w, NULL); return; }
        while (len > 0) {
            DWORD n = min(len, cap - pos);
            memcpy(buf + pos, data, n);
            pos += n; data += n; len -= n;
            if (pos == cap) flush();
        }
    }

    void flush() { if (pos) { DWORD w; WriteFile(h, buf, pos, &w, NULL); pos = 0; } }

    void close() {
        flush();
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); h = INVALID_HANDLE_VALUE; }
        delete[] buf; buf = nullptr;
    }
};

// --- СТЕК ДИРЕКТОРИЙ (один pathBuf, без std::wstring) ---
struct DirLevel {
    HANDLE hFind   = INVALID_HANDLE_VALUE;
    DWORD  pathEnd = 0;
    bool   first   = true;
};

// --- КАНАЛ: PRODUCER-CONSUMER С BOUNDED QUEUE ---
template<typename T>
struct Chan {
    std::deque<T>           q;
    std::mutex              mtx;
    std::condition_variable cv_pop, cv_push;
    size_t                  cap;
    bool                    closed = false;

    explicit Chan(size_t c) : cap(c) {}

    // Возвращает false если канал закрыт
    bool send(T item) {
        std::unique_lock<std::mutex> lk(mtx);
        cv_push.wait(lk, [&]{ return q.size() < cap || closed; });
        if (closed) return false;
        q.push_back(std::move(item));
        cv_pop.notify_one();
        return true;
    }

    // Возвращает false когда закрыт И пуст
    bool recv(T& item) {
        std::unique_lock<std::mutex> lk(mtx);
        cv_pop.wait(lk, [&]{ return !q.empty() || closed; });
        if (q.empty()) return false;
        item = std::move(q.front());
        q.pop_front();
        cv_push.notify_one();
        return true;
    }

    void close() {
        std::lock_guard<std::mutex> lk(mtx);
        closed = true;
        cv_pop.notify_all();
        cv_push.notify_all();
    }
};

// --- ЯДРО СКАНИРОВАНИЯ file_list.txt (не нуждается в параллелизме — I/O bound) ---
void GenerateFileList(const std::wstring& folderPath) {
    std::wstring baseStr = folderPath;
    if (!baseStr.empty() && baseStr.back() != L'\\') baseStr += L'\\';
    const DWORD baseLen = (DWORD)baseStr.length();

    OutBuf out;
    if (!out.open((baseStr + L"file_list.txt").c_str(), 1 * 1024 * 1024)) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }

    static wchar_t pathBuf[32768];
    wmemcpy(pathBuf, baseStr.c_str(), baseLen + 1);
    DWORD pathLen = baseLen;

    static char utf8Buf[MAX_PATH * 4 + 2];
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

// --- ОПРЕДЕЛЕНИЕ ТИПА ДИСКА (SSD / HDD) ---
// Использует IOCTL_STORAGE_QUERY_PROPERTY → IncursSeekPenalty.
// SSD = нет штрафа за seek → можно много параллельных потоков.
// HDD = есть штраф      → параллельность вредит (head thrashing).
static bool IsPathOnSSD(const wchar_t* path) {
    wchar_t volumePath[MAX_PATH] = {};
    if (!GetVolumePathNameW(path, volumePath, MAX_PATH)) return true;

    // Из "C:\" делаем "\\.\C:" для DeviceIoControl
    if (wcslen(volumePath) < 2 || volumePath[1] != L':') return true;
    wchar_t devPath[] = { L'\\',L'\\',L'.',L'\\', volumePath[0], L':', L'\0' };

    HANDLE hDev = CreateFileW(devPath, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);
    if (hDev == INVALID_HANDLE_VALUE) return true; // не определили → считаем SSD

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

// --- ЯДРО ДАМПА all.txt: ПАРАЛЛЕЛЬНАЯ ОБРАБОТКА ---
//
// SSD: [Сканер] → pathChan(256) → [Worker × N]  → outChan(64) → [Output thread]
// HDD: [Сканер] → pathChan(16)  → [Worker × 2]  → outChan(32) → [Output thread]
//
// На HDD больше 2 воркеров вызывают head-thrashing и замедляют работу.
// На SSD/NVMe параллельные запросы утилизируют очередь контроллера (NCQ/NVMe queue).

void GenerateAllTxt(const std::wstring& folderPath) {
    std::wstring baseStr = folderPath;
    if (!baseStr.empty() && baseStr.back() != L'\\') baseStr += L'\\';
    const DWORD baseLen = (DWORD)baseStr.length();

    OutBuf out;
    if (!out.open((baseStr + L"all.txt").c_str(), 8 * 1024 * 1024)) {
        PostMessage(g_hProgressWnd, WM_CLOSE, 0, 0);
        return;
    }

    // Определяем тип диска и подбираем параметры
    const bool ssd = IsPathOnSSD(baseStr.c_str());
    const int  numWorkers    = ssd ? max(2, min(8, (int)std::thread::hardware_concurrency() - 2)) : 2;
    const int  pathChanCap   = ssd ? 256 : 16;   // HDD: маленькая очередь = меньше seek-ов
    const int  outChanCap    = ssd ? 64  : 32;

    // Каналы
    Chan<std::wstring> pathChan(pathChanCap);
    Chan<std::string>  outChan(outChanCap);

    std::atomic<int> activeWorkers(numWorkers);

    // --- ВОРКЕР: mmap + SIMD binary check + state-machine hex clean ---
    auto workerFn = [&]() {
        std::wstring fullPath;
        char utf8Buf[MAX_PATH * 4 + 4];
        std::string  cleaned;

        while (pathChan.recv(fullPath)) {
            if (g_cancel.load(std::memory_order_relaxed)) continue;

            // Открываем файл
            HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            LARGE_INTEGER fsz;
            if (!GetFileSizeEx(hFile, &fsz) || fsz.QuadPart == 0) { CloseHandle(hFile); continue; }

            DWORD sz = (DWORD)min(fsz.QuadPart, (LONGLONG)50 * 1024 * 1024);

            // Memory Mapped File: ОС сама управляет кэшем, ноль лишних копий ядро→юзер
            HANDLE hMap = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, sz, NULL);
            CloseHandle(hFile);
            if (!hMap) continue;

            const char* view = (const char*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, sz);
            if (!view) { CloseHandle(hMap); continue; }

            // SIMD проверка на бинарность (первые 1024 байта)
            bool isBinary = HasNullByte(view, min((size_t)sz, (size_t)1024));
            if (isBinary) { UnmapViewOfFile(view); CloseHandle(hMap); continue; }

            // UTF-8 конвертация относительного пути (single-pass, стековый буфер)
            int relWLen = (int)(fullPath.size() - (size_t)baseLen);
            int utf8Len = WideCharToMultiByte(CP_UTF8, 0,
                fullPath.c_str() + baseLen, relWLen,
                utf8Buf, (int)sizeof(utf8Buf) - 4, NULL, NULL);
            if (utf8Len <= 0) { UnmapViewOfFile(view); CloseHandle(hMap); continue; }

            // Собираем выходной блок:
            //   "rel/path:\n"
            //   "----------\n"
            //   <content>\n\n
            std::string chunk;
            chunk.reserve((size_t)utf8Len * 2 + 4 + sz);

            // Заголовок
            chunk.append(utf8Buf, (size_t)utf8Len);
            chunk += ":\n";
            chunk.append((size_t)utf8Len, '-');
            chunk += '\n';

            // Контент: пробуем очистить hex-массивы через state-machine (без regex!)
            // Если файл > 500KB или нет замен — читаем прямо из mmap (zero-copy)
            if (sz < 500000 && CleanHexArrays(view, sz, cleaned))
                chunk += cleaned;
            else
                chunk.append(view, sz);

            chunk += "\n\n";

            UnmapViewOfFile(view);
            CloseHandle(hMap);

            outChan.send(std::move(chunk));
        }

        // Последний воркер закрывает outChan → output-поток завершается
        if (--activeWorkers == 0)
            outChan.close();
    };

    // --- OUTPUT ПОТОК: последовательная запись ---
    std::thread outputThread([&]() {
        std::string chunk;
        while (outChan.recv(chunk))
            out.write(chunk.data(), (DWORD)chunk.size());
    });

    // --- ЗАПУСК ВОРКЕРОВ ---
    std::vector<std::thread> workers;
    workers.reserve(numWorkers);
    for (int i = 0; i < numWorkers; ++i)
        workers.emplace_back(workerFn);

    // --- СКАНЕР (текущий поток): обход дерева директорий ---
    static wchar_t pathBuf[32768];
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

    // Cleanup сканера
    for (auto& lv : stk) if (lv.hFind != INVALID_HANDLE_VALUE) FindClose(lv.hFind);

    // Сигнал воркерам: новых задач не будет
    pathChan.close();

    // Ждём завершения всех потоков
    for (auto& w : workers) w.join();
    outputThread.join();

    out.close();
    if (g_cancel.load()) DeleteFileW((baseStr + L"all.txt").c_str());
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

// --- ЛОГИКА ВСТАВКИ ИЗОБРАЖЕНИЯ ---
void PasteImage(const std::wstring& folderPath) {
    if (!OpenClipboard(NULL)) return;
    HBITMAP hBitmap = (HBITMAP)GetClipboardData(CF_BITMAP);
    if (hBitmap) {
        std::wstring targetDir = folderPath;
        if (!targetDir.empty() && targetDir.back() != L'\\') targetDir += L'\\';
        std::wstring finalPath = targetDir + L"screenshot.png";
        for (int i = 2; FileExists(finalPath); ++i)
            finalPath = targetDir + L"screenshot (" + std::to_wstring(i) + L").png";

        IWICImagingFactory*    pFactory   = nullptr;
        IWICBitmap*            pWicBitmap = nullptr;
        IWICStream*            pStream    = nullptr;
        IWICBitmapEncoder*     pEncoder   = nullptr;
        IWICBitmapFrameEncode* pFrame     = nullptr;
        IPropertyBag2*         pProps     = nullptr;

        bool saved = false;
        if (SUCCEEDED(CoCreateInstance(CLSID_WICImagingFactory, nullptr, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pFactory))) &&
            SUCCEEDED(pFactory->CreateBitmapFromHBITMAP(hBitmap, nullptr, WICBitmapIgnoreAlpha, &pWicBitmap)) &&
            SUCCEEDED(pFactory->CreateStream(&pStream)) &&
            SUCCEEDED(pStream->InitializeFromFilename(finalPath.c_str(), GENERIC_WRITE)) &&
            SUCCEEDED(pFactory->CreateEncoder(GUID_ContainerFormatPng, nullptr, &pEncoder)) &&
            SUCCEEDED(pEncoder->Initialize(pStream, WICBitmapEncoderNoCache)) &&
            SUCCEEDED(pEncoder->CreateNewFrame(&pFrame, &pProps)))
        {
            PROPBAG2 opt = {};
            opt.pstrName = const_cast<LPOLESTR>(L"CompressionQuality");
            VARIANT val  = {}; val.vt = VT_R4; val.fltVal = 0.0f;
            pProps->Write(1, &opt, &val);
            UINT w = 0, h = 0;
            pWicBitmap->GetSize(&w, &h);
            WICPixelFormatGUID fmt = GUID_WICPixelFormat24bppBGR;
            if (SUCCEEDED(pFrame->Initialize(pProps)) &&
                SUCCEEDED(pFrame->SetSize(w, h)) &&
                SUCCEEDED(pFrame->SetPixelFormat(&fmt)) &&
                SUCCEEDED(pFrame->WriteSource(pWicBitmap, nullptr)) &&
                SUCCEEDED(pFrame->Commit()) &&
                SUCCEEDED(pEncoder->Commit()))
                saved = true;
        }
        if (pProps)     pProps->Release();
        if (pFrame)     pFrame->Release();
        if (pEncoder)   pEncoder->Release();
        if (pStream)    pStream->Release();
        if (pWicBitmap) pWicBitmap->Release();
        if (pFactory)   pFactory->Release();
        if (!saved) { CImage img; img.Attach(hBitmap); img.Save(finalPath.c_str(), Gdiplus::ImageFormatPNG); img.Detach(); }
    }
    CloseClipboard();
}

// --- РЕГИСТРАЦИЯ В РЕЕСТРЕ ---
static void CreateRegKey(const std::wstring& keyPath, const std::wstring& name,
                         const std::wstring& icon,    const std::wstring& cmd) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, NULL,    0, REG_SZ, (const BYTE*)name.c_str(), (DWORD)(name.length()+1)*2);
        RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)icon.c_str(), (DWORD)(icon.length()+1)*2);
        HKEY hCmd;
        if (RegCreateKeyExW(hKey, L"command", 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hCmd, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hCmd, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)(cmd.length()+1)*2);
            RegCloseKey(hCmd);
        }
        RegCloseKey(hKey);
    }
}

static void RegisterMenu() {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    std::wstring p = L"\""; p += exe; p += L"\"";
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\PastePNG",
        L"Вставить как PNG",             L"imageres.dll,-72",  p + L" -paste \"%V\"");
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\GenList",
        L"Создать список файлов",         L"shell32.dll,-152",  p + L" -list \"%V\"");
    CreateRegKey(L"Software\\Classes\\Directory\\Background\\shell\\GenDump",
        L"Создать полный дамп (all.txt)", L"shell32.dll,-264",  p + L" -dump \"%V\"");
    MessageBoxW(NULL,
        L"Контекстное меню успешно обновлено!\nДобавлен пункт 'Создать полный дамп'",
        L"Успех", MB_OK | MB_ICONINFORMATION);
}

// --- ТОЧКА ВХОДА ---
int main() {
#if defined(__AVX2__)
    // Если это скомпилировалось, значит флаг /arch:AVX2 работает
#else
#error AVX2 is NOT enabled! Check project settings.
#endif
    int args;
    LPWSTR* argList = CommandLineToArgvW(GetCommandLineW(), &args);
    if (args >= 3) {
        std::wstring flag = argList[1];
        std::wstring path = argList[2];
        CoInitialize(NULL);
        if      (flag == L"-paste") PasteImage(path);
        else if (flag == L"-list")  ShowProgressAndRun(path, false);
        else if (flag == L"-dump")  ShowProgressAndRun(path, true);
        CoUninitialize();
    } else {
        RegisterMenu();
    }
    if (argList) LocalFree(argList);
    return 0;
}
