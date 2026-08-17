#include "Scripts.h"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <regex>
#include "Utils/FileSystem/FileSystemUtils.h"

#pragma comment(lib, "winhttp.lib")

static std::string HttpGet(const wchar_t* host, const wchar_t* path) {
    HINTERNET hSession = WinHttpOpen(L"WindowsUtility/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

    WinHttpAddRequestHeaders(hRequest, L"User-Agent: WindowsUtility/1.0\r\n", -1, WINHTTP_ADDREQ_FLAG_ADD);

    bool res = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
               WinHttpReceiveResponse(hRequest, NULL);

    std::string response;
    if (res) {
        DWORD size = 0, downloaded = 0;
        do {
            size = 0;
            WinHttpQueryDataAvailable(hRequest, &size);
            if (!size) break;
            char* buf = new char[size];
            if (WinHttpReadData(hRequest, (LPVOID)buf, size, &downloaded)) {
                response.append(buf, downloaded);
            }
            delete[] buf;
        } while (size > 0);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

static void CreateRegKeyLocal(const std::wstring& keyPath, const std::wstring& name,
                              const std::wstring& icon, const std::wstring& cmd) {
    HKEY hKey;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, keyPath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        if (!name.empty()) RegSetValueExW(hKey, L"MUIVerb", 0, REG_SZ, (const BYTE*)name.c_str(), (DWORD)(name.length() + 1) * 2);
        if (!icon.empty()) RegSetValueExW(hKey, L"Icon", 0, REG_SZ, (const BYTE*)icon.c_str(), (DWORD)(icon.length() + 1) * 2);
        HKEY hCmd;
        if (RegCreateKeyExW(hKey, L"command", 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hCmd, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hCmd, NULL, 0, REG_SZ, (const BYTE*)cmd.c_str(), (DWORD)(cmd.length() + 1) * 2);
            RegCloseKey(hCmd);
        }
        RegCloseKey(hKey);
    }
}

void UpdateScriptsMenu() {
    std::string json = HttpGet(L"api.github.com", L"/repos/nikitagrinn/scripts/contents/");
    if (json.empty()) {
        MessageBoxW(NULL, L"Не удалось получить список скриптов с GitHub. Проверьте интернет-соединение.", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    std::regex re("\"name\"\\s*:\\s*\"([^\"]+\\.py)\"");
    auto words_begin = std::sregex_iterator(json.begin(), json.end(), re);
    auto words_end = std::sregex_iterator();

    std::vector<std::wstring> scripts;
    for (std::sregex_iterator i = words_begin; i != words_end; ++i) {
        std::string match = (*i)[1].str();
        int wlen = MultiByteToWideChar(CP_UTF8, 0, match.c_str(), -1, NULL, 0);
        if (wlen > 0) {
            std::wstring wmatch(wlen, 0);
            MultiByteToWideChar(CP_UTF8, 0, match.c_str(), -1, &wmatch[0], wlen);
            if (!wmatch.empty() && wmatch.back() == L'\0') wmatch.pop_back(); 
            scripts.push_back(wmatch);
        }
    }

    std::wstring basePath = L"Software\\Classes\\Directory\\Background\\shell\\WindowsUtility\\shell\\Scripts";
    RegDeleteTreeW(HKEY_CURRENT_USER, basePath.c_str()); 

    HKEY hScripts;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, basePath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hScripts, NULL) == ERROR_SUCCESS) {
        std::wstring title = L"Скрипты";
        std::wstring icon = L"imageres.dll,-114";
        RegSetValueExW(hScripts, L"MUIVerb", 0, REG_SZ, (const BYTE*)title.c_str(), (DWORD)(title.length() + 1) * 2);
        RegSetValueExW(hScripts, L"Icon", 0, REG_SZ, (const BYTE*)icon.c_str(), (DWORD)(icon.length() + 1) * 2);
        RegSetValueExW(hScripts, L"SubCommands", 0, REG_SZ, (const BYTE*)L"", 2);
        RegCloseKey(hScripts);
    }

    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);
    std::wstring p = L"\""; p += exe; p += L"\"";

    std::wstring updatePath = basePath + L"\\shell\\00_Update";
    CreateRegKeyLocal(updatePath, L"Обновить список", L"shell32.dll,-238", p + L" -updatescripts");

    int idx = 1;
    for (const auto& script : scripts) {
        std::wstring scriptPath = basePath + L"\\shell\\01_Script_" + std::to_wstring(idx++);
        CreateRegKeyLocal(scriptPath, script, L"imageres.dll,-114", p + L" -runscript \"" + script + L"\" \"%V\"");
    }

    std::wstring msg = L"Успешно загружено скриптов: " + std::to_wstring(scripts.size());
    MessageBoxW(NULL, msg.c_str(), L"Обновление завершено", MB_OK | MB_ICONINFORMATION);
}

void RunGithubScript(const std::wstring& scriptName, const std::wstring& targetFolder) {
    std::wstring safeUrlPath = L"/nikitagrinn/scripts/main/" + scriptName;
    std::string scriptContent = HttpGet(L"raw.githubusercontent.com", safeUrlPath.c_str());
    
    if (scriptContent.empty()) {
        MessageBoxW(NULL, L"Не удалось скачать скрипт.", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    std::wstring outFolder = targetFolder;
    if (!outFolder.empty() && outFolder.back() != L'\\') outFolder += L'\\';
    std::wstring finalPath = outFolder + scriptName;

    HANDLE hFile = CreateFileW(finalPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hFile, scriptContent.data(), (DWORD)scriptContent.size(), &written, NULL);
        CloseHandle(hFile);
    } else {
        MessageBoxW(NULL, L"Не удалось сохранить скрипт в текущую папку.", L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    std::wstring pythonArgs = L"\"" + finalPath + L"\"";
    HINSTANCE hInst = ShellExecuteW(NULL, L"open", L"python", pythonArgs.c_str(), outFolder.c_str(), SW_SHOW);
    if ((INT_PTR)hInst <= 32) {
        MessageBoxW(NULL, L"Не удалось запустить Python. Убедитесь, что python добавлен в PATH.", L"Ошибка", MB_OK | MB_ICONERROR);
    }
}
