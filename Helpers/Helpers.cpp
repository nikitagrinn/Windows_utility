#include <windows.h>
#include <string>
#include "Features/PasteImage/PasteImage.h"
#include "Features/Scripts/Scripts.h"
#include "UI/ProgressWindow/ProgressWindow.h"

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(linker, "/SUBSYSTEM:windows /ENTRY:mainCRTStartup")

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

    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\Background\\shell\\PastePNG");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\Background\\shell\\GenList");
    RegDeleteTreeW(HKEY_CURRENT_USER, L"Software\\Classes\\Directory\\Background\\shell\\GenDump");

    std::wstring parentPath = L"Software\\Classes\\Directory\\Background\\shell\\WindowsUtility";
    HKEY hParent;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, parentPath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hParent, NULL) == ERROR_SUCCESS) {
        std::wstring title = L"Утилиты Windows";
        std::wstring icon = L"shell32.dll,-324";
        RegSetValueExW(hParent, L"MUIVerb", 0, REG_SZ, (const BYTE*)title.c_str(), (DWORD)(title.length()+1)*2);
        RegSetValueExW(hParent, L"Icon", 0, REG_SZ, (const BYTE*)icon.c_str(), (DWORD)(icon.length()+1)*2);
        RegSetValueExW(hParent, L"SubCommands", 0, REG_SZ, (const BYTE*)L"", 2);
        RegCloseKey(hParent);
    }

    std::wstring subPath = parentPath + L"\\shell\\";
    CreateRegKey(subPath + L"PastePNG", L"Вставить как PNG",             L"imageres.dll,-72",  p + L" -paste \"%V\"");
    CreateRegKey(subPath + L"GenList",  L"Создать список файлов",         L"shell32.dll,-152",  p + L" -list \"%V\"");
    CreateRegKey(subPath + L"GenDump",  L"Создать полный дамп (all.txt)", L"shell32.dll,-264",  p + L" -dump \"%V\"");

    std::wstring scriptsPath = parentPath + L"\\shell\\Scripts";
    HKEY hScripts;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, scriptsPath.c_str(), 0, NULL,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hScripts, NULL) == ERROR_SUCCESS) {
        std::wstring sTitle = L"Скрипты";
        std::wstring sIcon = L"imageres.dll,-114";
        RegSetValueExW(hScripts, L"MUIVerb", 0, REG_SZ, (const BYTE*)sTitle.c_str(), (DWORD)(sTitle.length()+1)*2);
        RegSetValueExW(hScripts, L"Icon", 0, REG_SZ, (const BYTE*)sIcon.c_str(), (DWORD)(sIcon.length()+1)*2);
        RegSetValueExW(hScripts, L"SubCommands", 0, REG_SZ, (const BYTE*)L"", 2);
        RegCloseKey(hScripts);
    }
    CreateRegKey(scriptsPath + L"\\shell\\00_Update", L"Обновить список", L"shell32.dll,-238", p + L" -updatescripts");

    MessageBoxW(NULL,
        L"Контекстное меню успешно обновлено!\nВсе функции объединены во вложенное меню 'Утилиты Windows'.",
        L"Успех", MB_OK | MB_ICONINFORMATION);
}

int main() {
#if defined(__AVX2__)
#else
#error AVX2 is NOT enabled! Check project settings.
#endif
    int args;
    LPWSTR* argList = CommandLineToArgvW(GetCommandLineW(), &args);
    if (args >= 2 && std::wstring(argList[1]) == L"-updatescripts") {
        UpdateScriptsMenu();
    } else if (args >= 3) {
        std::wstring flag = argList[1];
        std::wstring path = argList[2];
        CoInitialize(NULL);
        if      (flag == L"-paste") PasteImage(path);
        else if (flag == L"-list")  ShowProgressAndRun(path, false);
        else if (flag == L"-dump")  ShowProgressAndRun(path, true);
        else if (flag == L"-runscript" && args >= 4) {
            std::wstring folder = argList[3];
            RunGithubScript(path, folder);
        }
        CoUninitialize();
    } else {
        RegisterMenu();
    }
    if (argList) LocalFree(argList);
    return 0;
}
