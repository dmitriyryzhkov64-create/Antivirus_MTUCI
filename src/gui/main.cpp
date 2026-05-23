#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <strsafe.h>

#include <string>
#include <ctime>

#include "../common/service_names.h"
#include "../common/rpc_status.h"
#include "../rpc/rpc_client.h"

#define WM_TRAYICON (WM_APP + 1)

#define ID_TRAY_OPEN 1001
#define ID_TRAY_EXIT 1002
#define ID_FILE_EXIT 2001

#define ID_EDIT_LOGIN 3001
#define ID_EDIT_PASSWORD 3002
#define ID_BUTTON_LOGIN 3003
#define ID_EDIT_ACTIVATION 3004
#define ID_BUTTON_ACTIVATE 3005
#define ID_BUTTON_LOGOUT 3006
#define ID_EDIT_SCAN_PATH 3007
#define ID_BUTTON_SCAN_FILE 3008
#define ID_BUTTON_SCAN_DIR 3009

#define ID_TIMER_LICENSE 4001

static const wchar_t* APP_CLASS_NAME = L"AntivirusMTUCIMainWindowClass";
static const wchar_t* MUTEX_NAME = L"Local\\AntivirusMTUCISingleInstanceMutex";

HINSTANCE g_hInstance = nullptr;
HWND g_hWnd = nullptr;
HANDLE g_hMutex = nullptr;
UINT g_taskbarCreatedMsg = 0;
bool g_trayIconAdded = false;

HWND g_statusLabel = nullptr;
HWND g_userLabel = nullptr;
HWND g_licenseLabel = nullptr;

HWND g_loginLabel = nullptr;
HWND g_loginEdit = nullptr;
HWND g_passwordLabel = nullptr;
HWND g_passwordEdit = nullptr;
HWND g_loginButton = nullptr;

HWND g_activationLabel = nullptr;
HWND g_activationEdit = nullptr;
HWND g_activationButton = nullptr;

HWND g_logoutButton = nullptr;
HWND g_databaseLabel = nullptr;
HWND g_scanPathLabel = nullptr;
HWND g_scanPathEdit = nullptr;
HWND g_scanFileButton = nullptr;
HWND g_scanDirButton = nullptr;
HWND g_scanResultLabel = nullptr;

std::wstring g_currentUser;
bool g_isAuthenticated = false;
bool g_hasLicense = false;
long long g_licenseExpiresAt = 0;

void RefreshApplicationState();
void RenderUi();

bool CreateSingleInstanceMutex()
{
    g_hMutex = CreateMutexW(nullptr, TRUE, MUTEX_NAME);

    if (!g_hMutex)
        return false;

    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        CloseHandle(g_hMutex);
        g_hMutex = nullptr;
        return false;
    }

    return true;
}

bool IsServiceRunning()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    SC_HANDLE service = OpenServiceW(scm, SERVICE_NAME, SERVICE_QUERY_STATUS);
    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD bytesNeeded = 0;
    bool running = false;

    if (QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytesNeeded))
    {
        running = status.dwCurrentState == SERVICE_RUNNING;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return running;
}

bool StartServiceAndWait()
{
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return false;

    SC_HANDLE service = OpenServiceW(
        scm,
        SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS
    );

    if (!service)
    {
        CloseServiceHandle(scm);
        return false;
    }

    StartServiceW(service, 0, nullptr);

    bool running = false;

    for (int i = 0; i < 30; ++i)
    {
        SERVICE_STATUS_PROCESS status{};
        DWORD bytesNeeded = 0;

        if (QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&status),
            sizeof(status),
            &bytesNeeded))
        {
            if (status.dwCurrentState == SERVICE_RUNNING)
            {
                running = true;
                break;
            }
        }

        Sleep(1000);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);

    return running;
}

DWORD GetParentProcessId()
{
    DWORD currentPid = GetCurrentProcessId();
    DWORD parentPid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == currentPid)
            {
                parentPid = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return parentPid;
}

bool IsParentService()
{
    DWORD parentPid = GetParentProcessId();
    if (parentPid == 0)
        return false;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return false;

    bool result = false;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (entry.th32ProcessID == parentPid)
            {
                result = _wcsicmp(entry.szExeFile, SERVICE_EXE_NAME) == 0;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return result;
}

bool HasArgument(LPCWSTR arg)
{
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    if (!argv)
        return false;

    bool found = false;

    for (int i = 1; i < argc; ++i)
    {
        if (_wcsicmp(argv[i], arg) == 0)
        {
            found = true;
            break;
        }
    }

    LocalFree(argv);
    return found;
}

HMENU CreateMainMenu()
{
    HMENU menuBar = CreateMenu();
    HMENU fileMenu = CreatePopupMenu();

    AppendMenuW(fileMenu, MF_STRING, ID_FILE_EXIT, L"Выход");
    AppendMenuW(menuBar, MF_POPUP, reinterpret_cast<UINT_PTR>(fileMenu), L"Файл");

    return menuBar;
}

void AddTrayIcon(HWND hwnd)
{
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = WM_TRAYICON;
    nid.hIcon = LoadIconW(nullptr, IDI_APPLICATION);

    StringCchCopyW(nid.szTip, ARRAYSIZE(nid.szTip), APP_NAME);

    if (Shell_NotifyIconW(NIM_ADD, &nid))
    {
        g_trayIconAdded = true;
        nid.uVersion = NOTIFYICON_VERSION_4;
        Shell_NotifyIconW(NIM_SETVERSION, &nid);
    }
}

void RemoveTrayIcon(HWND hwnd)
{
    if (!g_trayIconAdded)
        return;

    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = 1;

    Shell_NotifyIconW(NIM_DELETE, &nid);
    g_trayIconAdded = false;
}

void ShowMainWindow(HWND hwnd)
{
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
}

void ShowTrayMenu(HWND hwnd)
{
    POINT pt{};
    GetCursorPos(&pt);

    HMENU menu = CreatePopupMenu();

    AppendMenuW(menu, MF_STRING, ID_TRAY_OPEN, L"Открыть");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"Выход");

    SetForegroundWindow(hwnd);

    TrackPopupMenu(
        menu,
        TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
        pt.x,
        pt.y,
        0,
        hwnd,
        nullptr
    );

    DestroyMenu(menu);
}

std::wstring UnixTimeToString(long long unixTime)
{
    if (unixTime <= 0)
        return L"неизвестно";

    std::time_t rawTime = static_cast<std::time_t>(unixTime);
    tm localTime{};

    localtime_s(&localTime, &rawTime);

    wchar_t buffer[128]{};

    wcsftime(
        buffer,
        ARRAYSIZE(buffer),
        L"%d.%m.%Y %H:%M:%S",
        &localTime
    );

    return buffer;
}

void HideAllDynamicControls()
{
    HWND controls[] =
    {
        g_loginLabel,
        g_loginEdit,
        g_passwordLabel,
        g_passwordEdit,
        g_loginButton,
        g_activationLabel,
        g_activationEdit,
        g_activationButton,
        g_logoutButton,
        g_databaseLabel,
        g_scanPathLabel,
        g_scanPathEdit,
        g_scanFileButton,
        g_scanDirButton,
        g_scanResultLabel
    };

    for (HWND control : controls)
    {
        if (control)
            ShowWindow(control, SW_HIDE);
    }
}

void CreateUiControls(HWND hwnd)
{
    g_statusLabel = CreateWindowW(
        L"STATIC",
        L"",
        WS_VISIBLE | WS_CHILD,
        20,
        20,
        560,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_userLabel = CreateWindowW(
        L"STATIC",
        L"",
        WS_VISIBLE | WS_CHILD,
        20,
        55,
        520,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_licenseLabel = CreateWindowW(
        L"STATIC",
        L"",
        WS_VISIBLE | WS_CHILD,
        20,
        90,
        520,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_loginLabel = CreateWindowW(
        L"STATIC",
        L"Логин:",
        WS_CHILD,
        20,
        140,
        100,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_loginEdit = CreateWindowW(
        L"EDIT",
        L"",
        WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        130,
        140,
        250,
        24,
        hwnd,
        reinterpret_cast<HMENU>(ID_EDIT_LOGIN),
        g_hInstance,
        nullptr
    );

    g_passwordLabel = CreateWindowW(
        L"STATIC",
        L"Пароль:",
        WS_CHILD,
        20,
        175,
        100,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_passwordEdit = CreateWindowW(
        L"EDIT",
        L"",
        WS_CHILD | WS_BORDER | ES_PASSWORD | ES_AUTOHSCROLL,
        130,
        175,
        250,
        24,
        hwnd,
        reinterpret_cast<HMENU>(ID_EDIT_PASSWORD),
        g_hInstance,
        nullptr
    );

    g_loginButton = CreateWindowW(
        L"BUTTON",
        L"Войти",
        WS_CHILD,
        130,
        215,
        120,
        30,
        hwnd,
        reinterpret_cast<HMENU>(ID_BUTTON_LOGIN),
        g_hInstance,
        nullptr
    );

    g_activationLabel = CreateWindowW(
        L"STATIC",
        L"Код активации:",
        WS_CHILD,
        20,
        140,
        130,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_activationEdit = CreateWindowW(
        L"EDIT",
        L"",
        WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        160,
        140,
        260,
        24,
        hwnd,
        reinterpret_cast<HMENU>(ID_EDIT_ACTIVATION),
        g_hInstance,
        nullptr
    );

    g_activationButton = CreateWindowW(
        L"BUTTON",
        L"Активировать",
        WS_CHILD,
        160,
        180,
        140,
        30,
        hwnd,
        reinterpret_cast<HMENU>(ID_BUTTON_ACTIVATE),
        g_hInstance,
        nullptr
    );

    g_logoutButton = CreateWindowW(
        L"BUTTON",
        L"Выйти из аккаунта",
        WS_CHILD,
        20,
        260,
        180,
        30,
        hwnd,
        reinterpret_cast<HMENU>(ID_BUTTON_LOGOUT),
        g_hInstance,
        nullptr
    );

    g_databaseLabel = CreateWindowW(
        L"STATIC",
        L"",
        WS_CHILD,
        20,
        300,
        560,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_scanPathLabel = CreateWindowW(
        L"STATIC",
        L"Путь для сканирования:",
        WS_CHILD,
        20,
        330,
        180,
        24,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );

    g_scanPathEdit = CreateWindowW(
        L"EDIT",
        L"",
        WS_CHILD | WS_BORDER | ES_AUTOHSCROLL,
        200,
        330,
        360,
        24,
        hwnd,
        reinterpret_cast<HMENU>(ID_EDIT_SCAN_PATH),
        g_hInstance,
        nullptr
    );

    g_scanFileButton = CreateWindowW(
        L"BUTTON",
        L"Сканировать файл",
        WS_CHILD,
        200,
        365,
        160,
        30,
        hwnd,
        reinterpret_cast<HMENU>(ID_BUTTON_SCAN_FILE),
        g_hInstance,
        nullptr
    );

    g_scanDirButton = CreateWindowW(
        L"BUTTON",
        L"Сканировать папку",
        WS_CHILD,
        380,
        365,
        160,
        30,
        hwnd,
        reinterpret_cast<HMENU>(ID_BUTTON_SCAN_DIR),
        g_hInstance,
        nullptr
    );

    g_scanResultLabel = CreateWindowW(
        L"STATIC",
        L"",
        WS_CHILD,
        20,
        405,
        580,
        60,
        hwnd,
        nullptr,
        g_hInstance,
        nullptr
    );
}

void RenderUi()
{
    HideAllDynamicControls();

    if (!g_isAuthenticated)
    {
        SetWindowTextW(g_statusLabel, L"Антивирусная функциональность заблокирована");
        SetWindowTextW(g_userLabel, L"Пользователь не аутентифицирован");
        SetWindowTextW(g_licenseLabel, L"Войдите в учётную запись");

        ShowWindow(g_loginLabel, SW_SHOW);
        ShowWindow(g_loginEdit, SW_SHOW);
        ShowWindow(g_passwordLabel, SW_SHOW);
        ShowWindow(g_passwordEdit, SW_SHOW);
        ShowWindow(g_loginButton, SW_SHOW);

        return;
    }

    std::wstring userText = L"Пользователь: " + g_currentUser;
    SetWindowTextW(g_userLabel, userText.c_str());

    ShowWindow(g_logoutButton, SW_SHOW);

    if (!g_hasLicense)
    {
        SetWindowTextW(g_statusLabel, L"Антивирусная функциональность заблокирована");
        SetWindowTextW(g_licenseLabel, L"Лицензия отсутствует. Введите код активации.");

        ShowWindow(g_activationLabel, SW_SHOW);
        ShowWindow(g_activationEdit, SW_SHOW);
        ShowWindow(g_activationButton, SW_SHOW);

        return;
    }

    SetWindowTextW(g_statusLabel, L"Антивирусная функциональность разблокирована");

    std::wstring licenseText =
        L"Лицензия активна до: " + UnixTimeToString(g_licenseExpiresAt);

    SetWindowTextW(g_licenseLabel, licenseText.c_str());
    
    RpcAvDatabaseInfo dbInfo{};

    if (RpcClientGetAvDatabaseInfo(&dbInfo) == RPC_OK)
    {
        std::wstring dbText =
            L"Антивирусные базы: дата выпуска " +
            dbInfo.releaseDate +
            L", записей: " +
            std::to_wstring(dbInfo.recordCount);

        SetWindowTextW(g_databaseLabel, dbText.c_str());
    }
    else
    {
        SetWindowTextW(g_databaseLabel, L"Ошибка получения информации об антивирусных базах");
    }

    ShowWindow(g_databaseLabel, SW_SHOW);
    ShowWindow(g_scanPathLabel, SW_SHOW);
    ShowWindow(g_scanPathEdit, SW_SHOW);
    ShowWindow(g_scanFileButton, SW_SHOW);
    ShowWindow(g_scanDirButton, SW_SHOW);
    ShowWindow(g_scanResultLabel, SW_SHOW);
}

void RefreshApplicationState()
{
    bool authenticated = false;
    std::wstring username;

    if (!RpcClientGetCurrentUser(&authenticated, &username))
    {
        g_isAuthenticated = false;
        g_hasLicense = false;
        g_currentUser.clear();

        SetWindowTextW(g_statusLabel, L"Ошибка соединения со службой");
        RenderUi();
        return;
    }

    g_isAuthenticated = authenticated;
    g_currentUser = username;

    if (!g_isAuthenticated)
    {
        g_hasLicense = false;
        g_licenseExpiresAt = 0;
        RenderUi();
        return;
    }

    bool hasLicense = false;
    long long expiresAt = 0;

    int licenseResult = RpcClientGetLicenseInfo(&hasLicense, &expiresAt);

    if (licenseResult == RPC_OK)
    {
        g_hasLicense = hasLicense;
        g_licenseExpiresAt = expiresAt;
    }
    else
    {
        g_hasLicense = false;
        g_licenseExpiresAt = 0;
    }

    RenderUi();
}

std::wstring GetWindowString(HWND hwnd)
{
    int length = GetWindowTextLengthW(hwnd);

    if (length <= 0)
        return L"";

    std::wstring text(length, L'\0');
    GetWindowTextW(hwnd, text.data(), length + 1);

    return text;
}

void HandleLogin(HWND hwnd)
{
    std::wstring login = GetWindowString(g_loginEdit);
    std::wstring password = GetWindowString(g_passwordEdit);

    if (login.empty() || password.empty())
    {
        MessageBoxW(hwnd, L"Введите логин и пароль", APP_NAME, MB_ICONWARNING);
        return;
    }

    int result = RpcClientLogin(login, password);

    if (result != RPC_OK)
    {
        MessageBoxW(hwnd, L"Ошибка аутентификации", APP_NAME, MB_ICONERROR);
        g_isAuthenticated = false;
        g_hasLicense = false;
        RenderUi();
        return;
    }

    SetWindowTextW(g_passwordEdit, L"");
    RefreshApplicationState();
}

void HandleActivation(HWND hwnd)
{
    std::wstring code = GetWindowString(g_activationEdit);

    if (code.empty())
    {
        MessageBoxW(hwnd, L"Введите код активации", APP_NAME, MB_ICONWARNING);
        return;
    }

    int result = RpcClientActivate(code);

    if (result != RPC_OK)
    {
        MessageBoxW(hwnd, L"Ошибка активации продукта", APP_NAME, MB_ICONERROR);
        g_hasLicense = false;
        RenderUi();
        return;
    }

    SetWindowTextW(g_activationEdit, L"");
    RefreshApplicationState();
}

void HandleLogout()
{
    RpcClientLogout();

    g_isAuthenticated = false;
    g_hasLicense = false;
    g_licenseExpiresAt = 0;
    g_currentUser.clear();

    RenderUi();
}

void ShowScanResult(const RpcAvScanResult& result)
{
    std::wstring text;

    if (result.isMalicious)
    {
        text =
            L"Результат: ОБНАРУЖЕНА УГРОЗА\r\n"
            L"Угроза: " + result.threatName +
            L"\r\nПросканировано файлов: " + std::to_wstring(result.scannedFiles) +
            L"\r\nНайдено угроз: " + std::to_wstring(result.detectedThreats);
    }
    else
    {
        text =
            L"Результат: угроз не обнаружено\r\n"
            L"Просканировано файлов: " + std::to_wstring(result.scannedFiles) +
            L"\r\nНайдено угроз: " + std::to_wstring(result.detectedThreats);
    }

    SetWindowTextW(g_scanResultLabel, text.c_str());
}

void HandleScanFile(HWND hwnd)
{
    std::wstring path = GetWindowString(g_scanPathEdit);

    if (path.empty())
    {
        MessageBoxW(hwnd, L"Введите путь к файлу", APP_NAME, MB_ICONWARNING);
        return;
    }

    RpcAvScanResult result{};
    int status = RpcClientScanFile(path, &result);

    if (status == RPC_ERROR_NO_LICENSE)
    {
        MessageBoxW(hwnd, L"Нет активной лицензии", APP_NAME, MB_ICONWARNING);
        RefreshApplicationState();
        return;
    }

    if (status != RPC_OK)
    {
        MessageBoxW(hwnd, L"Ошибка сканирования файла", APP_NAME, MB_ICONERROR);
        return;
    }

    ShowScanResult(result);
}

void HandleScanDirectory(HWND hwnd)
{
    std::wstring path = GetWindowString(g_scanPathEdit);

    if (path.empty())
    {
        MessageBoxW(hwnd, L"Введите путь к папке", APP_NAME, MB_ICONWARNING);
        return;
    }

    RpcAvScanResult result{};
    int status = RpcClientScanDirectory(path, &result);

    if (status == RPC_ERROR_NO_LICENSE)
    {
        MessageBoxW(hwnd, L"Нет активной лицензии", APP_NAME, MB_ICONWARNING);
        RefreshApplicationState();
        return;
    }

    if (status != RPC_OK)
    {
        MessageBoxW(hwnd, L"Ошибка сканирования папки", APP_NAME, MB_ICONERROR);
        return;
    }

    ShowScanResult(result);
}

void StopServiceAndExit(HWND hwnd)
{
    SendStopServiceRpc();

    RemoveTrayIcon(hwnd);
    DestroyWindow(hwnd);
    PostQuitMessage(0);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (msg == g_taskbarCreatedMsg)
    {
        g_trayIconAdded = false;
        AddTrayIcon(hwnd);
        return 0;
    }

    switch (msg)
    {
    case WM_CREATE:
        AddTrayIcon(hwnd);
        CreateUiControls(hwnd);
        RefreshApplicationState();
        SetTimer(hwnd, ID_TIMER_LICENSE, 10000, nullptr);
        return 0;

    case WM_TIMER:
        if (wParam == ID_TIMER_LICENSE)
        {
            RefreshApplicationState();
            return 0;
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case ID_TRAY_OPEN:
            ShowMainWindow(hwnd);
            return 0;

        case ID_TRAY_EXIT:
        case ID_FILE_EXIT:
            StopServiceAndExit(hwnd);
            return 0;

        case ID_BUTTON_LOGIN:
            HandleLogin(hwnd);
            return 0;

        case ID_BUTTON_SCAN_FILE:
            HandleScanFile(hwnd);
            return 0;

        case ID_BUTTON_SCAN_DIR:
            HandleScanDirectory(hwnd);
            return 0;
        
        case ID_BUTTON_ACTIVATE:
            HandleActivation(hwnd);
            return 0;

        case ID_BUTTON_LOGOUT:
            HandleLogout();
            return 0;
        }
        break;

    case WM_TRAYICON:
        switch (LOWORD(lParam))
        {
        case WM_LBUTTONUP:
            ShowMainWindow(hwnd);
            return 0;

        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu(hwnd);
            return 0;
        }
        break;

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        KillTimer(hwnd, ID_TIMER_LICENSE);
        RemoveTrayIcon(hwnd);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int)
{
    g_hInstance = hInstance;

    if (!IsServiceRunning())
    {
        StartServiceAndWait();
        return 0;
    }

    if (!IsParentService())
    {
        return 0;
    }

    if (!CreateSingleInstanceMutex())
    {
        return 0;
    }

    g_taskbarCreatedMsg = RegisterWindowMessageW(L"TaskbarCreated");

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.hInstance = hInstance;
    wc.lpfnWndProc = WindowProc;
    wc.lpszClassName = APP_CLASS_NAME;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);

    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(
        0,
        APP_CLASS_NAME,
        APP_NAME,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        700,
        540,
        nullptr,
        CreateMainMenu(),
        hInstance,
        nullptr
    );

    if (!g_hWnd)
        return 1;

    bool startHidden = HasArgument(L"--hidden") || HasArgument(L"/hidden");

    if (!startHidden)
    {
        ShowWindow(g_hWnd, SW_SHOW);
        UpdateWindow(g_hWnd);
    }

    MSG msg{};

    while (GetMessageW(&msg, nullptr, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    if (g_hMutex)
    {
        ReleaseMutex(g_hMutex);
        CloseHandle(g_hMutex);
        g_hMutex = nullptr;
    }

    return static_cast<int>(msg.wParam);
}