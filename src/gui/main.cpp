#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <strsafe.h>

#include "../common/service_names.h"
#include "../rpc/rpc_client.h"

#define WM_TRAYICON (WM_APP + 1)

#define ID_TRAY_OPEN 1001
#define ID_TRAY_EXIT 1002
#define ID_FILE_EXIT 2001

static const wchar_t* APP_CLASS_NAME = L"AntivirusMTUCIMainWindowClass";
static const wchar_t* MUTEX_NAME = L"Local\\AntivirusMTUCISingleInstanceMutex";

HINSTANCE g_hInstance = nullptr;
HWND g_hWnd = nullptr;
HANDLE g_hMutex = nullptr;
UINT g_taskbarCreatedMsg = 0;
bool g_trayIconAdded = false;

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
    if (!scm) return false;

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
    if (!scm) return false;

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
    if (!argv) return false;

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

        CreateWindowW(
            L"STATIC",
            L"Antivirus MTUCI работает в фоновом режиме",
            WS_VISIBLE | WS_CHILD,
            20,
            20,
            360,
            30,
            hwnd,
            nullptr,
            g_hInstance,
            nullptr
        );

        return 0;

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
        600,
        400,
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
    }

    return static_cast<int>(msg.wParam);
}