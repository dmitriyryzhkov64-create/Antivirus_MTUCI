#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include "../av/av_database.h"
#include "../av/av_engine.h"

#include <vector>
#include <string>
#include <cstdlib>

#include "../common/service_names.h"
#include "../common/rpc_status.h"
#include "../auth/auth_manager.h"

#include "AntivirusRpc.h"

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Advapi32.lib")

SERVICE_STATUS g_serviceStatus{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;

HANDLE g_stopEvent = nullptr;
HANDLE g_rpcThread = nullptr;

CRITICAL_SECTION g_processLock;
std::vector<PROCESS_INFORMATION> g_guiProcesses;

AvDatabase g_avDatabase;

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* ptr)
{
    free(ptr);
}

void SetServiceStatusValue(DWORD state)
{
    g_serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_serviceStatus.dwCurrentState = state;

    // По заданию Stop и Shutdown отключены.
    // Принимаем только события смены сессий.
    g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;

    g_serviceStatus.dwWin32ExitCode = NO_ERROR;
    g_serviceStatus.dwServiceSpecificExitCode = 0;
    g_serviceStatus.dwCheckPoint = 0;
    g_serviceStatus.dwWaitHint = 0;

    if (g_statusHandle)
    {
        SetServiceStatus(g_statusHandle, &g_serviceStatus);
    }
}

std::wstring GetModuleDirectory()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\/");

    if (pos == std::wstring::npos)
    {
        return L".";
    }

    return fullPath.substr(0, pos);
}

bool IsGuiAlreadyStartedInSession(DWORD sessionId)
{
    EnterCriticalSection(&g_processLock);

    for (const auto& pi : g_guiProcesses)
    {
        DWORD processSessionId = 0;

        if (ProcessIdToSessionId(pi.dwProcessId, &processSessionId))
        {
            if (processSessionId == sessionId)
            {
                LeaveCriticalSection(&g_processLock);
                return true;
            }
        }
    }

    LeaveCriticalSection(&g_processLock);
    return false;
}

void CleanupFinishedGuiProcesses()
{
    EnterCriticalSection(&g_processLock);

    for (auto it = g_guiProcesses.begin(); it != g_guiProcesses.end();)
    {
        DWORD waitResult = WaitForSingleObject(it->hProcess, 0);

        if (waitResult == WAIT_OBJECT_0)
        {
            CloseHandle(it->hProcess);
            CloseHandle(it->hThread);
            it = g_guiProcesses.erase(it);
        }
        else
        {
            ++it;
        }
    }

    LeaveCriticalSection(&g_processLock);
}

void LaunchGuiInSession(DWORD sessionId)
{
    if (sessionId == 0)
    {
        return;
    }

    CleanupFinishedGuiProcesses();

    if (IsGuiAlreadyStartedInSession(sessionId))
    {
        return;
    }

    HANDLE userToken = nullptr;

    if (!WTSQueryUserToken(sessionId, &userToken))
    {
        return;
    }

    HANDLE primaryToken = nullptr;

    if (!DuplicateTokenEx(
            userToken,
            TOKEN_ALL_ACCESS,
            nullptr,
            SecurityIdentification,
            TokenPrimary,
            &primaryToken))
    {
        CloseHandle(userToken);
        return;
    }

    void* environment = nullptr;
    CreateEnvironmentBlock(&environment, primaryToken, FALSE);

    std::wstring moduleDir = GetModuleDirectory();
    std::wstring exePath = moduleDir + L"\\" GUI_EXE_NAME;
    std::wstring commandLine = L"\"" + exePath + L"\" --hidden";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PROCESS_INFORMATION pi{};

    BOOL created = CreateProcessAsUserW(
        primaryToken,
        exePath.c_str(),
        commandLine.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        moduleDir.c_str(),
        &si,
        &pi
    );

    if (environment)
    {
        DestroyEnvironmentBlock(environment);
    }

    CloseHandle(primaryToken);
    CloseHandle(userToken);

    if (created)
    {
        EnterCriticalSection(&g_processLock);
        g_guiProcesses.push_back(pi);
        LeaveCriticalSection(&g_processLock);
    }
}

void LaunchGuiForAllSessions()
{
    PWTS_SESSION_INFOW sessions = nullptr;
    DWORD count = 0;

    if (!WTSEnumerateSessionsW(
            WTS_CURRENT_SERVER_HANDLE,
            0,
            1,
            &sessions,
            &count))
    {
        return;
    }

    for (DWORD i = 0; i < count; ++i)
    {
        if (sessions[i].SessionId != 0 &&
            sessions[i].State == WTSActive)
        {
            LaunchGuiInSession(sessions[i].SessionId);
        }
    }

    WTSFreeMemory(sessions);
}

void TerminateAllGuiProcesses()
{
    EnterCriticalSection(&g_processLock);

    for (auto& pi : g_guiProcesses)
    {
        TerminateProcess(pi.hProcess, 0);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    g_guiProcesses.clear();

    LeaveCriticalSection(&g_processLock);
}

DWORD WINAPI RpcServerThread(LPVOID)
{
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(RPC_ENDPOINT)),
        nullptr
    );

    if (status != RPC_S_OK)
    {
        SetEvent(g_stopEvent);
        return 1;
    }

    status = RpcServerRegisterIf(
        AntivirusRpc_v1_0_s_ifspec,
        nullptr,
        nullptr
    );

    if (status != RPC_S_OK)
    {
        SetEvent(g_stopEvent);
        return 1;
    }

    status = RpcServerListen(
        1,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        FALSE
    );

    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING)
    {
        SetEvent(g_stopEvent);
        return 1;
    }

    return 0;
}

extern "C" void RpcStopService(handle_t)
{
    SetEvent(g_stopEvent);
}

extern "C" int RpcGetCurrentUser(
    handle_t,
    int* isAuthenticated,
    wchar_t** username)
{
    if (!isAuthenticated || !username)
    {
        return RPC_ERROR_INTERNAL;
    }

    bool auth = false;
    std::wstring user;

    int result = AuthGetCurrentUser(&auth, &user);

    *isAuthenticated = auth ? 1 : 0;

    size_t size = user.size() + 1;
    *username = static_cast<wchar_t*>(
        midl_user_allocate(size * sizeof(wchar_t))
    );

    if (!*username)
    {
        return RPC_ERROR_INTERNAL;
    }

    wcscpy_s(*username, size, user.c_str());

    return result;
}

extern "C" int RpcLogin(
    handle_t,
    const wchar_t* login,
    const wchar_t* password)
{
    if (!login || !password)
    {
        return RPC_ERROR_INVALID_CREDENTIALS;
    }

    return AuthLogin(login, password);
}

extern "C" int RpcLogout(handle_t)
{
    return AuthLogout();
}

extern "C" int RpcGetLicenseInfo(
    handle_t,
    int* hasLicense,
    hyper* expiresAtUnix)
{
    if (!hasLicense || !expiresAtUnix)
    {
        return RPC_ERROR_INTERNAL;
    }

    bool has = false;
    long long expires = 0;

    int result = AuthGetLicenseInfo(&has, &expires);

    *hasLicense = has ? 1 : 0;
    *expiresAtUnix = static_cast<hyper>(expires);

    return result;
}

extern "C" int RpcActivateProduct(
    handle_t,
    const wchar_t* activationCode)
{
    if (!activationCode)
    {
        return RPC_ERROR_ACTIVATION_FAILED;
    }

    return AuthActivateProduct(activationCode);
}

static wchar_t* RpcAllocString(const std::wstring& value)
{
    size_t size = value.size() + 1;

    wchar_t* result = static_cast<wchar_t*>(
        midl_user_allocate(size * sizeof(wchar_t))
    );

    if (!result)
    {
        return nullptr;
    }

    wcscpy_s(result, size, value.c_str());
    return result;
}

extern "C" int RpcGetAvDatabaseInfo(
    handle_t,
    int* isLoaded,
    hyper* recordCount,
    wchar_t** releaseDate)
{
    if (!isLoaded || !recordCount || !releaseDate)
    {
        return RPC_ERROR_INTERNAL;
    }

    *isLoaded = g_avDatabase.IsLoaded() ? 1 : 0;
    *recordCount = static_cast<hyper>(g_avDatabase.GetRecordCount());
    *releaseDate = RpcAllocString(g_avDatabase.GetReleaseDate());

    if (!*releaseDate)
    {
        return RPC_ERROR_INTERNAL;
    }

    return RPC_OK;
}

extern "C" int RpcScanFile(
    handle_t,
    const wchar_t* filePath,
    int* isMalicious,
    hyper* scannedFiles,
    hyper* detectedThreats,
    wchar_t** threatName)
{
    if (!filePath || !isMalicious || !scannedFiles || !detectedThreats || !threatName)
    {
        return RPC_ERROR_INTERNAL;
    }

    if (!AuthHasLicense())
    {
        return RPC_ERROR_NO_LICENSE;
    }

    if (!g_avDatabase.IsLoaded())
    {
        return RPC_ERROR_DATABASE_NOT_LOADED;
    }

    AvEngine engine(&g_avDatabase);
    AvScanResult result = engine.ScanFile(filePath);

    *isMalicious = result.isMalicious ? 1 : 0;
    *scannedFiles = static_cast<hyper>(result.scannedFiles);
    *detectedThreats = static_cast<hyper>(result.detectedThreats);
    *threatName = RpcAllocString(result.threatName);

    if (!*threatName)
    {
        return RPC_ERROR_INTERNAL;
    }

    return RPC_OK;
}

extern "C" int RpcScanDirectory(
    handle_t,
    const wchar_t* directoryPath,
    int* isMalicious,
    hyper* scannedFiles,
    hyper* detectedThreats,
    wchar_t** threatName)
{
    if (!directoryPath || !isMalicious || !scannedFiles || !detectedThreats || !threatName)
    {
        return RPC_ERROR_INTERNAL;
    }

    if (!AuthHasLicense())
    {
        return RPC_ERROR_NO_LICENSE;
    }

    if (!g_avDatabase.IsLoaded())
    {
        return RPC_ERROR_DATABASE_NOT_LOADED;
    }

    AvEngine engine(&g_avDatabase);
    AvScanResult result = engine.ScanDirectory(directoryPath);

    *isMalicious = result.isMalicious ? 1 : 0;
    *scannedFiles = static_cast<hyper>(result.scannedFiles);
    *detectedThreats = static_cast<hyper>(result.detectedThreats);
    *threatName = RpcAllocString(result.threatName);

    if (!*threatName)
    {
        return RPC_ERROR_INTERNAL;
    }

    return RPC_OK;
}

DWORD WINAPI ServiceControlHandler(
    DWORD control,
    DWORD eventType,
    LPVOID eventData,
    LPVOID)
{
    switch (control)
    {
    case SERVICE_CONTROL_SESSIONCHANGE:
    {
        if (eventType == WTS_SESSION_LOGON ||
            eventType == WTS_SESSION_UNLOCK)
        {
            auto* notification =
                static_cast<WTSSESSION_NOTIFICATION*>(eventData);

            if (notification)
            {
                LaunchGuiInSession(notification->dwSessionId);
            }
        }

        return NO_ERROR;
    }

    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // По заданию эти сигналы не обрабатываются.
        return ERROR_CALL_NOT_IMPLEMENTED;

    default:
        return NO_ERROR;
    }
}

void WINAPI ServiceMain(DWORD, LPWSTR*)
{
    g_statusHandle = RegisterServiceCtrlHandlerExW(
        SERVICE_NAME,
        ServiceControlHandler,
        nullptr
    );

    if (!g_statusHandle)
    {
        return;
    }

    SetServiceStatusValue(SERVICE_START_PENDING);

    InitializeCriticalSection(&g_processLock);

    g_stopEvent = CreateEventW(
        nullptr,
        TRUE,
        FALSE,
        nullptr
    );

    if (!g_stopEvent)
    {
        DeleteCriticalSection(&g_processLock);
        SetServiceStatusValue(SERVICE_STOPPED);
        return;
    }

    AuthInitialize();
    g_avDatabase.LoadMockDatabase();

    g_rpcThread = CreateThread(
        nullptr,
        0,
        RpcServerThread,
        nullptr,
        0,
        nullptr
    );

    if (!g_rpcThread)
    {
        AuthShutdown();
        CloseHandle(g_stopEvent);
        DeleteCriticalSection(&g_processLock);
        SetServiceStatusValue(SERVICE_STOPPED);
        return;
    }

    LaunchGuiForAllSessions();

    SetServiceStatusValue(SERVICE_RUNNING);

    WaitForSingleObject(g_stopEvent, INFINITE);

    SetServiceStatusValue(SERVICE_STOP_PENDING);

    TerminateAllGuiProcesses();

    AuthShutdown();

    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(nullptr, nullptr, FALSE);

    if (g_rpcThread)
    {
        WaitForSingleObject(g_rpcThread, 3000);
        CloseHandle(g_rpcThread);
        g_rpcThread = nullptr;
    }

    if (g_stopEvent)
    {
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
    }

    DeleteCriticalSection(&g_processLock);

    SetServiceStatusValue(SERVICE_STOPPED);
}

int wmain()
{
    SERVICE_TABLE_ENTRYW serviceTable[] =
    {
        {
            const_cast<LPWSTR>(SERVICE_NAME),
            ServiceMain
        },
        {
            nullptr,
            nullptr
        }
    };

    StartServiceCtrlDispatcherW(serviceTable);

    return 0;
}