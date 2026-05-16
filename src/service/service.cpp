#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <rpc.h>
#include <vector>
#include <string>
#include <cstdlib>

#include "../common/service_names.h"
#include "AntivirusRpc_h.h"

#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Userenv.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Advapi32.lib")

SERVICE_STATUS g_serviceStatus{};
SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
HANDLE g_stopEvent = nullptr;

CRITICAL_SECTION g_processLock;
std::vector<PROCESS_INFORMATION> g_guiProcesses;

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

    // Stop и Shutdown намеренно не принимаются.
    g_serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_SESSIONCHANGE;

    g_serviceStatus.dwWin32ExitCode = NO_ERROR;
    g_serviceStatus.dwCheckPoint = 0;
    g_serviceStatus.dwWaitHint = 0;

    SetServiceStatus(g_statusHandle, &g_serviceStatus);
}

std::wstring GetModuleDirectory()
{
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    std::wstring fullPath(path);
    size_t pos = fullPath.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : fullPath.substr(0, pos);
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

void LaunchGuiInSession(DWORD sessionId)
{
    if (sessionId == 0)
        return;

    if (IsGuiAlreadyStartedInSession(sessionId))
        return;

    HANDLE userToken = nullptr;
    if (!WTSQueryUserToken(sessionId, &userToken))
        return;

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

    std::wstring exePath = GetModuleDirectory() + L"\\" GUI_EXE_NAME;
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
        GetModuleDirectory().c_str(),
        &si,
        &pi
    );

    if (environment)
        DestroyEnvironmentBlock(environment);

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

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count))
        return;

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

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);

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

DWORD WINAPI ServiceControlHandler(
    DWORD control,
    DWORD eventType,
    LPVOID eventData,
    LPVOID)
{
    switch (control)
    {
    case SERVICE_CONTROL_SESSIONCHANGE:
        if (eventType == WTS_SESSION_LOGON ||
            eventType == WTS_SESSION_UNLOCK)
        {
            auto* notification = static_cast<WTSSESSION_NOTIFICATION*>(eventData);
            if (notification)
                LaunchGuiInSession(notification->dwSessionId);
        }
        return NO_ERROR;

    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // Stop и Shutdown отключены.
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
        return;

    InitializeCriticalSection(&g_processLock);

    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    SetServiceStatusValue(SERVICE_START_PENDING);

    HANDLE rpcThread = CreateThread(nullptr, 0, RpcServerThread, nullptr, 0, nullptr);

    LaunchGuiForAllSessions();

    SetServiceStatusValue(SERVICE_RUNNING);

    WaitForSingleObject(g_stopEvent, INFINITE);

    SetServiceStatusValue(SERVICE_STOP_PENDING);

    TerminateAllGuiProcesses();

    RpcMgmtStopServerListening(nullptr);
    RpcServerUnregisterIf(nullptr, nullptr, FALSE);

    if (rpcThread)
    {
        WaitForSingleObject(rpcThread, 3000);
        CloseHandle(rpcThread);
    }

    if (g_stopEvent)
        CloseHandle(g_stopEvent);

    DeleteCriticalSection(&g_processLock);

    SetServiceStatusValue(SERVICE_STOPPED);
}

int wmain()
{
    SERVICE_TABLE_ENTRYW serviceTable[] =
    {
        { const_cast<LPWSTR>(SERVICE_NAME), ServiceMain },
        { nullptr, nullptr }
    };

    StartServiceCtrlDispatcherW(serviceTable);
    return 0;
}