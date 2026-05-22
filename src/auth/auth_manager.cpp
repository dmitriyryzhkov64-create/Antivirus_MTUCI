#include "auth_manager.h"

#include <ctime>

#include "../common/rpc_status.h"

static CRITICAL_SECTION g_authLock;
static HANDLE g_refreshThread = nullptr;
static HANDLE g_stopRefreshEvent = nullptr;
static AuthState g_state;

static DWORD WINAPI RefreshWorker(LPVOID)
{
    while (WaitForSingleObject(g_stopRefreshEvent, 30000) == WAIT_TIMEOUT)
    {
        EnterCriticalSection(&g_authLock);

        if (g_state.isAuthenticated)
        {
            g_state.accessExpiresAt = std::time(nullptr) + 3600;
            g_state.refreshExpiresAt = std::time(nullptr) + 7200;
        }

        if (g_state.hasLicense)
        {
            // Mock-обновление license ticket.
            // В реальном режиме здесь должен быть HTTPS-запрос статуса лицензии.
            g_state.licenseExpiresAt = std::time(nullptr) + 30 * 24 * 60 * 60;
        }

        LeaveCriticalSection(&g_authLock);
    }

    return 0;
}

void AuthInitialize()
{
    InitializeCriticalSection(&g_authLock);

    g_stopRefreshEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    g_refreshThread = CreateThread(
        nullptr,
        0,
        RefreshWorker,
        nullptr,
        0,
        nullptr
    );
}

void AuthShutdown()
{
    if (g_stopRefreshEvent)
    {
        SetEvent(g_stopRefreshEvent);
    }

    if (g_refreshThread)
    {
        WaitForSingleObject(g_refreshThread, 3000);
        CloseHandle(g_refreshThread);
        g_refreshThread = nullptr;
    }

    if (g_stopRefreshEvent)
    {
        CloseHandle(g_stopRefreshEvent);
        g_stopRefreshEvent = nullptr;
    }

    DeleteCriticalSection(&g_authLock);
}

int AuthGetCurrentUser(bool* isAuthenticated, std::wstring* username)
{
    if (!isAuthenticated || !username)
    {
        return RPC_ERROR_INTERNAL;
    }

    EnterCriticalSection(&g_authLock);

    *isAuthenticated = g_state.isAuthenticated;
    *username = g_state.username;

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

int AuthLogin(const std::wstring& login, const std::wstring& password)
{
    // Mock для демонстрации без реального backend API.
    if (login != L"admin" || password != L"12345")
    {
        return RPC_ERROR_INVALID_CREDENTIALS;
    }

    EnterCriticalSection(&g_authLock);

    g_state.isAuthenticated = true;
    g_state.username = login;

    g_state.accessToken = L"mock_access_token";
    g_state.refreshToken = L"mock_refresh_token";

    g_state.accessExpiresAt = std::time(nullptr) + 3600;
    g_state.refreshExpiresAt = std::time(nullptr) + 7200;

    g_state.hasLicense = false;
    g_state.licenseTicket.clear();
    g_state.licenseExpiresAt = 0;

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

int AuthLogout()
{
    EnterCriticalSection(&g_authLock);

    g_state = AuthState{};

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

int AuthGetLicenseInfo(bool* hasLicense, long long* expiresAtUnix)
{
    if (!hasLicense || !expiresAtUnix)
    {
        return RPC_ERROR_INTERNAL;
    }

    EnterCriticalSection(&g_authLock);

    if (!g_state.isAuthenticated)
    {
        LeaveCriticalSection(&g_authLock);
        return RPC_ERROR_NOT_AUTHENTICATED;
    }

    *hasLicense = g_state.hasLicense;
    *expiresAtUnix = g_state.licenseExpiresAt;

    LeaveCriticalSection(&g_authLock);

    return *hasLicense ? RPC_OK : RPC_ERROR_NO_LICENSE;
}

int AuthActivateProduct(const std::wstring& activationCode)
{
    if (activationCode != L"MTUCI-2025")
    {
        return RPC_ERROR_ACTIVATION_FAILED;
    }

    EnterCriticalSection(&g_authLock);

    if (!g_state.isAuthenticated)
    {
        LeaveCriticalSection(&g_authLock);
        return RPC_ERROR_NOT_AUTHENTICATED;
    }

    g_state.hasLicense = true;
    g_state.licenseTicket = L"mock_license_ticket";
    g_state.licenseExpiresAt = std::time(nullptr) + 30 * 24 * 60 * 60;

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

bool AuthHasLicense()
{
    EnterCriticalSection(&g_authLock);

    bool result = g_state.hasLicense;

    LeaveCriticalSection(&g_authLock);

    return result;
}