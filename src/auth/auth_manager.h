#pragma once
#include <windows.h>
#include <string>

#include "../common/rpc_status.h"

void AuthInitialize();
void AuthShutdown();

int AuthGetCurrentUser(bool* isAuthenticated, std::wstring* username);

//int AuthLogin(const std::wstring& login, const std::wstring& password);
int AuthLogin(const std::wstring& login, const std::wstring& password)
{
    if (login != L"admin" || password != L"12345")
    {
        return RPC_ERROR_INVALID_CREDENTIALS;
    }

    EnterCriticalSection(&g_authLock);

    g_state.isAuthenticated = true;
    g_state.username = login;

    g_state.accessToken = L"mock_access";
    g_state.refreshToken = L"mock_refresh";

    g_state.accessExpiresAt = std::time(nullptr) + 3600;
    g_state.refreshExpiresAt = std::time(nullptr) + 7200;

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}
int AuthLogout();

int AuthGetLicenseInfo(bool* hasLicense, long long* expiresAtUnix);

//int AuthActivateProduct(const std::wstring& activationCode);
int AuthActivateProduct(const std::wstring& activationCode)
{
    if (activationCode != L"MTUCI-2025")
    {
        return RPC_ERROR_ACTIVATION_FAILED;
    }

    EnterCriticalSection(&g_authLock);

    g_state.hasLicense = true;
    g_state.licenseTicket = L"mock_ticket";

    g_state.licenseExpiresAt =
        std::time(nullptr) + 30 * 24 * 60 * 60;

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

bool AuthHasLicense();