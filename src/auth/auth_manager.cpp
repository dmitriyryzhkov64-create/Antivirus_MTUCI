#include "auth_manager.h"
#include "../common/api_config.h"
#include "../http/http_client.h"
#include <ctime>

// Определяем глобальные переменные здесь
CRITICAL_SECTION g_authLock;
AuthState g_state;
static HANDLE g_refreshThread = nullptr;
static HANDLE g_stopRefreshEvent = nullptr;

// Вспомогательные функции для mock/demo
static std::wstring EscapeJson(const std::wstring& value)
{
    std::wstring result;
    for (wchar_t ch : value)
    {
        if (ch == L'"') result += L"\\\"";
        else if (ch == L'\\') result += L"\\\\";
        else result += ch;
    }
    return result;
}

// Инициализация
void AuthInitialize()
{
    InitializeCriticalSection(&g_authLock);
    g_stopRefreshEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    // Поток для обновления токенов/лицензий пока можно пропустить для mock
}

// Завершение работы
void AuthShutdown()
{
    if (g_stopRefreshEvent)
        SetEvent(g_stopRefreshEvent);
    if (g_refreshThread)
    {
        WaitForSingleObject(g_refreshThread, 3000);
        CloseHandle(g_refreshThread);
    }
    if (g_stopRefreshEvent)
        CloseHandle(g_stopRefreshEvent);
    DeleteCriticalSection(&g_authLock);
}

// Получение текущего пользователя
int AuthGetCurrentUser(bool* isAuthenticated, std::wstring* username)
{
    EnterCriticalSection(&g_authLock);
    *isAuthenticated = g_state.isAuthenticated;
    *username = g_state.username;
    LeaveCriticalSection(&g_authLock);
    return RPC_OK;
}

// Логин (mock)
int AuthLogin(const std::wstring& login, const std::wstring& password)
{
    if (login != L"admin" || password != L"12345")
        return RPC_ERROR_INVALID_CREDENTIALS;

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

// Выход
int AuthLogout()
{
    EnterCriticalSection(&g_authLock);
    g_state = AuthState{};
    LeaveCriticalSection(&g_authLock);
    return RPC_OK;
}

// Активация продукта (mock)
int AuthActivateProduct(const std::wstring& activationCode)
{
    if (activationCode != L"MTUCI-2025")
        return RPC_ERROR_ACTIVATION_FAILED;

    EnterCriticalSection(&g_authLock);
    g_state.hasLicense = true;
    g_state.licenseTicket = L"mock_ticket";
    g_state.licenseExpiresAt = std::time(nullptr) + 30 * 24 * 60 * 60; // 30 дней
    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

// Получение статуса лицензии
int AuthGetLicenseInfo(bool* hasLicense, long long* expiresAtUnix)
{
    EnterCriticalSection(&g_authLock);
    *hasLicense = g_state.hasLicense;
    *expiresAtUnix = g_state.licenseExpiresAt;
    LeaveCriticalSection(&g_authLock);
    return *hasLicense ? RPC_OK : RPC_ERROR_NO_LICENSE;
}

// Проверка лицензии
bool AuthHasLicense()
{
    EnterCriticalSection(&g_authLock);
    bool result = g_state.hasLicense;
    LeaveCriticalSection(&g_authLock);
    return result;
}