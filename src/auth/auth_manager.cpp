#include <windows.h>
#include <string>
#include <ctime>

#include "auth_manager.h"
#include "../common/api_config.h"
#include "../common/rpc_status.h"
#include "../http/http_client.h"

static CRITICAL_SECTION g_authLock;
static HANDLE g_refreshThread = nullptr;
static HANDLE g_stopRefreshEvent = nullptr;
static AuthState g_state;

static std::wstring EscapeJson(const std::wstring& value)
{
    std::wstring result;

    for (wchar_t ch : value)
    {
        if (ch == L'"')
            result += L"\\\"";
        else if (ch == L'\\')
            result += L"\\\\";
        else
            result += ch;
    }

    return result;
}

static std::wstring ExtractJsonString(const std::wstring& body, const std::wstring& key)
{
    std::wstring pattern = L"\"" + key + L"\"";
    size_t keyPos = body.find(pattern);
    if (keyPos == std::wstring::npos)
        return L"";

    size_t colon = body.find(L":", keyPos);
    if (colon == std::wstring::npos)
        return L"";

    size_t firstQuote = body.find(L"\"", colon + 1);
    if (firstQuote == std::wstring::npos)
        return L"";

    size_t secondQuote = body.find(L"\"", firstQuote + 1);
    if (secondQuote == std::wstring::npos)
        return L"";

    return body.substr(firstQuote + 1, secondQuote - firstQuote - 1);
}

static long long ExtractJsonNumber(const std::wstring& body, const std::wstring& key)
{
    std::wstring pattern = L"\"" + key + L"\"";
    size_t keyPos = body.find(pattern);
    if (keyPos == std::wstring::npos)
        return 0;

    size_t colon = body.find(L":", keyPos);
    if (colon == std::wstring::npos)
        return 0;

    size_t start = body.find_first_of(L"0123456789", colon + 1);
    if (start == std::wstring::npos)
        return 0;

    size_t end = body.find_first_not_of(L"0123456789", start);
    std::wstring number = body.substr(start, end - start);

    return _wtoi64(number.c_str());
}

static bool ParseLoginResponse(const std::wstring& body, AuthState* state)
{
    // Ожидаемый учебный формат:
    // {
    //   "username": "user",
    //   "accessToken": "...",
    //   "refreshToken": "...",
    //   "accessExpiresAt": 1730000000,
    //   "refreshExpiresAt": 1730000000
    // }

    std::wstring username = ExtractJsonString(body, L"username");
    std::wstring access = ExtractJsonString(body, L"accessToken");
    std::wstring refresh = ExtractJsonString(body, L"refreshToken");

    long long accessExp = ExtractJsonNumber(body, L"accessExpiresAt");
    long long refreshExp = ExtractJsonNumber(body, L"refreshExpiresAt");

    if (username.empty() || access.empty() || refresh.empty())
        return false;

    std::time_t now = std::time(nullptr);

    state->isAuthenticated = true;
    state->username = username;
    state->accessToken = access;
    state->refreshToken = refresh;
    state->accessExpiresAt = accessExp > 0 ? static_cast<std::time_t>(accessExp) : now + 15 * 60;
    state->refreshExpiresAt = refreshExp > 0 ? static_cast<std::time_t>(refreshExp) : now + 24 * 60 * 60;

    return true;
}

static bool ParseLicenseResponse(const std::wstring& body, AuthState* state)
{
    // Ожидаемый учебный формат:
    // {
    //   "licenseTicket": "...",
    //   "expiresAt": 1730000000
    // }

    std::wstring ticket = ExtractJsonString(body, L"licenseTicket");
    long long expiresAt = ExtractJsonNumber(body, L"expiresAt");

    if (ticket.empty())
        return false;

    state->hasLicense = true;
    state->licenseTicket = ticket;
    state->licenseExpiresAt = expiresAt > 0
        ? static_cast<std::time_t>(expiresAt)
        : std::time(nullptr) + 60 * 60;

    return true;
}

static int RefreshTokens()
{
    std::wstring refreshToken;

    EnterCriticalSection(&g_authLock);
    refreshToken = g_state.refreshToken;
    LeaveCriticalSection(&g_authLock);

    if (refreshToken.empty())
        return RPC_ERROR_NOT_AUTHENTICATED;

    std::wstring body = L"{\"refreshToken\":\"" + EscapeJson(refreshToken) + L"\"}";

    HttpResponse response = HttpsPostJson(
        API_HOST,
        API_PORT,
        API_REFRESH_PATH,
        body
    );

    if (!response.ok)
        return RPC_ERROR_NETWORK;

    EnterCriticalSection(&g_authLock);
    bool parsed = ParseLoginResponse(response.body, &g_state);
    LeaveCriticalSection(&g_authLock);

    return parsed ? RPC_OK : RPC_ERROR_INTERNAL;
}

static int RefreshLicense()
{
    std::wstring accessToken;

    EnterCriticalSection(&g_authLock);
    accessToken = g_state.accessToken;
    LeaveCriticalSection(&g_authLock);

    if (accessToken.empty())
        return RPC_ERROR_NOT_AUTHENTICATED;

    HttpResponse response = HttpsGetJson(
        API_HOST,
        API_PORT,
        API_LICENSE_STATUS_PATH,
        accessToken
    );

    if (!response.ok)
        return RPC_ERROR_NETWORK;

    EnterCriticalSection(&g_authLock);
    bool parsed = ParseLicenseResponse(response.body, &g_state);
    LeaveCriticalSection(&g_authLock);

    return parsed ? RPC_OK : RPC_ERROR_NO_LICENSE;
}

static DWORD CalculateDelayMs()
{
    EnterCriticalSection(&g_authLock);

    std::time_t now = std::time(nullptr);

    std::time_t next = 0;

    if (g_state.isAuthenticated)
    {
        next = g_state.accessExpiresAt - 60;
    }

    if (g_state.hasLicense)
    {
        std::time_t licenseRefresh = g_state.licenseExpiresAt - 300;
        if (next == 0 || licenseRefresh < next)
            next = licenseRefresh;
    }

    LeaveCriticalSection(&g_authLock);

    if (next <= now)
        return 30 * 1000;

    DWORD seconds = static_cast<DWORD>(next - now);
    return seconds * 1000;
}

static DWORD WINAPI RefreshWorker(LPVOID)
{
    while (WaitForSingleObject(g_stopRefreshEvent, CalculateDelayMs()) == WAIT_TIMEOUT)
    {
        EnterCriticalSection(&g_authLock);
        bool isAuth = g_state.isAuthenticated;
        bool hasLicense = g_state.hasLicense;
        LeaveCriticalSection(&g_authLock);

        if (isAuth)
            RefreshTokens();

        if (isAuth && hasLicense)
            RefreshLicense();
    }

    return 0;
}

void AuthInitialize()
{
    InitializeCriticalSection(&g_authLock);
    g_stopRefreshEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_refreshThread = CreateThread(nullptr, 0, RefreshWorker, nullptr, 0, nullptr);
}

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

int AuthGetCurrentUser(bool* isAuthenticated, std::wstring* username)
{
    EnterCriticalSection(&g_authLock);

    *isAuthenticated = g_state.isAuthenticated;
    *username = g_state.username;

    LeaveCriticalSection(&g_authLock);

    return RPC_OK;
}

int AuthLogin(const std::wstring& login, const std::wstring& password)
{
    std::wstring body =
        L"{\"login\":\"" + EscapeJson(login) +
        L"\",\"password\":\"" + EscapeJson(password) + L"\"}";

    HttpResponse response = HttpsPostJson(
        API_HOST,
        API_PORT,
        API_LOGIN_PATH,
        body
    );

    if (response.statusCode == 401 || response.statusCode == 403)
        return RPC_ERROR_INVALID_CREDENTIALS;

    if (!response.ok)
        return RPC_ERROR_NETWORK;

    EnterCriticalSection(&g_authLock);
    bool parsed = ParseLoginResponse(response.body, &g_state);
    LeaveCriticalSection(&g_authLock);

    if (!parsed)
        return RPC_ERROR_INTERNAL;

    RefreshLicense();

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
    EnterCriticalSection(&g_authLock);

    if (!g_state.isAuthenticated)
    {
        LeaveCriticalSection(&g_authLock);
        return RPC_ERROR_NOT_AUTHENTICATED;
    }

    *hasLicense = g_state.hasLicense;
    *expiresAtUnix = static_cast<long long>(g_state.licenseExpiresAt);

    LeaveCriticalSection(&g_authLock);

    if (!*hasLicense)
        return RPC_ERROR_NO_LICENSE;

    return RPC_OK;
}

int AuthActivateProduct(const std::wstring& activationCode)
{
    std::wstring accessToken;

    EnterCriticalSection(&g_authLock);
    accessToken = g_state.accessToken;
    LeaveCriticalSection(&g_authLock);

    if (accessToken.empty())
        return RPC_ERROR_NOT_AUTHENTICATED;

    std::wstring body =
        L"{\"activationCode\":\"" + EscapeJson(activationCode) + L"\"}";

    HttpResponse response = HttpsPostJson(
        API_HOST,
        API_PORT,
        API_ACTIVATE_PATH,
        body,
        accessToken
    );

    if (!response.ok)
        return RPC_ERROR_ACTIVATION_FAILED;

    EnterCriticalSection(&g_authLock);
    bool parsed = ParseLicenseResponse(response.body, &g_state);
    LeaveCriticalSection(&g_authLock);

    if (parsed)
        return RPC_OK;

    // Если endpoint активации не вернул ticket — запрашиваем статус.
    return RefreshLicense();
}

bool AuthHasLicense()
{
    EnterCriticalSection(&g_authLock);
    bool result = g_state.hasLicense;
    LeaveCriticalSection(&g_authLock);

    return result;
}