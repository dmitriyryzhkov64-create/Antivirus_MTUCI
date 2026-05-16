#pragma once
#include <string>
#include <ctime>

struct AuthState
{
    bool isAuthenticated = false;
    bool hasLicense = false;

    std::wstring username;

    // Только в памяти службы. Клиентам не отдаём.
    std::wstring accessToken;
    std::wstring refreshToken;
    std::wstring licenseTicket;

    std::time_t accessExpiresAt = 0;
    std::time_t refreshExpiresAt = 0;
    std::time_t licenseExpiresAt = 0;
};