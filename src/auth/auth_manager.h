#pragma once

#include <string>
#include <windows.h>

struct AuthState
{
    bool isAuthenticated = false;
    std::wstring username;

    std::wstring accessToken;
    std::wstring refreshToken;

    bool hasLicense = false;
    std::wstring licenseTicket;

    long long accessExpiresAt = 0;
    long long refreshExpiresAt = 0;
    long long licenseExpiresAt = 0;
};

void AuthInitialize();
void AuthShutdown();

int AuthGetCurrentUser(bool* isAuthenticated, std::wstring* username);
int AuthLogin(const std::wstring& login, const std::wstring& password);
int AuthLogout();

int AuthGetLicenseInfo(bool* hasLicense, long long* expiresAtUnix);
int AuthActivateProduct(const std::wstring& activationCode);

bool AuthHasLicense();