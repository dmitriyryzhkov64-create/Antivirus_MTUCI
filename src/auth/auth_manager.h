#pragma once
#include <windows.h>
#include <string>

#include "auth_state.h"

void AuthInitialize();
void AuthShutdown();

int AuthGetCurrentUser(bool* isAuthenticated, std::wstring* username);

int AuthLogin(const std::wstring& login, const std::wstring& password);
int AuthLogout();

int AuthGetLicenseInfo(bool* hasLicense, long long* expiresAtUnix);
int AuthActivateProduct(const std::wstring& activationCode);

bool AuthHasLicense();