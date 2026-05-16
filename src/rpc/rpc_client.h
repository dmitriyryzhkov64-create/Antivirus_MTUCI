#pragma once

#include <string>

bool SendStopServiceRpc();

bool RpcClientGetCurrentUser(
    bool* isAuthenticated,
    std::wstring* username
);

int RpcClientLogin(
    const std::wstring& login,
    const std::wstring& password
);

int RpcClientLogout();

int RpcClientGetLicenseInfo(
    bool* hasLicense,
    long long* expiresAtUnix
);

int RpcClientActivate(
    const std::wstring& activationCode
);