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

struct RpcAvDatabaseInfo
{
    bool isLoaded = false;
    unsigned long long recordCount = 0;
    std::wstring releaseDate;
};

struct RpcAvScanResult
{
    bool isMalicious = false;
    unsigned long long scannedFiles = 0;
    unsigned long long detectedThreats = 0;
    std::wstring threatName;
};

int RpcClientGetAvDatabaseInfo(RpcAvDatabaseInfo* info);

int RpcClientScanFile(
    const std::wstring& filePath,
    RpcAvScanResult* result
);

int RpcClientScanDirectory(
    const std::wstring& directoryPath,
    RpcAvScanResult* result
);