#include <windows.h>
#include <rpc.h>
#include <string>
#include <cstdlib>

#include "../common/service_names.h"
#include "rpc_client.h"
#include "AntivirusRpc.h"

#pragma comment(lib, "Rpcrt4.lib")

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* ptr)
{
    free(ptr);
}

static RPC_BINDING_HANDLE CreateBinding()
{
    RPC_WSTR stringBinding = nullptr;
    RPC_BINDING_HANDLE binding = nullptr;

    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(RPC_ENDPOINT)),
        nullptr,
        &stringBinding
    );

    if (status != RPC_S_OK)
        return nullptr;

    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK)
        return nullptr;

    return binding;
}

bool SendStopServiceRpc()
{
    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return false;

    bool ok = true;

    RpcTryExcept
    {
        RpcStopService(binding);
    }
    RpcExcept(1)
    {
        ok = false;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return ok;
}

bool RpcClientGetCurrentUser(bool* isAuthenticated, std::wstring* username)
{
    if (!isAuthenticated || !username)
        return false;

    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return false;

    int auth = 0;
    wchar_t* rpcUsername = nullptr;
    bool ok = true;

    RpcTryExcept
    {
        int result = RpcGetCurrentUser(binding, &auth, &rpcUsername);

        if (result != 0)
        {
            ok = false;
        }
        else
        {
            *isAuthenticated = auth != 0;
            *username = rpcUsername ? rpcUsername : L"";
        }

        if (rpcUsername)
            midl_user_free(rpcUsername);
    }
    RpcExcept(1)
    {
        ok = false;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return ok;
}

int RpcClientLogin(const std::wstring& login, const std::wstring& password)
{
    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int result = -1;

    RpcTryExcept
    {
        result = RpcLogin(binding, login.c_str(), password.c_str());
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

int RpcClientLogout()
{
    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int result = -1;

    RpcTryExcept
    {
        result = RpcLogout(binding);
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

int RpcClientGetLicenseInfo(bool* hasLicense, long long* expiresAtUnix)
{
    if (!hasLicense || !expiresAtUnix)
        return -1;

    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int has = 0;
    hyper expires = 0;
    int result = -1;

    RpcTryExcept
    {
        result = RpcGetLicenseInfo(binding, &has, &expires);
        *hasLicense = has != 0;
        *expiresAtUnix = static_cast<long long>(expires);
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

int RpcClientActivate(const std::wstring& activationCode)
{
    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int result = -1;

    RpcTryExcept
    {
        result = RpcActivateProduct(binding, activationCode.c_str());
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

int RpcClientGetAvDatabaseInfo(RpcAvDatabaseInfo* info)
{
    if (!info)
        return -1;

    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int loaded = 0;
    hyper count = 0;
    wchar_t* rpcDate = nullptr;
    int result = -1;

    RpcTryExcept
    {
        result = RpcGetAvDatabaseInfo(binding, &loaded, &count, &rpcDate);

        info->isLoaded = loaded != 0;
        info->recordCount = static_cast<unsigned long long>(count);
        info->releaseDate = rpcDate ? rpcDate : L"";

        if (rpcDate)
            midl_user_free(rpcDate);
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

int RpcClientScanFile(
    const std::wstring& filePath,
    RpcAvScanResult* resultData)
{
    if (!resultData)
        return -1;

    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int malicious = 0;
    hyper scanned = 0;
    hyper detected = 0;
    wchar_t* rpcThreat = nullptr;
    int result = -1;

    RpcTryExcept
    {
        result = RpcScanFile(
            binding,
            filePath.c_str(),
            &malicious,
            &scanned,
            &detected,
            &rpcThreat
        );

        resultData->isMalicious = malicious != 0;
        resultData->scannedFiles = static_cast<unsigned long long>(scanned);
        resultData->detectedThreats = static_cast<unsigned long long>(detected);
        resultData->threatName = rpcThreat ? rpcThreat : L"";

        if (rpcThreat)
            midl_user_free(rpcThreat);
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}

int RpcClientScanDirectory(
    const std::wstring& directoryPath,
    RpcAvScanResult* resultData)
{
    if (!resultData)
        return -1;

    RPC_BINDING_HANDLE binding = CreateBinding();
    if (!binding)
        return -1;

    int malicious = 0;
    hyper scanned = 0;
    hyper detected = 0;
    wchar_t* rpcThreat = nullptr;
    int result = -1;

    RpcTryExcept
    {
        result = RpcScanDirectory(
            binding,
            directoryPath.c_str(),
            &malicious,
            &scanned,
            &detected,
            &rpcThreat
        );

        resultData->isMalicious = malicious != 0;
        resultData->scannedFiles = static_cast<unsigned long long>(scanned);
        resultData->detectedThreats = static_cast<unsigned long long>(detected);
        resultData->threatName = rpcThreat ? rpcThreat : L"";

        if (rpcThreat)
            midl_user_free(rpcThreat);
    }
    RpcExcept(1)
    {
        result = -1;
    }
    RpcEndExcept

    RpcBindingFree(&binding);
    return result;
}