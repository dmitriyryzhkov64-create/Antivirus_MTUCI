#include <windows.h>
#include <rpc.h>
#include <cstdlib>

#include "../common/service_names.h"
#include "rpc_client.h"
#include "AntivirusRpc_h.h"

#pragma comment(lib, "Rpcrt4.lib")

void* __RPC_USER midl_user_allocate(size_t size)
{
    return malloc(size);
}

void __RPC_USER midl_user_free(void* ptr)
{
    free(ptr);
}

bool SendStopServiceRpc()
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
        return false;

    status = RpcBindingFromStringBindingW(stringBinding, &binding);
    RpcStringFreeW(&stringBinding);

    if (status != RPC_S_OK)
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