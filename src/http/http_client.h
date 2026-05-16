#pragma once

#include <windows.h>
#include <winhttp.h>

#include <string>

struct HttpResponse
{
    bool ok = false;
    DWORD statusCode = 0;
    std::wstring body;
};

HttpResponse HttpsPostJson(
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& path,
    const std::wstring& jsonBody,
    const std::wstring& bearerToken = L""
);

HttpResponse HttpsGetJson(
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& path,
    const std::wstring& bearerToken = L""
);