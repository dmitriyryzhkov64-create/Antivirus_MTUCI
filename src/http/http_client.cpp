#include <windows.h>
#include <winhttp.h>
#include <string>

#include "http_client.h"

#pragma comment(lib, "Winhttp.lib")

static std::wstring ReadResponseBody(HINTERNET request)
{
    std::wstring result;
    DWORD bytesAvailable = 0;

    while (WinHttpQueryDataAvailable(request, &bytesAvailable) && bytesAvailable > 0)
    {
        std::string buffer(bytesAvailable, '\0');
        DWORD bytesRead = 0;

        if (!WinHttpReadData(request, buffer.data(), bytesAvailable, &bytesRead))
            break;

        if (bytesRead == 0)
            break;

        int wideSize = MultiByteToWideChar(
            CP_UTF8,
            0,
            buffer.data(),
            static_cast<int>(bytesRead),
            nullptr,
            0
        );

        if (wideSize > 0)
        {
            std::wstring wideBuffer(wideSize, L'\0');
            MultiByteToWideChar(
                CP_UTF8,
                0,
                buffer.data(),
                static_cast<int>(bytesRead),
                wideBuffer.data(),
                wideSize
            );

            result += wideBuffer;
        }
    }

    return result;
}

static HttpResponse SendJsonRequest(
    const std::wstring& method,
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& path,
    const std::wstring& jsonBody,
    const std::wstring& bearerToken
)
{
    HttpResponse response;

    HINTERNET session = WinHttpOpen(
        L"Antivirus MTUCI Service/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!session)
        return response;

    HINTERNET connect = WinHttpConnect(session, host.c_str(), port, 0);
    if (!connect)
    {
        WinHttpCloseHandle(session);
        return response;
    }

    HINTERNET request = WinHttpOpenRequest(
        connect,
        method.c_str(),
        path.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE
    );

    if (!request)
    {
        WinHttpCloseHandle(connect);
        WinHttpCloseHandle(session);
        return response;
    }

    std::wstring headers = L"Content-Type: application/json\r\n";

    if (!bearerToken.empty())
    {
        headers += L"Authorization: Bearer ";
        headers += bearerToken;
        headers += L"\r\n";
    }

    std::string utf8Body;
    if (!jsonBody.empty())
    {
        int size = WideCharToMultiByte(
            CP_UTF8,
            0,
            jsonBody.c_str(),
            -1,
            nullptr,
            0,
            nullptr,
            nullptr
        );

        if (size > 0)
        {
            utf8Body.resize(size - 1);
            WideCharToMultiByte(
                CP_UTF8,
                0,
                jsonBody.c_str(),
                -1,
                utf8Body.data(),
                size,
                nullptr,
                nullptr
            );
        }
    }

    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.length()),
        utf8Body.empty() ? WINHTTP_NO_REQUEST_DATA : utf8Body.data(),
        static_cast<DWORD>(utf8Body.size()),
        static_cast<DWORD>(utf8Body.size()),
        0
    );

    if (sent && WinHttpReceiveResponse(request, nullptr))
    {
        DWORD statusCode = 0;
        DWORD statusCodeSize = sizeof(statusCode);

        WinHttpQueryHeaders(
            request,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusCodeSize,
            WINHTTP_NO_HEADER_INDEX
        );

        response.statusCode = statusCode;
        response.body = ReadResponseBody(request);
        response.ok = statusCode >= 200 && statusCode < 300;
    }

    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);

    return response;
}

HttpResponse HttpsPostJson(
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& path,
    const std::wstring& jsonBody,
    const std::wstring& bearerToken
)
{
    return SendJsonRequest(L"POST", host, port, path, jsonBody, bearerToken);
}

HttpResponse HttpsGetJson(
    const std::wstring& host,
    INTERNET_PORT port,
    const std::wstring& path,
    const std::wstring& bearerToken
)
{
    return SendJsonRequest(L"GET", host, port, path, L"", bearerToken);
}