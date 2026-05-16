cmake_minimum_required(VERSION 3.20)

project(TrayApp LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TrayApp WIN32
    src/main.cpp
)

add_executable(AntivirusMTUCIService
    src/service/service.cpp
    src/auth/auth_manager.cpp
    src/http/http_client.cpp
    ${RPC_GEN_DIR}/AntivirusRpc_s.c
)

target_compile_definitions(TrayApp PRIVATE UNICODE _UNICODE)

target_link_libraries(TrayApp PRIVATE
    user32
    shell32
    gdi32
)

target_link_libraries(AntivirusMTUCIService PRIVATE
    advapi32
    user32
    wtsapi32
    userenv
    rpcrt4
    winhttp
)

