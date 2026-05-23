cmake_minimum_required(VERSION 3.20)

project(AntivirusMTUCI LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RPC_IDL ${CMAKE_SOURCE_DIR}/src/rpc/AntivirusRpc.idl)
set(RPC_GEN_DIR ${CMAKE_BINARY_DIR}/generated)

file(MAKE_DIRECTORY ${RPC_GEN_DIR})

add_custom_command(
    OUTPUT
        ${RPC_GEN_DIR}/AntivirusRpc.h
        ${RPC_GEN_DIR}/AntivirusRpc_c.c
        ${RPC_GEN_DIR}/AntivirusRpc_s.c
    COMMAND midl
        /nologo
        /env x64
        /out ${RPC_GEN_DIR}
        ${RPC_IDL}
    DEPENDS ${RPC_IDL}
)

add_custom_target(generate_rpc
    DEPENDS
        ${RPC_GEN_DIR}/AntivirusRpc.h
        ${RPC_GEN_DIR}/AntivirusRpc_c.c
        ${RPC_GEN_DIR}/AntivirusRpc_s.c
)

add_executable(AntivirusMTUCI WIN32
    src/gui/main.cpp
    src/rpc/rpc_client.cpp
    ${RPC_GEN_DIR}/AntivirusRpc_c.c
)

add_dependencies(AntivirusMTUCI generate_rpc)

target_include_directories(AntivirusMTUCI PRIVATE
    ${RPC_GEN_DIR}
    src
)

target_compile_definitions(AntivirusMTUCI PRIVATE UNICODE _UNICODE)

target_link_libraries(AntivirusMTUCI PRIVATE
    user32
    shell32
    gdi32
    advapi32
    rpcrt4
)

add_executable(AntivirusMTUCIService
    src/service/service.cpp
    src/auth/auth_manager.cpp
    src/http/http_client.cpp
    ${RPC_GEN_DIR}/AntivirusRpc_s.c
)

add_dependencies(AntivirusMTUCIService generate_rpc)

target_include_directories(AntivirusMTUCIService PRIVATE
    ${RPC_GEN_DIR}
    src
)

target_compile_definitions(AntivirusMTUCIService PRIVATE UNICODE _UNICODE)

target_link_libraries(AntivirusMTUCIService PRIVATE
    advapi32
    user32
    wtsapi32
    userenv
    rpcrt4
    winhttp
)