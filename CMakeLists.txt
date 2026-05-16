cmake_minimum_required(VERSION 3.20)

project(TrayApp LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(TrayApp WIN32
    src/main.cpp
)

target_compile_definitions(TrayApp PRIVATE UNICODE _UNICODE)

target_link_libraries(TrayApp PRIVATE
    user32
    shell32
    gdi32
)