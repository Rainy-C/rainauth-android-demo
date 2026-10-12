cmake_minimum_required(VERSION 3.22.1)
project(rainguard CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(rainguard SHARED
        src/main/cpp/rainguard.cpp)

target_compile_options(rainguard PRIVATE
        -Wall -Wextra -O2
        -fvisibility=hidden          # 隐藏符号，抬高静态定位成本
        -fvisibility-inlines-hidden
        -fno-exceptions
        -ffunction-sections -fdata-sections)

target_link_options(rainguard PRIVATE
        -Wl,--gc-sections
        -Wl,--exclude-libs,ALL
        -Wl,-z,relro,-z,now          # 只读重定位 / 立即绑定
        -Wl,-z,noexecstack)

# 发布包剥离符号（NDK 的 Release 构建默认已 strip，这里显式声明）
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options(rainguard PRIVATE -s)
endif()

find_library(log-lib log)
target_link_libraries(rainguard ${log-lib})
