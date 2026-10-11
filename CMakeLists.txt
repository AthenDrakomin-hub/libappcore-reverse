cmake_minimum_required(VERSION 3.15)
project(libappcore-reverse VERSION 1.0.0 LANGUAGES CXX OBJC OBJCXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 平台检测
if(NOT IOS AND NOT APPLE)
    message(FATAL_ERROR "This project only supports iOS/macOS")
endif()

# 源文件
set(SOURCES
    src/autorun.mm
    src/server/AcqViewCntrlr.mm
    src/upload/SimpleUploader.m
    src/kernel/RealDeviceKernelMemory.cpp
    src/kernel/VersionedOffsetProvider.cpp
    src/permissions/KernelUcredStealer.cpp
    src/permissions/MacDirtyCowPatcher.cpp
    src/acquisition/FilesystemServer.cpp
    src/common/IDataWriter.cpp
)

# 头文件目录
include_directories(
    ${CMAKE_SOURCE_DIR}/include
)

# 生成 dylib
add_library(appcore SHARED ${SOURCES})

# 链接框架
target_link_libraries(appcore
    "-framework Foundation"
    "-framework UIKit"
    "-framework Security"
    "-framework SystemConfiguration"
    "-framework MobileCoreServices"
    libarchive
    sqlite3
)

# 安装
install(TARGETS appcore DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
