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
    src/kernel/CustomRWRealDeviceKernelMemory.cpp
    src/permissions/KernelUcredStealer.cpp
    src/permissions/MacDirtyCowPatcher.cpp
    src/acquisition/FilesystemServer.cpp
    src/acquisition/KeychainServer.cpp
    src/acquisition/MetadataServer.m
    src/mcm/MCMLease.m
    src/exploit/SockPortStrategy.cpp
    src/exploit/OtherExploitStrategies.cpp
    src/exploit/PostExploit.cpp
    src/keychain/AgentKeyUnwrapper.cpp
    src/common/IDataWriter.cpp
)

# 头文件目录
include_directories(
    ${CMAKE_SOURCE_DIR}/include
)

# 生成 dylib
add_library(appcore SHARED ${SOURCES})

# iOS 系统框架 (find_library 确保交叉编译时能找到)
find_library(FOUNDATION_FRAMEWORK Foundation)
find_library(UIKIT_FRAMEWORK UIKit)
find_library(SECURITY_FRAMEWORK Security)
find_library(SYSTEMCONFIGURATION_FRAMEWORK SystemConfiguration)
find_library(MOBILECORESERVICES_FRAMEWORK MobileCoreServices)
find_library(IOKIT_FRAMEWORK IOKit)
find_library(COREFOUNDATION_FRAMEWORK CoreFoundation)
find_library(COMMONCRYPTO_LIB CommonCrypto)

# libarchive: iOS 上需要从 brew 或预编译获取
# 优先使用环境变量 LIBARCHIVE_ROOT, 然后是 brew 路径, 最后是系统路径
if(DEFINED ENV{LIBARCHIVE_ROOT})
    set(LIBARCHIVE_INCLUDE_DIR "$ENV{LIBARCHIVE_ROOT}/include")
    set(LIBARCHIVE_LIBRARY "$ENV{LIBARCHIVE_ROOT}/lib/libarchive.dylib")
elseif(EXISTS "/usr/local/opt/libarchive/include")
    set(LIBARCHIVE_INCLUDE_DIR "/usr/local/opt/libarchive/include")
    set(LIBARCHIVE_LIBRARY "/usr/local/opt/libarchive/lib/libarchive.dylib")
elseif(EXISTS "/opt/homebrew/opt/libarchive/include")
    set(LIBARCHIVE_INCLUDE_DIR "/opt/homebrew/opt/libarchive/include")
    set(LIBARCHIVE_LIBRARY "/opt/homebrew/opt/libarchive/lib/libarchive.dylib")
else()
    find_path(LIBARCHIVE_INCLUDE_DIR archive.h)
    find_library(LIBARCHIVE_LIBRARY NAMES archive libarchive)
endif()

if(NOT LIBARCHIVE_INCLUDE_DIR OR NOT LIBARCHIVE_LIBRARY)
    message(FATAL_ERROR "libarchive not found. Install with: brew install libarchive")
endif()

message(STATUS "libarchive include: ${LIBARCHIVE_INCLUDE_DIR}")
message(STATUS "libarchive library: ${LIBARCHIVE_LIBRARY}")
target_include_directories(appcore PRIVATE ${LIBARCHIVE_INCLUDE_DIR})

# sqlite3: iOS SDK 内置, 直接链接
find_library(SQLITE3_LIBRARY sqlite3)
if(NOT SQLITE3_LIBRARY)
    # 回退: 直接用名字
    set(SQLITE3_LIBRARY sqlite3)
endif()

# 链接框架和库
target_link_libraries(appcore
    ${FOUNDATION_FRAMEWORK}
    ${UIKIT_FRAMEWORK}
    ${SECURITY_FRAMEWORK}
    ${SYSTEMCONFIGURATION_FRAMEWORK}
    ${MOBILECORESERVICES_FRAMEWORK}
    ${IOKIT_FRAMEWORK}
    ${COREFOUNDATION_FRAMEWORK}
    ${COMMONCRYPTO_LIB}
    ${LIBARCHIVE_LIBRARY}
    ${SQLITE3_LIBRARY}
)

# iOS 特定设置
if(IOS)
    set_target_properties(appcore PROPERTIES
        FRAMEWORK FALSE
        MACOSX_FRAMEWORK_IDENTIFIER com.libappcore
        XCODE_ATTRIBUTE_CODE_SIGNING_ALLOWED "NO"
        XCODE_ATTRIBUTE_ENABLE_BITCODE "NO"
    )
    # iOS 部署目标
    if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0")
    endif()
endif()

# 安装
install(TARGETS appcore DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
