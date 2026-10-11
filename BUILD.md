# 构建指南

## 环境要求

- **操作系统**: macOS 12+ (编译 iOS dylib 必须 macOS)
- **Xcode**: 14.0+ (含 iOS SDK)
- **CMake**: 3.15+
- **依赖库**: libarchive, sqlite3 (通过 brew 或 iOS toolchain 提供)

## 方式一：使用 ios.toolchain.cmake (推荐)

```bash
# 1. 安装 ios-cmake
git clone https://github.com/leetal/ios-cmake.git
export IOS_CMAKE_TOOLCHAIN=$(pwd)/ios-cmake/ios.toolchain.cmake

# 2. 安装依赖 (使用 Homebrew)
brew install libarchive sqlite3

# 3. 配置构建
mkdir build && cd build
cmake .. \
  -DCMAKE_TOOLCHAIN_FILE=$IOS_CMAKE_TOOLCHAIN \
  -DPLATFORM=OS64 \
  -DDEPLOYMENT_TARGET=14.0 \
  -DCMAKE_BUILD_TYPE=Release

# 4. 编译
make -j$(sysctl -n hw.ncpu)

# 5. 产物
# build/libappcore.dylib
```

## 方式二：Xcode 直接编译

```bash
# 生成 Xcode 项目
mkdir build-xcode && cd build-xcode
cmake .. -G Xcode -DCMAKE_TOOLCHAIN_FILE=$IOS_CMAKE_TOOLCHAIN -DPLATFORM=OS64

# 用 Xcode 打开
open libappcore-reverse.xcodeproj
# 选择 Any iOS Device (arm64) -> Build
```

## 方式三：macOS 本地编译 (测试用)

```bash
mkdir build-mac && cd build-mac
cmake .. -DCMAKE_BUILD_TYPE=Debug
make -j4
# 产物: build-mac/libappcore.dylib (macOS 版本, 仅用于编译验证)
```

## 依赖说明

| 依赖 | 用途 | 安装 |
|------|------|------|
| libarchive | 文件系统 tar.gz 打包 | `brew install libarchive` |
| sqlite3 | 钥匙串数据库读取 | iOS SDK 内置 |
| CommonCrypto | AKS GCM 解密 | iOS SDK 内置 |
| IOKit | sock_port IOSurface 操作 | iOS SDK 内置 |
| Foundation/UIKit | Objective-C 运行时 | iOS SDK 内置 |

## CMake 选项

```cmake
# 平台
-DPLATFORM=OS64        # iOS 64-bit
-DPLATFORM=SIMULATOR64 # iOS 模拟器
-DPLATFORM=MAC         # macOS

# 部署目标
-DDEPLOYMENT_TARGET=14.0

# 构建类型
-DCMAKE_BUILD_TYPE=Release  # or Debug
```

## 注入到 IPA

编译出 `libappcore.dylib` 后，使用注入工具：

```bash
# 使用 vpoker-inject-pack 的注入脚本
python3 vpoker-inject-pack/scripts/inject.py \
  --ipa original.ipa \
  --dylib build/libappcore.dylib \
  --output repacked.ipa
```

## 验证编译

```bash
# 检查 dylib 架构
file build/libappcore.dylib
# 应输出: Mach-O 64-bit dynamically linked shared library arm64

# 检查导出符号
nm -gU build/libappcore.dylib | head -20
# 应包含: libappcore_autorun, libappcore_do_acquisition 等

# 检查依赖
otool -L build/libappcore.dylib
# 应包含: libarchive, libsqlite3, Foundation, UIKit, IOKit 等
```

## 常见问题

### Q: `'IOKit/IOKitLib.h' file not found`
A: iOS 模拟器 SDK 不含 IOKit，使用 `-DPLATFORM=OS64` 编译真机版本。

### Q: `'archive.h' file not found`
A: libarchive 未安装或路径不对。`brew install libarchive` 后添加：
```cmake
include_directories(/usr/local/opt/libarchive/include)
link_directories(/usr/local/opt/libarchive/lib)
```

### Q: 编译成功但注入后 crash
A: 检查代码签名和 entitlements。需要 `get-task-allow` 和沙箱例外权限。

### Q: 漏洞利用不生效
A: 偏移表数值需按目标 iOS 版本和设备型号验证。参考 `VersionedOffsetProvider.cpp` 中的注释。
