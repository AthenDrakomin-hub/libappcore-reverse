// VersionedOffsetProvider.h - 多版本内核偏移表
// 逆向自 libappcore.dylib (kernel::VersionedOffsetProvider)
#pragma once
#include "IOffsetProvider.h"
#include <memory>

namespace kernel {

// 按 iOS 版本选择对应的偏移表
// 支持 iOS 12 - iOS 16
class VersionedOffsetProvider {
public:
    // 检测当前 iOS 版本并创建对应偏移提供器
    static std::unique_ptr<IOffsetProvider> MakeOffsetProvider();

    // 检测 iOS 版本 (读取 kern.osversion)
    static int DetectIOSVersion();

    // 选择偏移表
    static std::unique_ptr<IOffsetProvider> SelectOffsetTable(int major_version);
};

// iOS 12 偏移表
class OffsetProvideriOS12 : public IOffsetProvider { /* ... */ };

// iOS 13 偏移表
class OffsetProvideriOS13 : public IOffsetProvider { /* ... */ };

// iOS 14 偏移表
class OffsetProvideriOS14 : public IOffsetProvider { /* ... */ };

// iOS 15 偏移表
class OffsetProvideriOS15 : public IOffsetProvider { /* ... */ };

// iOS 16 偏移表
class OffsetProvideriOS16 : public IOffsetProvider { /* ... */ };

} // namespace kernel
