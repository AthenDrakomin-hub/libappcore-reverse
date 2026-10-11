// MacDirtyCowPatcher.h - MacDirtyCow 漏洞补丁
// 逆向自 libappcore.dylib (permissions::MacDirtyCowPatcher)
#pragma once
#include <cstdint>

namespace permissions {

// MacDirtyCow (CVE-2022-46689) 漏洞利用
// 原理: 通过 vm_copy _overwrite 只读内存页, 修改沙箱配置
class MacDirtyCowPatcher {
public:
    MacDirtyCowPatcher();
    ~MacDirtyCowPatcher();

    // 检查是否支持 MacDirtyCow
    static bool IsSupported();

    // 执行补丁
    // target: 目标只读地址, replacement: 替换数据, len: 长度
    bool Patch(uint64_t target, const void* replacement, size_t len);

    // 补丁沙箱扩展 (允许访问更多路径)
    bool PatchSandboxExtension();

    // 补丁 csops (允许未签名代码)
    bool PatchCodeSigning();

private:
    // MacDirtyCow 核心原语
    bool OverwriteReadOnlyPage(uint64_t target, const void* data, size_t len);

    // 构造覆盖用的 vm_map
    bool SetupOverwriteMap();

    int overwrite_fd_;
};

// 沙箱扩展补丁
class SandboxExtPatcher {
public:
    // 补丁 ucred 中的沙箱标签, 扩展文件系统访问权限
    static void Patch(kernel::IKernelMemory* km, uint64_t label_addr);

    // 补丁 AMFI 标志 (允许未签名 dylib)
    static void PatchAMFI(kernel::IKernelMemory* km, uint64_t label_addr);
};

} // namespace permissions
