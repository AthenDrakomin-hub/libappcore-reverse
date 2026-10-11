// MacDirtyCowPatcher.h - MacDirtyCow 漏洞补丁
// 逆向自 libappcore.dylib (permissions::MacDirtyCowPatcher)
// 核心代码来自 Apple XNU 开源: vm_unaligned_copy_switch_race.c
#pragma once
#include <cstdint>
#include <cstddef>

namespace kernel { class IKernelMemory; }

namespace permissions {

// MacDirtyCow (CVE-2022-46689) 漏洞利用
// 原理: vm_read_overwrite 非对齐复制的竞争条件, 修改只读映射
class MacDirtyCowPatcher {
public:
    MacDirtyCowPatcher();
    ~MacDirtyCowPatcher();

    // 检查是否支持 MacDirtyCow (iOS 15.0-15.7.1, 16.0-16.1.2)
    static bool IsSupported();

    // 执行补丁 (任意地址, 需要内核 r/w)
    bool Patch(uint64_t target, const void* replacement, size_t len);

    // 文件覆盖 (最常用场景: mmap 只读文件后用 MacDirtyCow 修改)
    bool OverwriteFile(const char* target_path,
                       const void* replacement_data,
                       size_t replacement_len);

    // 补丁沙箱扩展 (允许访问更多路径)
    bool PatchSandboxExtension();

    // 补丁 csops (允许未签名代码)
    bool PatchCodeSigning();

private:
    // MacDirtyCow 核心原语: 竞争条件修改只读页
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
