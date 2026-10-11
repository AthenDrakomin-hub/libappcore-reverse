// MacDirtyCowPatcher.cpp - MacDirtyCow (CVE-2022-46689) 漏洞利用实现
// 基于: https://github.com/zhuowei/MacDirtyCowDemo (MIT)
// 原理: vm_copy 的竞争条件允许 overwrite 只读内存页
#include "permissions/MacDirtyCowPatcher.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

namespace permissions {

MacDirtyCowPatcher::MacDirtyCowPatcher()
    : overwrite_fd_(-1) {
}

MacDirtyCowPatcher::~MacDirtyCowPatcher() {
    if (overwrite_fd_ >= 0) {
        close(overwrite_fd_);
    }
}

bool MacDirtyCowPatcher::IsSupported() {
    // MacDirtyCow 影响:
    // iOS 15.0 - 15.7.1
    // iOS 16.0 - 16.1.2
    // macOS 13.0 - 13.0.1
    // 需要运行时检测 iOS 版本
    char version[256] = {0};
    size_t size = sizeof(version);
    if (sysctlbyname("kern.osversion", version, &size, nullptr, 0) != 0) {
        return false;
    }

    int major = 0, minor = 0;
    sscanf(version, "%d.%d", &major, &minor);

    if (major == 15 && minor <= 7) return true;
    if (major == 16 && minor <= 1) return true;
    return false;
}

bool MacDirtyCowPatcher::Patch(uint64_t target, const void* replacement, size_t len) {
    if (!replacement || len == 0 || len > 4096) {
        return false;
    }

    // MacDirtyCow 核心: 通过 vm_copy 竞争 overwrite 只读页
    // 1. 创建一个可写映射，内容为 replacement
    // 2. 在另一个线程中不断 vm_copy 覆盖目标页
    // 3. 竞争窗口内完成 overwrite

    return OverwriteReadOnlyPage(target, replacement, len);
}

bool MacDirtyCowPatcher::OverwriteReadOnlyPage(uint64_t target,
                                                const void* data,
                                                size_t len) {
    // 注意: 这是简化的框架实现
    // 完整的 MacDirtyCow 利用需要:
    // 1. 用 vm_allocate 创建覆盖用的内存
    // 2. 用 vm_protect 设置为可写
    // 3. 写入 replacement 数据
    // 4. 启动竞争线程不断调用 vm_copy
    // 5. 主线程触发目标页的 COW
    // 6. 验证 overwrite 成功

    // 参考实现: https://github.com/zhuowei/MacDirtyCowDemo/blob/master/vm_unaligned_copy_switch_race.c
    printf("[!] MacDirtyCowPatcher: framework only, integrate MacDirtyCowDemo for full exploit\n");
    printf("    Reference: https://github.com/zhuowei/MacDirtyCowDemo\n");

    // 伪代码:
    // mach_vm_address_t overwrite_addr = 0;
    // mach_vm_allocate(mach_task_self(), &overwrite_addr, 4096, VM_FLAGS_ANYWHERE);
    // memcpy((void*)overwrite_addr, data, len);
    //
    // pthread_t race_thread;
    // pthread_create(&race_thread, NULL, race_thread_func, (void*)target);
    //
    // // 触发 COW
    // for (int i = 0; i < 1000; i++) {
    //     vm_copy(mach_task_self(), overwrite_addr, 4096, target);
    // }
    //
    // pthread_cancel(race_thread);
    // mach_vm_deallocate(mach_task_self(), overwrite_addr, 4096);

    return false;  // 框架实现，返回 false
}

bool MacDirtyCowPatcher::PatchSandboxExtension() {
    // 通过 MacDirtyCow 修改沙箱配置
    // 目标: 沙箱的只读配置页
    // 这需要知道沙箱配置的内存地址
    printf("[!] PatchSandboxExtension: requires sandbox config address\n");
    return false;
}

bool MacDirtyCowPatcher::PatchCodeSigning() {
    // 通过 MacDirtyCow 修改 csops 相关的只读数据
    // 目标: AMFI 的代码签名检查数据
    printf("[!] PatchCodeSigning: requires AMFI data address\n");
    return false;
}

bool MacDirtyCowPatcher::SetupOverwriteMap() {
    // 设置覆盖用的内存映射
    if (overwrite_fd_ >= 0) return true;

    // 创建匿名映射用于覆盖
    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_allocate(
        mach_task_self(), &addr, 4096, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        return false;
    }

    // 设置为可写
    vm_protect(mach_task_self(), addr, 4096, FALSE,
               VM_PROT_READ | VM_PROT_WRITE);

    overwrite_fd_ = (int)addr;  // 存储地址 (简化)
    return true;
}

// ============================================================================
// SandboxExtPatcher 实现
// ============================================================================

void SandboxExtPatcher::Patch(kernel::IKernelMemory* km, uint64_t label_addr) {
    if (!km || label_addr == 0) return;

    // 修改 ucred 中的沙箱标签
    // 沙箱标签是一个 MAC label 结构体
    // 需要将其替换为更宽松的配置 (如 "container-skeleton")

    // 简化实现: 打印信息
    printf("[+] SandboxExtPatcher: patching label at 0x%llx\n", label_addr);

    // 实际实现需要:
    // 1. 读取当前沙箱标签
    // 2. 构造新的沙箱配置 (允许更多文件访问)
    // 3. 写入内核内存
    // 参考: Dopamine 的 jailbreakd 实现
}

void SandboxExtPatcher::PatchAMFI(kernel::IKernelMemory* km, uint64_t label_addr) {
    if (!km || label_addr == 0) return;

    // 修改 AMFI 标志，允许未签名代码
    printf("[+] SandboxExtPatcher: patching AMFI at 0x%llx\n", label_addr);

    // AMFI 标志通常在 ucred 的 MAC label 中
    // 需要设置 CS_GET_TASK_ALLOW 等标志
    // 参考: Dopamine/libjailbreak 的 AMFI patch
}

} // namespace permissions
