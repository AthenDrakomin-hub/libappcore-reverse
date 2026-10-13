// CustomRWRealDeviceKernelMemory.cpp - 自定义读写函数的内核内存实现
// 用于漏洞利用阶段, 通过伪造端口实现内核读写
#include "kernel/CustomRWRealDeviceKernelMemory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

namespace kernel {

CustomRWRealDeviceKernelMemory::CustomRWRealDeviceKernelMemory(ReadFunc read_fn, WriteFunc write_fn)
    : read_fn_(std::move(read_fn)), write_fn_(std::move(write_fn)) {
}

CustomRWRealDeviceKernelMemory::~CustomRWRealDeviceKernelMemory() {
}

ssize_t CustomRWRealDeviceKernelMemory::Read(uint64_t addr, void* buf, size_t len) {
    if (!CanRead(addr)) return -1;
    return ReadUnsafe(addr, buf, len);
}

ssize_t CustomRWRealDeviceKernelMemory::Write(uint64_t addr, const void* buf, size_t len) {
    if (!CanWrite(addr)) return -1;
    return WriteUnsafe(addr, buf, len);
}

ssize_t CustomRWRealDeviceKernelMemory::ReadUnsafe(uint64_t addr, void* buf, size_t len) {
    if (!read_fn_ || !buf || len == 0) return -1;
    return read_fn_(addr, buf, len);
}

ssize_t CustomRWRealDeviceKernelMemory::WriteUnsafe(uint64_t addr, const void* buf, size_t len) {
    if (!write_fn_ || !buf || len == 0) return -1;
    return write_fn_(addr, buf, len);
}

bool CustomRWRealDeviceKernelMemory::CanRead(uint64_t addr) const {
    if (addr == 0) return false;
    if (addr < 0x100000000ULL) return false;
    return true;
}

bool CustomRWRealDeviceKernelMemory::CanWrite(uint64_t addr) const {
    return CanRead(addr);
}

uint64_t CustomRWRealDeviceKernelMemory::KallocDataAlloc(size_t size, IKernelMemory& km) {
    // 在内核中分配数据
    // 方法1: 如果有 tfp0, 通过 mach_vm_allocate 在内核空间分配
    // 方法2: 通过 IOSurface 属性触发内核 kalloc (需要 IOSurface 用户客户端)
    // 方法3: 回退到用户态分配 (仅用于测试, 不可用于内核指针)

    // 尝试通过内核写原语构造分配
    // 标准做法: 利用 ipc_port 分配 (mach_port_allocate 触发内核 kalloc)
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        printf("[-] KallocDataAlloc: mach_port_allocate failed (kr=%d)\n", kr);
        return 0;
    }

    // 端口分配会触发内核 kalloc(ipc_port), 大小约 0x68 字节
    // 对于更大的分配, 需要多次分配或使用 IOSurface
    if (size <= 0x80) {
        // ipc_port 大小足够, 返回端口的内核地址 (需要内核读原语获取)
        // 注意: 这里返回的是用户态端口名, 不是内核地址
        // 调用者需要通过 find_port() 等方法获取内核地址
        printf("[*] KallocDataAlloc: allocated ipc_port (name=%d) for size=%zu\n", port, size);
        return (uint64_t)port;  // 返回端口名, 调用者需转换为内核地址
    }

    // 大分配: 通过 IOSurface empty_kalloc 触发
    // 需要 IOSurfaceRootUserClient, 这里简化处理
    printf("[!] KallocDataAlloc: size=%zu > 0x80, requires IOSurface kalloc primitive\n", size);
    printf("    Implement via IOSurface external method 0x16 (empty_kalloc)\n");

    // 回退: 分配用户态内存 (标注为不可直接用作内核指针)
    mach_vm_address_t addr = 0;
    kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), port);
        return 0;
    }
    printf("[!] KallocDataAlloc: fallback to userspace alloc at 0x%llx (NOT kernel memory)\n",
           (uint64_t)addr);
    return (uint64_t)addr;
}

void CustomRWRealDeviceKernelMemory::KmemAllocMultiple(size_t count, size_t size, uint64_t* addrs) {
    // 分配多个内核对象
    if (!addrs) return;
    memset(addrs, 0, count * sizeof(uint64_t));

    size_t success = 0;
    for (size_t i = 0; i < count; i++) {
        addrs[i] = KallocDataAlloc(size, *this);
        if (addrs[i] != 0) success++;
    }
    printf("[*] KmemAllocMultiple: %zu/%zu allocated\n", success, count);
}

} // namespace kernel
