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
    // 在内核中分配数据 (通过 kalloc)
    // 需要内核写原语构造伪造的 kalloc 区域
    // 简化: 分配用户态内存并返回地址 (不可用于内核)
    printf("[!] KallocDataAlloc: requires kernel kalloc primitive\n");

    mach_vm_address_t addr = 0;
    kern_return_t kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) return 0;
    return (uint64_t)addr;
}

void CustomRWRealDeviceKernelMemory::KmemAllocMultiple(size_t count, size_t size, uint64_t* addrs) {
    // 分配多个内核对象
    if (!addrs) return;
    for (size_t i = 0; i < count; i++) {
        addrs[i] = 0;
    }
    printf("[!] KmemAllocMultiple: requires kernel alloc primitive\n");
}

} // namespace kernel
