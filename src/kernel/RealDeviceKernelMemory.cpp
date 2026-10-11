// RealDeviceKernelMemory.cpp - 真实设备内核内存读写实现
// 基于标准 mach_vm API (tfp0) 实现
// 参考: libjailbreak (Dopamine), XNU 源码
#include "kernel/RealDeviceKernelMemory.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdio.h>

namespace kernel {

RealDeviceKernelMemory::RealDeviceKernelMemory(mach_port_t tfp0)
    : tfp0_(tfp0) {
}

RealDeviceKernelMemory::~RealDeviceKernelMemory() {
    // 不关闭 tfp0 (可能被其他模块共享)
}

ssize_t RealDeviceKernelMemory::Read(uint64_t addr, void* buf, size_t len) {
    if (!CanRead(addr)) return -1;
    return ReadUnsafe(addr, buf, len);
}

ssize_t RealDeviceKernelMemory::Write(uint64_t addr, const void* buf, size_t len) {
    if (!CanWrite(addr)) return -1;
    return WriteUnsafe(addr, buf, len);
}

ssize_t RealDeviceKernelMemory::ReadUnsafe(uint64_t addr, void* buf, size_t len) {
    if (tfp0_ == MACH_PORT_NULL || buf == nullptr || len == 0) return -1;

    mach_vm_size_t out_size = 0;
    kern_return_t kr = mach_vm_read_overwrite(
        tfp0_,
        (mach_vm_address_t)addr,
        (mach_vm_size_t)len,
        (mach_vm_address_t)buf,
        &out_size
    );

    if (kr != KERN_SUCCESS) {
        return -1;
    }
    return (ssize_t)out_size;
}

ssize_t RealDeviceKernelMemory::WriteUnsafe(uint64_t addr, const void* buf, size_t len) {
    if (tfp0_ == MACH_PORT_NULL || buf == nullptr || len == 0) return -1;

    kern_return_t kr = mach_vm_write(
        tfp0_,
        (mach_vm_address_t)addr,
        (vm_offset_t)buf,
        (mach_msg_type_number_t)len
    );

    if (kr != KERN_SUCCESS) {
        return -1;
    }
    return (ssize_t)len;
}

bool RealDeviceKernelMemory::CanRead(uint64_t addr) const {
    // 简单的地址范围检查
    // 内核地址通常在 0xffff000000000000 以上 (ARM64)
    // 实际应检查 vm_map 区域
    if (addr == 0) return false;
    if (addr < 0x100000000ULL) return false;  // 用户态低地址
    return true;
}

bool RealDeviceKernelMemory::CanWrite(uint64_t addr) const {
    // 写入需要更严格的检查
    return CanRead(addr);
}

} // namespace kernel
