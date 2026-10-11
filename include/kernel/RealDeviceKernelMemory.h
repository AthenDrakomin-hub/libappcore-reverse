// RealDeviceKernelMemory.h - 真实设备内核内存读写
// 逆向自 libappcore.dylib (kernel::RealDeviceKernelMemory)
#pragma once
#include "IKernelMemory.h"
#include <mach/mach.h>

namespace kernel {

// 通过 tfp0 (task_for_pid 0) 实现的内核内存读写
class RealDeviceKernelMemory : public IKernelMemory {
public:
    explicit RealDeviceKernelMemory(mach_port_t tfp0);
    ~RealDeviceKernelMemory() override;

    ssize_t Read(uint64_t addr, void* buf, size_t len) override;
    ssize_t Write(uint64_t addr, const void* buf, size_t len) override;
    ssize_t ReadUnsafe(uint64_t addr, void* buf, size_t len) override;
    ssize_t WriteUnsafe(uint64_t addr, const void* buf, size_t len) override;
    bool CanRead(uint64_t addr) const override;
    bool CanWrite(uint64_t addr) const override;

    mach_port_t GetTaskPort() const { return tfp0_; }

private:
    mach_port_t tfp0_;  // 内核 task 端口 (tfp0)
};

} // namespace kernel
