// CustomRWRealDeviceKernelMemory.h - 自定义读写函数的内核内存
// 逆向自 libappcore.dylib (kernel::CustomRWRealDeviceKernelMemory)
#pragma once
#include "IKernelMemory.h"
#include <functional>

namespace kernel {

// 使用自定义读写回调的内核内存实现
// 用于漏洞利用阶段，通过伪造端口实现内核读写
class CustomRWRealDeviceKernelMemory : public IKernelMemory {
public:
    using ReadFunc = std::function<ssize_t(uint64_t, void*, size_t)>;
    using WriteFunc = std::function<ssize_t(uint64_t, const void*, size_t)>;

    CustomRWRealDeviceKernelMemory(ReadFunc read_fn, WriteFunc write_fn);
    ~CustomRWRealDeviceKernelMemory() override;

    ssize_t Read(uint64_t addr, void* buf, size_t len) override;
    ssize_t Write(uint64_t addr, const void* buf, size_t len) override;
    ssize_t ReadUnsafe(uint64_t addr, void* buf, size_t len) override;
    ssize_t WriteUnsafe(uint64_t addr, const void* buf, size_t len) override;
    bool CanRead(uint64_t addr) const override;
    bool CanWrite(uint64_t addr) const override;

    // 在内核中分配数据 (kalloc)
    static uint64_t KallocDataAlloc(size_t size, IKernelMemory& km);

    // 分配多个内核对象
    static void KmemAllocMultiple(size_t count, size_t size, uint64_t* addrs);

private:
    ReadFunc read_fn_;
    WriteFunc write_fn_;
};

} // namespace kernel
