// IKernelMemory.h - 内核内存读写接口
// 逆向自 libappcore.dylib (kernel::IKernelMemory)
#pragma once
#include <cstdint>
#include <cstddef>

namespace kernel {

// 内核内存读写抽象接口
class IKernelMemory {
public:
    virtual ~IKernelMemory() = default;

    // 读取内核内存
    // addr: 内核虚拟地址, buf: 用户态缓冲区, len: 读取长度
    // 返回: 实际读取的字节数, 失败返回 -1
    virtual ssize_t Read(uint64_t addr, void* buf, size_t len) = 0;

    // 写入内核内存
    virtual ssize_t Write(uint64_t addr, const void* buf, size_t len) = 0;

    // 不安全读取 (无边界检查)
    virtual ssize_t ReadUnsafe(uint64_t addr, void* buf, size_t len) = 0;
    virtual ssize_t WriteUnsafe(uint64_t addr, const void* buf, size_t len) = 0;

    // 检查地址是否可读/可写
    virtual bool CanRead(uint64_t addr) const = 0;
    virtual bool CanWrite(uint64_t addr) const = 0;

    // 便捷读取模板
    template<typename T>
    T Read(uint64_t addr) {
        T val{};
        Read(addr, &val, sizeof(T));
        return val;
    }

    template<typename T>
    void Write(uint64_t addr, const T& val) {
        Write(addr, &val, sizeof(T));
    }

    // 读取内核字符串
    virtual char* ReadString(uint64_t addr, size_t max_len = 1024) {
        static char buf[1024];
        Read(addr, buf, max_len);
        return buf;
    }
};

} // namespace kernel
