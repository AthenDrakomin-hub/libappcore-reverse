// IDataWriter.h - 数据写入器接口
// 逆向自 libappcore.dylib (IDataWriter / FileDataWriter / MemoryWriter)
#pragma once
#include <cstddef>
#include <cstdint>

// 数据写入器接口
class IDataWriter {
public:
    virtual ~IDataWriter() = default;
    virtual ssize_t Write(const void* buf, size_t len) = 0;
    virtual void Flush() = 0;
    virtual void Close() = 0;
    virtual bool IsClosed() const = 0;
};

// 文件数据写入器
class FileDataWriter : public IDataWriter {
public:
    explicit FileDataWriter(const char* path);
    explicit FileDataWriter(int fd);
    ~FileDataWriter() override;

    ssize_t Write(const void* buf, size_t len) override;
    void Flush() override;
    void Close() override;
    bool IsClosed() const override;

private:
    int fd_;
    bool owns_fd_;
    bool closed_;
};

namespace writers {

// 内存写入器
class MemoryWriter : public IDataWriter {
public:
    MemoryWriter();
    ~MemoryWriter() override;

    ssize_t Write(const void* buf, size_t len) override;
    void Flush() override;
    void Close() override;
    bool IsClosed() const override;

    // 获取写入的数据
    const void* GetData() const;
    size_t GetSize() const;
    void* ReleaseData();  // 释放所有权

private:
    uint8_t* buffer_;
    size_t size_;
    size_t capacity_;
    bool closed_;
};

} // namespace writers
