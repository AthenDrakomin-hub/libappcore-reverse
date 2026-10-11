// IDataWriter.cpp - 数据写入器实现
#include "common/IDataWriter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ============================================================================
// FileDataWriter 实现
// ============================================================================

FileDataWriter::FileDataWriter(const char* path)
    : fd_(-1), owns_fd_(true), closed_(false) {
    if (path) {
        fd_ = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    }
}

FileDataWriter::FileDataWriter(int fd)
    : fd_(fd), owns_fd_(false), closed_(false) {
}

FileDataWriter::~FileDataWriter() {
    Close();
}

ssize_t FileDataWriter::Write(const void* buf, size_t len) {
    if (closed_ || fd_ < 0 || !buf) return -1;
    return write(fd_, buf, len);
}

void FileDataWriter::Flush() {
    if (fd_ >= 0) {
        fsync(fd_);
    }
}

void FileDataWriter::Close() {
    if (!closed_ && fd_ >= 0 && owns_fd_) {
        close(fd_);
    }
    closed_ = true;
}

bool FileDataWriter::IsClosed() const {
    return closed_;
}

// ============================================================================
// MemoryWriter 实现
// ============================================================================

namespace writers {

MemoryWriter::MemoryWriter()
    : buffer_(nullptr), size_(0), capacity_(0), closed_(false) {
    capacity_ = 4096;
    buffer_ = (uint8_t*)malloc(capacity_);
}

MemoryWriter::~MemoryWriter() {
    if (buffer_) {
        free(buffer_);
    }
}

ssize_t MemoryWriter::Write(const void* buf, size_t len) {
    if (closed_ || !buf) return -1;

    // 扩容
    if (size_ + len > capacity_) {
        while (size_ + len > capacity_) {
            capacity_ *= 2;
        }
        buffer_ = (uint8_t*)realloc(buffer_, capacity_);
    }

    memcpy(buffer_ + size_, buf, len);
    size_ += len;
    return (ssize_t)len;
}

void MemoryWriter::Flush() {
    // 内存写入器无需 flush
}

void MemoryWriter::Close() {
    closed_ = true;
}

bool MemoryWriter::IsClosed() const {
    return closed_;
}

const void* MemoryWriter::GetData() const {
    return buffer_;
}

size_t MemoryWriter::GetSize() const {
    return size_;
}

void* MemoryWriter::ReleaseData() {
    void* data = buffer_;
    buffer_ = nullptr;
    size_ = 0;
    capacity_ = 0;
    return data;
}

} // namespace writers
