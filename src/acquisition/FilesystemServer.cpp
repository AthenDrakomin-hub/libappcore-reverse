// FilesystemServer.cpp - 文件系统提取服务器实现
// 基于 libarchive 标准用法
// 参考: libarchive 文档, iLEAPP 取证工具
#include "acquisition/FilesystemServer.h"
#include "common/IDataWriter.h"
#include <archive.h>
#include <archive_entry.h>
#include <dirent.h>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

namespace acquisition {
namespace filesystem {

FilesystemServer::FilesystemServer()
    : observer_(nullptr), should_stop_(false) {
}

FilesystemServer::~FilesystemServer() {
}

void FilesystemServer::OnNewSession(int client_fd) {
    // 这个方法由 AcqViewCntrlr 调用
    // 实际的归档写入在 WriteFilesToArchive 中完成
    should_stop_ = false;
}

void FilesystemServer::WriteFilesToArchive(const FilesystemTraversalPolicy& policy,
                                            struct archive* ar,
                                            FilesystemServerObserver* observer) {
    observer_ = observer;
    should_stop_ = false;

    if (policy.rootPath.empty()) {
        printf("[-] FilesystemServer: root path is empty\n");
        return;
    }

    printf("[+] FilesystemServer: traversing %s\n", policy.rootPath.c_str());
    TraverseAndWrite(policy.rootPath, ar, policy, observer);
    printf("[+] FilesystemServer: traversal complete\n");
}

void FilesystemServer::TraverseAndWrite(const std::string& path,
                                         struct archive* ar,
                                         const FilesystemTraversalPolicy& policy,
                                         FilesystemServerObserver* observer) {
    if (should_stop_ || (observer && observer->ShouldStop())) {
        return;
    }

    // 检查排除模式
    for (const auto& pattern : policy.excludePatterns) {
        if (path.find(pattern) != std::string::npos) {
            return;
        }
    }

    DIR* dir = opendir(path.c_str());
    if (!dir) {
        printf("[-] Cannot open directory: %s\n", path.c_str());
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (should_stop_) break;

        // 跳过 . 和 ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        // 跳过隐藏文件 (如果策略要求)
        if (!policy.includeHidden && entry->d_name[0] == '.') {
            continue;
        }

        std::string fullPath = path;
        if (fullPath.back() != '/') fullPath += '/';
        fullPath += entry->d_name;

        struct stat st;
        if (lstat(fullPath.c_str(), &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            // 写入目录头
            WriteDirectoryHeader(ar, fullPath, &st);
            // 递归遍历
            TraverseAndWrite(fullPath, ar, policy, observer);
        } else if (S_ISREG(st.st_mode)) {
            // 检查文件大小限制
            if (policy.maxFileSize > 0 && (size_t)st.st_size > policy.maxFileSize) {
                printf("[!] Skipping large file: %s (%lld bytes)\n",
                       fullPath.c_str(), (long long)st.st_size);
                continue;
            }
            WriteFileToArchive(ar, fullPath, &st, observer);
        } else if (S_ISLNK(st.st_mode)) {
            // 符号链接
            if (policy.followSymlinks) {
                struct stat target_st;
                if (stat(fullPath.c_str(), &target_st) == 0) {
                    if (S_ISDIR(target_st.st_mode)) {
                        WriteDirectoryHeader(ar, fullPath, &target_st);
                        TraverseAndWrite(fullPath, ar, policy, observer);
                    } else {
                        WriteFileToArchive(ar, fullPath, &target_st, observer);
                    }
                }
            } else {
                WriteSymlinkHeader(ar, fullPath, &st);
            }
        }
    }

    closedir(dir);
}

void FilesystemServer::WriteFileToArchive(struct archive* ar,
                                           const std::string& path,
                                           struct stat* st,
                                           FilesystemServerObserver* observer) {
    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, path.c_str());
    archive_entry_set_size(entry, st->st_size);
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, st->st_mode & 07777);
    archive_entry_set_uid(entry, st->st_uid);
    archive_entry_set_gid(entry, st->st_gid);
    archive_entry_set_mtime(entry, st->st_mtime, 0);
    archive_entry_set_atime(entry, st->st_atime, 0);
    archive_entry_set_ctime(entry, st->st_ctime, 0);

    archive_write_header(ar, entry);

    // 通知观察者
    if (observer) {
        observer->OnNewFile(path);
    }
    printf("[+] Sending file: %s (%lld bytes)\n", path.c_str(), (long long)st->st_size);

    // 写入文件内容
    FILE* f = fopen(path.c_str(), "rb");
    if (f) {
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
            archive_write_data(ar, buf, n);
            if (observer) {
                observer->OnData(buf, n);
            }
            if (should_stop_) break;
        }
        fclose(f);
    }

    archive_entry_free(entry);
}

void FilesystemServer::WriteDirectoryHeader(struct archive* ar,
                                              const std::string& path,
                                              struct stat* st) {
    struct archive_entry* entry = archive_entry_new();
    archive_entry_set_pathname(entry, path.c_str());
    archive_entry_set_filetype(entry, AE_IFDIR);
    archive_entry_set_perm(entry, st->st_mode & 07777);
    archive_entry_set_uid(entry, st->st_uid);
    archive_entry_set_gid(entry, st->st_gid);
    archive_entry_set_mtime(entry, st->st_mtime, 0);
    archive_write_header(ar, entry);
    archive_entry_free(entry);
}

void FilesystemServer::WriteSymlinkHeader(struct archive* ar,
                                            const std::string& path,
                                            struct stat* st) {
    char target[4096];
    ssize_t len = readlink(path.c_str(), target, sizeof(target) - 1);
    if (len > 0) {
        target[len] = '\0';

        struct archive_entry* entry = archive_entry_new();
        archive_entry_set_pathname(entry, path.c_str());
        archive_entry_set_filetype(entry, AE_IFLNK);
        archive_entry_set_symlink(entry, target);
        archive_entry_set_perm(entry, st->st_mode & 07777);
        archive_entry_set_mtime(entry, st->st_mtime, 0);
        archive_write_header(ar, entry);
        archive_entry_free(entry);
    }
}

void FilesystemServer::WriteFilesMetadata(const FilesystemTraversalPolicy& policy,
                                           IDataWriter* writer) {
    // 写入 XML 格式的元数据
    if (!writer) return;

    std::string header = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<filesystem_metadata>\n";
    writer->Write(header.c_str(), header.size());

    // 遍历收集元数据 (不写入文件内容)
    CollectMetadata(policy.rootPath, policy, writer);

    std::string footer = "</filesystem_metadata>\n";
    writer->Write(footer.c_str(), footer.size());
}

void FilesystemServer::CollectMetadata(const std::string& path,
                                        const FilesystemTraversalPolicy& policy,
                                        IDataWriter* writer) {
    DIR* dir = opendir(path.c_str());
    if (!dir) return;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;

        std::string fullPath = path + "/" + entry->d_name;
        struct stat st;
        if (lstat(fullPath.c_str(), &st) != 0) continue;

        // 写入 XML 条目
        char buf[1024];
        int n = snprintf(buf, sizeof(buf),
            "  <file path=\"%s\" size=\"%lld\" mode=\"%o\" uid=\"%d\" gid=\"%d\" "
            "mtime=\"%lld\" type=\"%s\"/>\n",
            fullPath.c_str(), (long long)st.st_size, st.st_mode & 07777,
            st.st_uid, st.st_gid, (long long)st.st_mtime,
            S_ISDIR(st.st_mode) ? "directory" :
            S_ISLNK(st.st_mode) ? "symlink" : "file");
        writer->Write(buf, n);

        if (S_ISDIR(st.st_mode)) {
            CollectMetadata(fullPath, policy, writer);
        }
    }
    closedir(dir);
}

bool FilesystemServer::ShouldStop() const {
    return should_stop_;
}

} // namespace filesystem
} // namespace acquisition
