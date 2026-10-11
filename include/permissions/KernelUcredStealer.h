// KernelUcredStealer.h - 内核 ucred 窃取 (权限提升)
// 逆向自 libappcore.dylib (permissions::KernelUcredStealer)
#pragma once
#include "../kernel/IKernelMemory.h"
#include "../kernel/IOffsetProvider.h"

namespace permissions {

// 通过内核读写修改当前进程的 ucred, 提升为 root
class KernelUcredStealer {
public:
    KernelUcredStealer();
    ~KernelUcredStealer();

    // 执行权限提升
    // km: 内核内存读写, offsets: 偏移表
    void Steal(kernel::IKernelMemory* km, kernel::IOffsetProvider* offsets);

    // 找到当前进程的 proc_t
    uint64_t FindCurrentProc(kernel::IKernelMemory* km, kernel::IOffsetProvider* offsets);

    // 备份原始 ucred (用于恢复)
    void BackupUcred(kernel::IKernelMemory* km, uint64_t ucred);

    // 恢复原始 ucred
    void RestoreUcred(kernel::IKernelMemory* km, uint64_t ucred);

private:
    // 修改 UID/GID 为 0
    void PatchUID(kernel::IKernelMemory* km, uint64_t ucred, kernel::IOffsetProvider* off);

    // 修改组列表
    void PatchGroups(kernel::IKernelMemory* km, uint64_t ucred, kernel::IOffsetProvider* off);

    // 备份数据
    uint32_t orig_uid_;
    uint32_t orig_ruid_;
    uint32_t orig_svuid_;
    uint32_t orig_gid_;
    uint8_t orig_groups_[64];
};

} // namespace permissions
