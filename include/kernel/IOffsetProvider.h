// IOffsetProvider.h - 内核结构偏移提供器接口
// 逆向自 libappcore.dylib (kernel::IOffsetProvider)
#pragma once
#include <cstdint>

namespace kernel {

// 内核结构体偏移表接口
// 不同 iOS 版本的内核结构体布局不同，需要对应版本的偏移表
class IOffsetProvider {
public:
    virtual ~IOffsetProvider() = default;

    // proc_t 结构体偏移
    virtual uint32_t ProcProcRO() const = 0;           // proc->p_proc_ro
    virtual uint32_t ProcROUcred() const = 0;          // proc_ro->p_ucred
    virtual uint32_t ProcROTask() const = 0;           // proc_ro->task
    virtual uint32_t ProcPid() const = 0;              // proc->p_pid
    virtual uint32_t ProcListNext() const = 0;         // proc->p_list_next

    // ucred 结构体偏移
    virtual uint32_t UcredUID() const = 0;             // ucred->cr_uid
    virtual uint32_t UcredRUID() const = 0;            // ucred->cr_ruid
    virtual uint32_t UcredSVUID() const = 0;           // ucred->cr_svuid
    virtual uint32_t UcredGID() const = 0;             // ucred->cr_gid
    virtual uint32_t UcredGroups() const = 0;          // ucred->cr_groups
    virtual uint32_t LabelSandbox() const = 0;         // ucred->cr_label (sandbox)
    virtual uint32_t LabelAMFI() const = 0;            // ucred->cr_label (AMFI)

    // task 结构体偏移
    virtual uint32_t TaskItkSpace() const = 0;         // task->itk_space
    virtual uint32_t TaskVMMap() const = 0;            // task->map

    // ipc_port 结构体偏移
    virtual uint32_t IpcPortKObject() const = 0;       // ipc_port->ip_kobject
    virtual uint32_t IpcPortRights() const = 0;        // ipc_port->ip_rights
    virtual uint32_t IpcPortNSRequests() const = 0;    // ipc_port->ip_nsrequest

    // vm_map 偏移
    virtual uint32_t VMMapHdr() const = 0;             // vm_map->hdr
    virtual uint32_t VMMapEntryLink() const = 0;       // vm_map_entry->links

    // 内核全局符号
    virtual uint64_t KernelTextBase() const = 0;       // 内核代码基址 (运行时确定)
    virtual uint64_t Allproc() const = 0;              // allproc 全局变量
    virtual uint64_t KernelSlide() const = 0;          // KASLR slide

    // iOS 版本信息
    virtual int MajorVersion() const = 0;
    virtual const char* VersionString() const = 0;
};

} // namespace kernel
