// VersionedOffsetProvider.cpp - 多版本内核偏移表实现
// 偏移值参考: Dopamine/libjailbreak, Fugu15, XNU 源码
// 注意: 具体偏移需按 iOS 版本和设备型号验证
#include "kernel/VersionedOffsetProvider.h"
#include <sys/sysctl.h>
#include <stdio.h>
#include <string.h>
#include <memory>

namespace kernel {

// ============================================================================
// iOS 15 偏移表 (基于 Dopamine libjailbreak, A12+)
// ============================================================================
class OffsetProvideriOS15 : public IOffsetProvider {
public:
    uint32_t ProcProcRO() const override { return 0x20; }
    uint32_t ProcROUcred() const override { return 0x10; }
    uint32_t ProcROTask() const override { return 0x18; }
    uint32_t ProcPid() const override { return 0x68; }
    uint32_t ProcListNext() const override { return 0x08; }

    uint32_t UcredUID() const override { return 0x18; }
    uint32_t UcredRUID() const override { return 0x1c; }
    uint32_t UcredSVUID() const override { return 0x20; }
    uint32_t UcredGID() const override { return 0x24; }
    uint32_t UcredGroups() const override { return 0x28; }
    uint32_t LabelSandbox() const override { return 0x78; }
    uint32_t LabelAMFI() const override { return 0x80; }

    uint32_t TaskItkSpace() const override { return 0x388; }
    uint32_t TaskVMMap() const override { return 0x28; }

    uint32_t IpcPortKObject() const override { return 0x48; }
    uint32_t IpcPortRights() const override { return 0x18; }
    uint32_t IpcPortNSRequests() const override { return 0x58; }

    uint32_t VMMapHdr() const override { return 0x10; }
    uint32_t VMMapEntryLink() const override { return 0x08; }

    uint64_t KernelTextBase() const override { return 0; }  // 运行时确定
    uint64_t Allproc() const override { return 0; }         // 运行时确定
    uint64_t KernelSlide() const override { return 0; }     // 运行时确定

    int MajorVersion() const override { return 15; }
    const char* VersionString() const override { return "iOS 15.x"; }
};

// ============================================================================
// iOS 16 偏移表 (基于 Dopamine 2, A12+)
// ============================================================================
class OffsetProvideriOS16 : public IOffsetProvider {
public:
    uint32_t ProcProcRO() const override { return 0x20; }
    uint32_t ProcROUcred() const override { return 0x10; }
    uint32_t ProcROTask() const override { return 0x18; }
    uint32_t ProcPid() const override { return 0x68; }
    uint32_t ProcListNext() const override { return 0x08; }

    uint32_t UcredUID() const override { return 0x18; }
    uint32_t UcredRUID() const override { return 0x1c; }
    uint32_t UcredSVUID() const override { return 0x20; }
    uint32_t UcredGID() const override { return 0x24; }
    uint32_t UcredGroups() const override { return 0x28; }
    uint32_t LabelSandbox() const override { return 0x78; }
    uint32_t LabelAMFI() const override { return 0x80; }

    uint32_t TaskItkSpace() const override { return 0x388; }
    uint32_t TaskVMMap() const override { return 0x28; }

    uint32_t IpcPortKObject() const override { return 0x48; }
    uint32_t IpcPortRights() const override { return 0x18; }
    uint32_t IpcPortNSRequests() const override { return 0x58; }

    uint32_t VMMapHdr() const override { return 0x10; }
    uint32_t VMMapEntryLink() const override { return 0x08; }

    uint64_t KernelTextBase() const override { return 0; }
    uint64_t Allproc() const override { return 0; }
    uint64_t KernelSlide() const override { return 0; }

    int MajorVersion() const override { return 16; }
    const char* VersionString() const override { return "iOS 16.x"; }
};

// ============================================================================
// iOS 14 偏移表 (基于 Taurine/unc0ver)
// ============================================================================
class OffsetProvideriOS14 : public IOffsetProvider {
public:
    uint32_t ProcProcRO() const override { return 0x20; }
    uint32_t ProcROUcred() const override { return 0x10; }
    uint32_t ProcROTask() const override { return 0x18; }
    uint32_t ProcPid() const override { return 0x60; }
    uint32_t ProcListNext() const override { return 0x08; }

    uint32_t UcredUID() const override { return 0x18; }
    uint32_t UcredRUID() const override { return 0x1c; }
    uint32_t UcredSVUID() const override { return 0x20; }
    uint32_t UcredGID() const override { return 0x24; }
    uint32_t UcredGroups() const override { return 0x28; }
    uint32_t LabelSandbox() const override { return 0x78; }
    uint32_t LabelAMFI() const override { return 0x80; }

    uint32_t TaskItkSpace() const override { return 0x380; }
    uint32_t TaskVMMap() const override { return 0x28; }

    uint32_t IpcPortKObject() const override { return 0x40; }
    uint32_t IpcPortRights() const override { return 0x18; }
    uint32_t IpcPortNSRequests() const override { return 0x50; }

    uint32_t VMMapHdr() const override { return 0x10; }
    uint32_t VMMapEntryLink() const override { return 0x08; }

    uint64_t KernelTextBase() const override { return 0; }
    uint64_t Allproc() const override { return 0; }
    uint64_t KernelSlide() const override { return 0; }

    int MajorVersion() const override { return 14; }
    const char* VersionString() const override { return "iOS 14.x"; }
};

// ============================================================================
// iOS 13 偏移表 (基于 checkra1n/unc0ver)
// ============================================================================
class OffsetProvideriOS13 : public IOffsetProvider {
public:
    uint32_t ProcProcRO() const override { return 0x18; }
    uint32_t ProcROUcred() const override { return 0x10; }
    uint32_t ProcROTask() const override { return 0x18; }
    uint32_t ProcPid() const override { return 0x60; }
    uint32_t ProcListNext() const override { return 0x08; }

    uint32_t UcredUID() const override { return 0x18; }
    uint32_t UcredRUID() const override { return 0x1c; }
    uint32_t UcredSVUID() const override { return 0x20; }
    uint32_t UcredGID() const override { return 0x24; }
    uint32_t UcredGroups() const override { return 0x28; }
    uint32_t LabelSandbox() const override { return 0x78; }
    uint32_t LabelAMFI() const override { return 0x80; }

    uint32_t TaskItkSpace() const override { return 0x380; }
    uint32_t TaskVMMap() const override { return 0x28; }

    uint32_t IpcPortKObject() const override { return 0x40; }
    uint32_t IpcPortRights() const override { return 0x18; }
    uint32_t IpcPortNSRequests() const override { return 0x50; }

    uint32_t VMMapHdr() const override { return 0x10; }
    uint32_t VMMapEntryLink() const override { return 0x08; }

    uint64_t KernelTextBase() const override { return 0; }
    uint64_t Allproc() const override { return 0; }
    uint64_t KernelSlide() const override { return 0; }

    int MajorVersion() const override { return 13; }
    const char* VersionString() const override { return "iOS 13.x"; }
};

// ============================================================================
// iOS 12 偏移表 (基于 unc0ver/checkra1n)
// ============================================================================
class OffsetProvideriOS12 : public IOffsetProvider {
public:
    uint32_t ProcProcRO() const override { return 0x18; }
    uint32_t ProcROUcred() const override { return 0x10; }
    uint32_t ProcROTask() const override { return 0x18; }
    uint32_t ProcPid() const override { return 0x60; }
    uint32_t ProcListNext() const override { return 0x08; }

    uint32_t UcredUID() const override { return 0x18; }
    uint32_t UcredRUID() const override { return 0x1c; }
    uint32_t UcredSVUID() const override { return 0x20; }
    uint32_t UcredGID() const override { return 0x24; }
    uint32_t UcredGroups() const override { return 0x28; }
    uint32_t LabelSandbox() const override { return 0x78; }
    uint32_t LabelAMFI() const override { return 0x80; }

    uint32_t TaskItkSpace() const override { return 0x380; }
    uint32_t TaskVMMap() const override { return 0x28; }

    uint32_t IpcPortKObject() const override { return 0x40; }
    uint32_t IpcPortRights() const override { return 0x18; }
    uint32_t IpcPortNSRequests() const override { return 0x50; }

    uint32_t VMMapHdr() const override { return 0x10; }
    uint32_t VMMapEntryLink() const override { return 0x08; }

    uint64_t KernelTextBase() const override { return 0; }
    uint64_t Allproc() const override { return 0; }
    uint64_t KernelSlide() const override { return 0; }

    int MajorVersion() const override { return 12; }
    const char* VersionString() const override { return "iOS 12.x"; }
};

// ============================================================================
// VersionedOffsetProvider 实现
// ============================================================================

int VersionedOffsetProvider::DetectIOSVersion() {
    // 读取 kern.osversion
    char version[256] = {0};
    size_t size = sizeof(version);
    if (sysctlbyname("kern.osversion", version, &size, nullptr, 0) != 0) {
        printf("[-] Cannot detect iOS version\n");
        return 0;
    }

    // 解析主版本号
    int major = 0;
    if (sscanf(version, "%d", &major) == 1) {
        printf("[+] Detected iOS version: %s (major=%d)\n", version, major);
        return major;
    }

    return 0;
}

std::unique_ptr<IOffsetProvider> VersionedOffsetProvider::SelectOffsetTable(int major_version) {
    switch (major_version) {
        case 12: return std::make_unique<OffsetProvideriOS12>();
        case 13: return std::make_unique<OffsetProvideriOS13>();
        case 14: return std::make_unique<OffsetProvideriOS14>();
        case 15: return std::make_unique<OffsetProvideriOS15>();
        case 16: return std::make_unique<OffsetProvideriOS16>();
        default:
            printf("[-] Unsupported iOS version: %d\n", major_version);
            return nullptr;
    }
}

std::unique_ptr<IOffsetProvider> VersionedOffsetProvider::MakeOffsetProvider() {
    int major = DetectIOSVersion();
    if (major == 0) return nullptr;
    return SelectOffsetTable(major);
}

} // namespace kernel
