// MCMLease.h - MCM 容器租约
// 逆向自 libappcore.dylib (MCMLease 类)
#pragma once
#import <Foundation/Foundation.h>

// MCM (Mach Container Manager) 容器类型
typedef NS_ENUM(NSInteger, MCMContainerClass) {
    MCMContainerClassApplication = 1,
    MCMContainerClassData = 2,
    MCMContainerClassGroup = 3,
    MCMContainerClassTemporary = 4,
    MCMContainerClassCache = 5,
};

// MCM 容器部分
typedef NS_ENUM(NSInteger, MCMContainerPart) {
    MCMContainerPartData = 1,
    MCMContainerPartBundle = 2,
    MCMContainerPartShared = 3,
};

// MCM 容器租约
// 激活后可以访问对应应用的沙箱目录
@interface MCMLease : NSObject

@property (nonatomic, readonly) NSString* identifier;     // bundle ID
@property (nonatomic, readonly) MCMContainerClass containerClass;
@property (nonatomic, readonly) NSURL* rootPath;          // 容器根路径
@property (nonatomic, readonly) BOOL active;

// 创建租约
+ (instancetype)leaseForClass:(MCMContainerClass)cls
                   identifier:(NSString*)identifier
                        group:(NSString*)group
                         part:(MCMContainerPart)part
                        flags:(uint32_t)flags
                        error:(NSError**)error;

// 激活租约 (获取访问权限)
- (BOOL)activate:(NSError**)error;

// 取消激活
- (void)invalidate;

@end

// MCM 共享 API
@interface MCMSharedAPI : NSObject

+ (instancetype)sharedAPI;

// 枚举所有容器标识符
- (NSArray<NSString*>*)enumerateIdentifiersForClass:(MCMContainerClass)cls;

// 枚举所有容器
- (NSArray<MCMLease*>*)enumerateContainersOfClass:(MCMContainerClass)cls;

@end

// 全局函数
void MCMFilzaStart(void);       // 启动 Filza 模式 (激活所有容器)
void MCMEnsureState(void);      // 确保 MCM 状态
void MCMBridge(void);           // MCM 桥接
