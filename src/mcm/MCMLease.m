// MCMLease.m - MCM 容器租约实现
// 逆向自 libappcore.dylib (MCMLease 类)
// 参考: iOS 容器管理机制, KernBypass
#import "mcm/MCMLease.h"
#import <Foundation/Foundation.h>

@implementation MCMLease

- (instancetype)initWithClass:(MCMContainerClass)cls
                   identifier:(NSString*)identifier
                        group:(NSString*)group
                         part:(MCMContainerPart)part
                        flags:(uint32_t)flags {
    self = [super init];
    if (self) {
        _containerClass = cls;
        _identifier = [identifier copy];
        _active = NO;

        // 构造容器根路径
        NSString* base = @"/var/mobile/Containers";
        NSString* classDir;
        switch (cls) {
            case MCMContainerClassApplication: classDir = @"Application"; break;
            case MCMContainerClassData: classDir = @"Data/Application"; break;
            case MCMContainerClassGroup: classDir = @"Data/Group"; break;
            case MCMContainerClassTemporary: classDir = @"Data/Temporary"; break;
            case MCMContainerClassCache: classDir = @"Data/Caches"; break;
            default: classDir = @"Data"; break;
        }

        if (group && group.length > 0) {
            _rootPath = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/%@/%@", base, classDir, group]];
        } else {
            _rootPath = [NSURL fileURLWithPath:[NSString stringWithFormat:@"%@/%@/%@", base, classDir, identifier]];
        }
    }
    return self;
}

+ (instancetype)leaseForClass:(MCMContainerClass)cls
                   identifier:(NSString*)identifier
                        group:(NSString*)group
                         part:(MCMContainerPart)part
                        flags:(uint32_t)flags
                        error:(NSError**)error {
    return [[MCMLease alloc] initWithClass:cls identifier:identifier group:group part:part flags:flags];
}

- (BOOL)activate:(NSError**)error {
    // 激活租约: 通过 MCM 守护进程获取容器访问权限
    // 真实实现需要与 com.apple.mobilecontainermanager 通信
    // 简化: 检查路径是否存在
    NSFileManager* fm = [NSFileManager defaultManager];
    BOOL isDir = NO;
    BOOL exists = [fm fileExistsAtPath:_rootPath.path isDirectory:&isDir];

    if (!exists) {
        if (error) {
            *error = [NSError errorWithDomain:@"MCMLease" code:404
                                     userInfo:@{NSLocalizedDescriptionKey: @"Container not found"}];
        }
        return NO;
    }

    _active = YES;
    NSLog(@"MCMLease activated: %@", _rootPath.path);
    return YES;
}

- (void)invalidate {
    _active = NO;
    NSLog(@"MCMLease invalidated: %@", _identifier);
}

@end

@implementation MCMSharedAPI

+ (instancetype)sharedAPI {
    static MCMSharedAPI* instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[MCMSharedAPI alloc] init];
    });
    return instance;
}

- (NSArray<NSString*>*)enumerateIdentifiersForClass:(MCMContainerClass)cls {
    // 枚举指定类型的所有容器标识符
    NSString* base = @"/var/mobile/Containers";
    NSString* classDir;
    switch (cls) {
        case MCMContainerClassApplication: classDir = @"Application"; break;
        case MCMContainerClassData: classDir = @"Data/Application"; break;
        case MCMContainerClassGroup: classDir = @"Data/Group"; break;
        default: classDir = @"Data"; break;
    }

    NSString* path = [base stringByAppendingPathComponent:classDir];
    NSFileManager* fm = [NSFileManager defaultManager];
    NSArray* contents = [fm contentsOfDirectoryAtPath:path error:nil];
    return contents ?: @[];
}

- (NSArray<MCMLease*>*)enumerateContainersOfClass:(MCMContainerClass)cls {
    NSArray* identifiers = [self enumerateIdentifiersForClass:cls];
    NSMutableArray* leases = [NSMutableArray array];
    for (NSString* ident in identifiers) {
        MCMLease* lease = [MCMLease leaseForClass:cls identifier:ident group:nil
                                              part:MCMContainerPartData flags:0 error:nil];
        [leases addObject:lease];
    }
    return leases;
}

@end

// 全局函数实现
void MCMFilzaStart(void) {
    // Filza 模式: 激活所有容器, 获取全文件系统访问
    NSLog(@"MCMFilzaStart: enabling full filesystem access");

    MCMSharedAPI* api = [MCMSharedAPI sharedAPI];
    NSArray* classes = @[@(MCMContainerClassApplication),
                         @(MCMContainerClassData),
                         @(MCMContainerClassGroup)];

    for (NSNumber* clsNum in classes) {
        NSArray* leases = [api enumerateContainersOfClass:[clsNum integerValue]];
        for (MCMLease* lease in leases) {
            [lease activate:nil];
        }
    }
}

void MCMEnsureState(void) {
    NSLog(@"MCMEnsureState: ensuring MCM state");
}

void MCMBridge(void) {
    NSLog(@"MCMBridge: MCM bridge initialized");
}
