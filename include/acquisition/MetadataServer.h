// IOSDeviceInfo.h - iOS 设备信息采集
// 逆向自 libappcore.dylib (IOSDeviceInfo 类)
#pragma once
#import <Foundation/Foundation.h>

@interface IOSDeviceInfo : NSObject

// 设备名称
+ (NSString*)GetDeviceName;

// 设备型号 (iPhone12,1 等)
+ (NSString*)GetDeviceType;

// iOS 版本
+ (NSString*)GetIOSVersion;

// 序列号
+ (NSString*)GetSerialNumber;

// UDID
+ (NSString*)GetUDID;

// 锁屏状态
+ (BOOL)IsLockscreenOn;

// AAFramework 密钥获取
+ (NSString*)AAFrameworkGetKey:(NSString*)key;

// 设备是否支持采集
+ (BOOL)IsSupported;

@end

// 元数据服务器
@interface MetadataServer : NSObject

- (void)OnNewSession:(int)client_fd;
- (NSDictionary*)CollectMetadata;

@end

// 缩略图收集器
@interface ThumbCollector : NSObject

- (void)startCollection;
- (NSArray*)collectThumbnails:(NSString*)directory;

@end
