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
    }
    return self;
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
    [req setValue:_acquisitionId forHTTPHeaderField:@"acquisition-id"];
    [req setValue:@"application/octet-stream" forHTTPHeaderField:@"Content-Type"];
    return req;
}

@end
