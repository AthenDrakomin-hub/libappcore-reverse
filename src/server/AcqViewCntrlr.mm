// AcqViewCntrlr.mm - 采集主控制器实现
// 逆向自 libappcore.dylib (AcqViewCntrlr_ 类)
#import "server/AcqViewCntrlr.h"
#import "acquisition/FilesystemServer.h"
#import "acquisition/KeychainServer.h"
#import "acquisition/MetadataServer.h"
#import "mcm/MCMLease.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

using namespace acquisition;

@implementation AcqViewCntrlr_

- (void)viewDidLoad {
    [super viewDidLoad];
    [self InitLogs];
    [self SetVersionText:[NSString stringWithFormat:@"App version: v%@", @"2.6.1"]];
    [self ShowSpinner:YES];

    // 后台执行采集
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        libappcore_do_acquisition();
    });
}

#pragma mark - 漏洞利用

- (void)Sploit {
    NSLog(@"Starting exploitation...");

    // 策略列表 (8种漏洞利用)
    NSArray* strategies = @[
        @"SockPortStrategy",
        @"TimeWasteStrategy",
        @"StreetRaceStrategy",
        @"BusyScheduleStrategy",
        @"CicutaVirosaStrategy",
        @"DanglingJoinStrategy",
        @"MadVMStrategy",
        @"DarkSwordStrategy",
    ];

    for (NSString* strategyName in strategies) {
        NSLog(@"Trying %@...", strategyName);

        // 检查是否支持
        // if (![strategy IsViable]) continue;

        // 执行漏洞利用
        // if ([strategy DoExploit]) {
        //     self.deviceExploited = YES;
        //     NSLog(@"Finished exploitation, going to escalate privileges.");
        //
        //     // 权限提升
        //     permissions::KernelUcredStealer stealer;
        //     stealer.Steal(kernel_mem, offset_provider);
        //
        //     // 启动 MCM Filza 模式
        //     MCMFilzaStart();
        //     return;
        // }
    }

    NSLog(@"All exploits failed.");
}

#pragma mark - 服务器

- (void)RunServer {
    // 查找可用端口
    int port = 1337;
    self.serverPort = port;
    NSLog(@"Running server on port %d", port);

    // 创建监听 socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);

    while (true) {
        NSLog(@"Waiting for connection on port %u", port);
        int client = accept(server_fd, NULL, NULL);
        if (client < 0) continue;

        if (!self.deviceExploited) {
            NSLog(@"Device not exploited, cannot start session.");
            close(client);
            continue;
        }

        // 读取客户端命令
        char cmd_buf[256] = {0};
        ssize_t n = recv(client, cmd_buf, sizeof(cmd_buf) - 1, 0);
        if (n <= 0) {
            NSLog(@"Failed to read command from client, cannot start session.");
            close(client);
            continue;
        }

        NSString* cmd = [NSString stringWithUTF8String:cmd_buf];
        NSLog(@"Read command from client: %@", cmd);

        if (![self ServerIsCmdSupported:cmd]) {
            [self ServerOnUnsupportedCmd:cmd];
            close(client);
            continue;
        }

        // 分发命令
        if ([cmd isEqualToString:@"filesystem"]) {
            [self FilesystemServerOnNewSession:client];
        } else if ([cmd isEqualToString:@"keychain"]) {
            [self KeychainServerOnNewSession:client];
        } else if ([cmd isEqualToString:@"metadata"]) {
            [self MetadataServerOnNewSession:client];
        }

        [self ServerOnFinishTransfer];
        close(client);
    }
}

#pragma mark - 命令处理

- (NSString*)ServerGetDeviceStatus {
    return self.deviceExploited ? @"exploited" : @"not_exploited";
}

- (NSString*)ServerGetAgentVersion {
    return @"2.6.1";
}

- (BOOL)ServerIsCmdSupported:(NSString*)cmd {
    NSSet* supported = [NSSet setWithArray:@[@"filesystem", @"keychain", @"metadata",
                                               @"status", @"version", @"upload"]];
    return [supported containsObject:cmd];
}

- (void)ServerOnUnsupportedCmd:(NSString*)cmd {
    NSLog(@"Unsupported command: %@", cmd);
}

- (void)ServerOnFinishTransfer {
    NSLog(@"Transfer finished.");
}

#pragma mark - 文件系统服务器

- (void)FilesystemServerOnNewSession:(int)client_fd {
    NSLog(@"Filesystem server new session");

    // 读取目标路径
    char path_buf[4096] = {0};
    recv(client_fd, path_buf, sizeof(path_buf), 0);
    NSString* path = [NSString stringWithUTF8String:path_buf];

    // 创建归档写入器 (通过 socket 发送 tar 流)
    struct archive* ar = archive_write_new();
    archive_write_add_filter_gzip(ar);
    archive_write_set_format_pax_restricted(ar);
    archive_write_open_fd(ar, client_fd);

    // 遍历并发送
    filesystem::FilesystemServer fs;
    filesystem::FilesystemTraversalPolicy policy;
    policy.rootPath = path.UTF8String;
    // fs.WriteFilesToArchive(policy, ar, observer);

    archive_write_close(ar);
    archive_write_free(ar);
}

- (void)FilesystemServerOnData:(int)client_fd data:(NSData*)data {
    send(client_fd, data.bytes, data.length, 0);
}

- (void)FilesystemServerOnFile:(NSString*)path {
    NSLog(@"Sending file: %@", path);
}

- (BOOL)FilesystemServerShouldStop {
    return NO;
}

#pragma mark - 钥匙串服务器

- (void)KeychainServerOnNewSession:(int)client_fd {
    NSLog(@"Keychain server new session, extracting keychain...");

    // 提取钥匙串并发送
    // NSData* keychainData = [self.keychainServer exportKeychainToXML];
    // send(client_fd, keychainData.bytes, keychainData.length, 0);
}

- (void)KeychainServerOnData:(int)client_fd data:(NSData*)data {
    send(client_fd, data.bytes, data.length, 0);
}

#pragma mark - 元数据服务器

- (void)MetadataServerOnNewSession:(int)client_fd {
    NSLog(@"Metadata server new session");
    // 采集并发送设备元数据
}

- (void)MetadataServerOnData:(int)client_fd data:(NSData*)data {
    send(client_fd, data.bytes, data.length, 0);
}

#pragma mark - 观察者

- (id)ServerGetFilesystemObserver { return nil; }
- (id)ServerGetKeychainObserver { return nil; }
- (id)ServerGetMetadataObserver { return nil; }

#pragma mark - UI

- (void)SetStateText:(NSString*)text {
    dispatch_async(dispatch_get_main_queue(), ^{
        self.lblState.text = text;
    });
}

- (void)SetVersionText:(NSString*)text {
    self.lblVersion.text = text;
}

- (void)ShowSpinner:(BOOL)show {
    if (show) [self.spinner startAnimating];
    else [self.spinner stopAnimating];
}

- (void)InitLogs {
    // 初始化日志系统 (SocketAppender 等)
    NSLog(@"[libappcore] Logs initialized");
}

@end
