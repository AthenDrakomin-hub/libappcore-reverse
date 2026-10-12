// AcqViewCntrlr.h - 采集主控制器
// 逆向自 libappcore.dylib (AcqViewCntrlr_ 类)
#pragma once
#import <UIKit/UIKit.h>
#import "upload/SimpleUploader.h"

@class FilesystemServer;
@class KeychainServer;
@class MetadataServer;

// 采集视图控制器
// 协调漏洞利用、服务器启动、数据提取和上传
@interface AcqViewCntrlr_ : UIViewController

@property (nonatomic, strong) UILabel* lblState;
@property (nonatomic, strong) UILabel* lblVersion;
@property (nonatomic, strong) UIActivityIndicatorView* spinner;

@property (nonatomic, strong) FilesystemServer* filesystemServer;
@property (nonatomic, strong) KeychainServer* keychainServer;
@property (nonatomic, strong) id metadataServer;
@property (nonatomic, strong) SimpleUploader* uploader;

@property (nonatomic, assign) BOOL deviceExploited;
@property (nonatomic, assign) int serverPort;

// 视图加载
- (void)viewDidLoad;

// 运行漏洞利用
- (void)Sploit;

// 启动本地服务器 (主循环)
- (void)RunServer;

// === 服务器命令处理 ===
- (NSString*)ServerGetDeviceStatus;
- (NSString*)ServerGetAgentVersion;
- (BOOL)ServerIsCmdSupported:(NSString*)cmd;
- (void)ServerOnUnsupportedCmd:(NSString*)cmd;

// === 连接处理 ===
- (void)ServerOnNewConnection:(int)client_fd;
- (void)ServerOnConnectionError:(NSError*)error;
- (void)ServerOnFinishTransfer;

// === 文件系统服务器 ===
- (void)FilesystemServerOnNewSession:(int)client_fd;
- (void)FilesystemServerOnData:(int)client_fd data:(NSData*)data;
- (void)FilesystemServerOnFile:(NSString*)path;
- (BOOL)FilesystemServerShouldStop;

// === 钥匙串服务器 ===
- (void)KeychainServerOnNewSession:(int)client_fd;
- (void)KeychainServerOnData:(int)client_fd data:(NSData*)data;

// === 元数据服务器 ===
- (void)MetadataServerOnNewSession:(int)client_fd;
- (void)MetadataServerOnData:(int)client_fd data:(NSData*)data;

// === 观察者获取 ===
- (id)ServerGetFilesystemObserver;
- (id)ServerGetKeychainObserver;
- (id)ServerGetMetadataObserver;

// === UI 更新 ===
- (void)SetStateText:(NSString*)text;
- (void)SetVersionText:(NSString*)text;
- (void)ShowSpinner:(BOOL)show;

// === 日志 ===
- (void)InitLogs;

@end
