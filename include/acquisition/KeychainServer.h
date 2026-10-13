// KeychainServer.h - 钥匙串提取服务器
// 逆向自 libappcore.dylib (acquisition + keychain 命名空间)
// 完整解密: AKS KeyUnwrap + AES-256-GCM
#pragma once
#include <string>
#include <sqlite3.h>

namespace keychain { class AgentKeyUnwrapper; }

namespace keychain {

// 钥匙串版本枚举
enum KeychainVersion {
    kKeychainV3 = 3,    // iOS 10 及更早
    kKeychainV9 = 9,    // iOS 11-13
    kKeychainV11 = 11,  // iOS 14+
};

// 钥匙串项
struct KeychainItem {
    std::string service;
    std::string account;
    std::string data;        // 解密后的数据 (base64)
    std::string accessGroup;
    uint32_t protocol;
    uint32_t type;
    std::string label;
    std::string description;
};

// 钥匙串服务器观察者
class KeychainServerObserver {
public:
    virtual ~KeychainServerObserver() = default;
    virtual void OnNewSession(int client_fd) = 0;
    virtual void OnData(const void* data, size_t len) = 0;
};

// 钥匙串服务器
class KeychainServer {
public:
    KeychainServer();
    ~KeychainServer();

    // 处理新会话
    void OnNewSession(int client_fd);

    // 提取原始钥匙串数据库
    void GetRawKeychain(const char* path, class IDataWriter* writer, ...);

    // 复制钥匙串数据库到临时目录
    void CopyKeychainDBToTmpDirect();

    // 导出钥匙串为 XML
    std::string ExportKeychainToXML();

    // 获取钥匙串数据库版本
    KeychainVersion GetKeychainDBVersion(sqlite3* db);

    // 获取钥匙串项数量
    int GetKeychainDbItemsCount(sqlite3* db);

private:
    // 导出单个表为 XML 字符串
    std::string ExportTableToXMLString(sqlite3* db, const char* table, bool decrypt);

    // 解密钥匙串项 (入口)
    std::string DecryptKeychainItem(const void* encrypted, size_t len);

    // iOS 4 解密 (AES-CBC, 硬编码密钥)
    std::string DecryptBlobV4(const uint8_t* data, size_t len);

    // iOS 5+ 解密 (AKS unwrap + AES-GCM)
    std::string DecryptBlobV5Plus(const uint8_t* data, size_t len, uint32_t version);

    // Base64 编码
    static std::string Base64Encode(const void* data, size_t len);

    KeychainVersion version_;
    std::string tmp_dir_;
    AgentKeyUnwrapper* unwrapper_;

    // 解密结果缓存 (避免重复 AKS 调用)
    std::string cached_xml_;
    time_t cache_timestamp_;
    bool cache_valid_;
};

} // namespace keychain
