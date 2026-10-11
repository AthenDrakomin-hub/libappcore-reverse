// KeychainServer.cpp - 钥匙串提取服务器实现
// 基于: Keychain-Dumper (https://github.com/ptoomey3/Keychain-Dumper)
// 原理: 读取 keychain-2.db, 查询 genp/inet/cert 表, 通过 AKS 解密
#include "acquisition/KeychainServer.h"
#include "common/IDataWriter.h"
#include "keychain/AgentKeyUnwrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sqlite3.h>

namespace keychain {

KeychainServer::KeychainServer()
    : version_(kKeychainV11), tmp_dir_("/tmp/keychain_extract") {
}

KeychainServer::~KeychainServer() {
}

void KeychainServer::OnNewSession(int client_fd) {
    // 这个方法由 AcqViewCntrlr 调用
    // 实际导出在 ExportKeychainToXML 中完成
    printf("[+] KeychainServer: new session on fd %d\n", client_fd);
}

void KeychainServer::GetRawKeychain(const char* path, IDataWriter* writer, ...) {
    if (!path || !writer) return;

    // 直接复制原始 keychain-2.db
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
    printf("[+] Raw keychain copied\n");
}

void KeychainServer::CopyKeychainDBToTmpDirect() {
    // 钥匙串数据库路径 (iOS)
    const char* src_paths[] = {
        "/private/var/Keychains/keychain-2.db",
        "/var/Keychains/keychain-2.db",
        nullptr
    };

    // 创建临时目录
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

    // 复制数据库到临时目录
    CopyKeychainDBToTmpDirect();

    std::string db_path = tmp_dir_ + "/keychain-2.db";
    sqlite3* db = nullptr;
    if (sqlite3_open(db_path.c_str(), &db) != SQLITE_OK) {
        result += "  <error>Cannot open keychain database</error>\n";
        result += "</keychain_export>\n";
        return result;
    }

    // 检测版本
    version_ = GetKeychainDBVersion(db);
    result += "  <version>" + std::to_string(version_) + "</version>\n";
    result += "  <item_count>" + std::to_string(GetKeychainDbItemsCount(db)) + "</item_count>\n";

    // 导出各表
    const char* tables[] = {"genp", "inet", "cert", "keys", nullptr};
    for (int i = 0; tables[i]; i++) {
        // 简化: 只导出元数据, 不解密 (需要 AKS)
        result += "  <table name=\"" + std::string(tables[i]) + "\">\n";

        std::string sql = "SELECT rowid, svce, acct, agrp FROM " + std::string(tables[i]) + " LIMIT 100;";
        sqlite3_stmt* stmt = nullptr;
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                int rowid = sqlite3_column_int(stmt, 0);
                const unsigned char* svce = sqlite3_column_text(stmt, 1);
                const unsigned char* acct = sqlite3_column_text(stmt, 2);
                const unsigned char* agrp = sqlite3_column_text(stmt, 3);

                result += "    <item id=\"" + std::to_string(rowid) + "\">\n";
                if (svce) result += "      <service>" + std::string((const char*)svce) + "</service>\n";
                if (acct) result += "      <account>" + std::string((const char*)acct) + "</account>\n";
                if (agrp) result += "      <access_group>" + std::string((const char*)agrp) + "</access_group>\n";
                result += "    </item>\n";
            }
            sqlite3_finalize(stmt);
        }
        result += "  </table>\n";
    }

    sqlite3_close(db);
    result += "</keychain_export>\n";
    return result;
}

KeychainVersion KeychainServer::GetKeychainDBVersion(sqlite3* db) {
    if (!db) return kKeychainV11;

    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, "SELECT value FROM tsettings WHERE key='version';", -1, &stmt, nullptr) == SQLITE_OK) {
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
    const char* tables[] = {"genp", "inet", "cert", nullptr};
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

    std::string sql = "SELECT * FROM " + std::string(table) + " LIMIT 500;";
    sqlite3_stmt* stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) return;

    int col_count = sqlite3_column_count(stmt);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        std::string row = "<row>";
        for (int i = 0; i < col_count; i++) {
            const char* col_name = sqlite3_column_name(stmt, i);
            const unsigned char* val = sqlite3_column_text(stmt, i);
            if (val) {
                row += "<" + std::string(col_name) + ">" +
                       std::string((const char*)val) + "</" + std::string(col_name) + ">";
            }
        }
        row += "</row>\n";
        writer->Write(row.c_str(), row.size());
    }
    sqlite3_finalize(stmt);
}

std::string KeychainServer::DecryptKeychainItem(const void* encrypted, size_t len) {
    // 钥匙串解密需要 AKS (Apple KeyStore) 硬件
    // 完整实现需要 AgentKeyUnwrapper
    // 这里返回 base64 编码的加密数据
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const uint8_t* data = (const uint8_t*)encrypted;
    std::string result;

    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = data[i] << 16;
        if (i + 1 < len) n |= data[i + 1] << 8;
        if (i + 2 < len) n |= data[i + 2];
        result += b64[(n >> 18) & 63];
        result += b64[(n >> 12) & 63];
        result += (i + 1 < len) ? b64[(n >> 6) & 63] : '=';
        result += (i + 2 < len) ? b64[n & 63] : '=';
    }
    return result;
}

} // namespace keychain
