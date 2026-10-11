// AgentKeyUnwrapper.cpp - 钥匙串密钥解包器实现
// 通过 AppleKeyStore (AKS) 服务解密硬件包装的密钥
// 参考: iOS 钥匙串解密机制, Keychain-Dumper
#include "keychain/AgentKeyUnwrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <CommonCrypto/CommonCrypto.h>

namespace keychain {

AgentKeyUnwrapper::AgentKeyUnwrapper()
    : aks_client_fd_(-1), initialized_(false) {
    memset(class_keys_, 0, sizeof(class_keys_));
    memset(class_keys_loaded_, 0, sizeof(class_keys_loaded_));
}

AgentKeyUnwrapper::~AgentKeyUnwrapper() {
    if (aks_client_fd_ >= 0) {
        close(aks_client_fd_);
    }
}

bool AgentKeyUnwrapper::Initialize() {
    if (initialized_) return true;

    // 启动 AppleKeyStore 客户端
    if (!StartAppleKeyStoreClient()) {
        printf("[-] AgentKeyUnwrapper: AKS client start failed\n");
        return false;
    }

    // 加载元数据密钥
    LoadMetadataKeys();

    initialized_ = true;
    printf("[+] AgentKeyUnwrapper: initialized\n");
    return true;
}

bool AgentKeyUnwrapper::UnwrapKey(const AKSWrappedKey* wrapped,
                                   uint8_t** out_key, size_t* out_len) {
    if (!initialized_ || !wrapped || !out_key || !out_len) return false;

    // 通过 AKS 解包硬件包装的密钥
    uint8_t unwrapped[64] = {0};
    size_t unwrapped_len = sizeof(unwrapped);

    if (!AKSUnwrapKey(wrapped->wrapped, wrapped->wrapped_len,
                      unwrapped, &unwrapped_len)) {
        printf("[-] AgentKeyUnwrapper: AKS unwrap failed\n");
        return false;
    }

    *out_key = (uint8_t*)malloc(unwrapped_len);
    memcpy(*out_key, unwrapped, unwrapped_len);
    *out_len = unwrapped_len;
    return true;
}

bool AgentKeyUnwrapper::DecryptSFAuthenticated(const SFAuthenticatedData* auth_data,
                                                const uint8_t* key, size_t key_len,
                                                uint8_t** out_plaintext, size_t* out_len) {
    if (!auth_data || !key || !out_plaintext || !out_len) return false;

    // AES-GCM 解密
    // SFAuthenticatedData 使用 AES-GCM 加密
    size_t plaintext_len = auth_data->len;
    uint8_t* plaintext = (uint8_t*)malloc(plaintext_len);
    if (!plaintext) return false;

    CCCryptorStatus status = CCCryptGCM(
        kCCDecrypt,
        key, key_len,
        NULL,  // IV 从 auth_data 读取
        auth_data->iv, 16,
        NULL, 0,  // AAD
        auth_data->data, auth_data->len,
        plaintext, plaintext_len,
        auth_data->tag, 16
    );

    if (status != kCCSuccess) {
        free(plaintext);
        printf("[-] AgentKeyUnwrapper: GCM decrypt failed (status=%d)\n", status);
        return false;
    }

    *out_plaintext = plaintext;
    *out_len = plaintext_len;
    return true;
}

bool AgentKeyUnwrapper::DecryptGCMFromKeyedArchive(const void* archive, size_t len,
                                                    const std::basic_string<uint8_t>& key,
                                                    std::basic_string<uint8_t>& out_plaintext) {
    // 从 KeyedArchive 中提取加密数据并解密
    // KeyedArchive 是 Apple 的序列化格式
    // 简化: 直接对数据做 GCM 解密
    if (!archive || len < 48) return false;  // 至少需要 IV(16) + tag(16) + data

    const uint8_t* data = (const uint8_t*)archive;
    SFAuthenticatedData auth;
    auth.iv = (uint8_t*)data;
    auth.tag = (uint8_t*)(data + 16);
    auth.data = (uint8_t*)(data + 32);
    auth.len = len - 32;

    uint8_t* plaintext = nullptr;
    size_t plaintext_len = 0;

    if (!DecryptSFAuthenticated(&auth, key.data(), key.size(),
                                &plaintext, &plaintext_len)) {
        return false;
    }

    out_plaintext.assign(plaintext, plaintext + plaintext_len);
    free(plaintext);
    return true;
}

void AgentKeyUnwrapper::LoadMetadataKeys() {
    // 加载各保护类的元数据密钥
    // 类密钥通过 AKS 从 keybag 中解包
    // 简化: 标记为未加载
    printf("[!] AgentKeyUnwrapper: metadata keys require AKS keybag access\n");
    for (int i = 0; i < 8; i++) {
        class_keys_loaded_[i] = false;
    }
}

const char* AgentKeyUnwrapper::GetRawKeychainPath() {
    return "/private/var/Keychains/keychain-2.db";
}

bool AgentKeyUnwrapper::StartAppleKeyStoreClient() {
    // AppleKeyStore 是 IOKit 服务
    // 需要通过 IOKit 框架连接
    // 简化: 返回 false (需要完整的 IOKit 实现)
    printf("[!] AgentKeyUnwrapper: AKS client requires IOKit AppleKeyStore userclient\n");
    printf("    This is hardware-specific and requires kernel privileges\n");
    return false;
}

bool AgentKeyUnwrapper::AKSUnwrapKey(const void* wrapped, size_t wrapped_len,
                                      uint8_t* unwrapped, size_t* unwrapped_len) {
    // AKS 解包原语
    // 通过 ioctl 或 IOKit 调用 AppleKeyStore
    // 简化: 返回 false
    if (aks_client_fd_ < 0) return false;
    return false;
}

} // namespace keychain
