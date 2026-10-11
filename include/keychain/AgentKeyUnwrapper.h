// AgentKeyUnwrapper.h - 钥匙串密钥解包器
// 逆向自 libappcore.dylib (keychain::AgentKeyUnwrapper)
#pragma once
#include <cstdint>
#include <string>

namespace keychain {

// AKS (Apple KeyStore) 包装密钥
struct AKSWrappedKey {
    uint8_t wrapped[128];
    size_t wrapped_len;
    uint32_t keyclass;      // 密钥类 (NSFileProtectionKey)
    uint32_t wrap_type;     // 包装类型 (v3/v9/v11)
};

// SFAuthenticated 加密数据
struct SFAuthenticatedData {
    uint8_t* data;
    size_t len;
    uint8_t iv[16];
    uint8_t tag[16];
};

// 钥匙串密钥解包器
// 通过 AppleKeyStore 服务解密硬件包装的密钥
class AgentKeyUnwrapper {
public:
    AgentKeyUnwrapper();
    ~AgentKeyUnwrapper();

    // 初始化 (启动 AppleKeyStore 客户端)
    bool Initialize();

    // 是否已初始化
    bool IsInitialized() const { return initialized_; }

    // 解包 AKS 包装密钥
    bool UnwrapKey(const AKSWrappedKey* wrapped, uint8_t** out_key, size_t* out_len);

    // 解密 SFAuthenticated 数据 (GCM)
    bool DecryptSFAuthenticated(const SFAuthenticatedData* auth_data,
                                const uint8_t* key, size_t key_len,
                                uint8_t** out_plaintext, size_t* out_len);

    // GCM 解密 (从 KeyedArchive)
    bool DecryptGCMFromKeyedArchive(const void* archive, size_t len,
                                    const std::basic_string<uint8_t>& key,
                                    std::basic_string<uint8_t>& out_plaintext);

    // 加载元数据密钥 (类密钥)
    void LoadMetadataKeys();

    // 从 keychain-2.db 的 metadatakeys 表加载并解包所有 class key
    // sqlite_handle: sqlite3* 数据库句柄
    bool LoadMetadataKeysFromDB(void* sqlite_handle);

    // 获取已加载的 class key (返回 32 字节 AES-256 key)
    const uint8_t* GetClassKey(int keyclass) const;

    // 解包指定 keyclass 的密钥
    bool UnwrapKeyWithClass(uint32_t keyclass,
                            const void* wrapped, size_t wrapped_len,
                            uint8_t* unwrapped, size_t* unwrapped_len);

    // 获取设备锁屏状态 (0x1=从未解锁, 0x4=已解锁, 0x5=已锁定, 0x6=无密码)
    int GetLockState();

    // 获取原始钥匙串数据库路径
    static const char* GetRawKeychainPath();

private:
    // 启动 AppleKeyStore 客户端
    bool StartAppleKeyStoreClient();

    // AKS 解包原语
    bool AKSUnwrapKey(const void* wrapped, size_t wrapped_len,
                      uint8_t* unwrapped, size_t* unwrapped_len);

    int aks_client_fd_;
    bool initialized_;

    // 类密钥缓存
    uint8_t class_keys_[8][32];
    bool class_keys_loaded_[8];
};

} // namespace keychain
