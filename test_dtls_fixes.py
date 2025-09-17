#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试DTLS密钥派生和加解密修复
"""

import hashlib
import hmac
import struct
import os
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class DTLSKeyTest:
    def __init__(self):
        # 测试数据
        self.pre_master_secret = os.urandom(48)
        self.client_random = os.urandom(32)
        self.server_random = os.urandom(32)
        self.master_secret = None
        
        # 密钥材料
        self.client_write_mac_key = None
        self.server_write_mac_key = None
        self.client_write_key = None
        self.server_write_key = None
        
    def _prf(self, secret: bytes, seed: bytes, length: int) -> bytes:
        """TLS 1.2伪随机函数 - 始终使用SHA-256"""
        result = b''
        a = seed
        
        # TLS 1.2/DTLS 1.2的PRF始终使用SHA-256
        hash_func = hashlib.sha256
        
        while len(result) < length:
            a = hmac.new(secret, a, hash_func).digest()
            result += hmac.new(secret, a + seed, hash_func).digest()
        return result[:length]
    
    def derive_master_secret(self):
        """派生主密钥"""
        seed = b"master secret" + self.client_random + self.server_random
        self.master_secret = self._prf(self.pre_master_secret, seed, 48)
        print(f"主密钥派生完成: {self.master_secret.hex()[:32]}...")
        
    def derive_key_material(self):
        """派生密钥材料 - 修复版本"""
        if not self.master_secret:
            raise ValueError("需要先派生主密钥")
        
        # 密钥材料种子
        seed = b"key expansion" + self.server_random + self.client_random
        
        # AES-128-CBC + HMAC-SHA1
        key_length = 16     # AES-128密钥长度
        mac_length = 20     # HMAC-SHA1密钥长度
        # 注意：TLS 1.2的CBC模式不使用固定IV
        
        # 密钥材料顺序（RFC 5246）: 
        # client_write_MAC_key + server_write_MAC_key + 
        # client_write_key + server_write_key
        key_material_length = 2 * (mac_length + key_length)
        key_material = self._prf(self.master_secret, seed, key_material_length)
        
        # 分配密钥
        offset = 0
        self.client_write_mac_key = key_material[offset:offset+mac_length]
        offset += mac_length
        self.server_write_mac_key = key_material[offset:offset+mac_length]
        offset += mac_length
        self.client_write_key = key_material[offset:offset+key_length]
        offset += key_length
        self.server_write_key = key_material[offset:offset+key_length]
        
        print(f"密钥材料派生完成:")
        print(f"  客户端MAC密钥: {self.client_write_mac_key.hex()[:16]}...")
        print(f"  服务端MAC密钥: {self.server_write_mac_key.hex()[:16]}...")
        print(f"  客户端加密密钥: {self.client_write_key.hex()[:16]}...")
        print(f"  服务端加密密钥: {self.server_write_key.hex()[:16]}...")
        
    def test_cbc_encrypt_decrypt(self):
        """测试CBC加解密"""
        test_data = b"Hello DTLS World! This is a test message."
        content_type = 22  # HANDSHAKE
        sequence_number = 0
        
        print(f"\n测试数据: {test_data}")
        
        # 1. 加密（客户端发送）
        encrypted = self._encrypt_cbc(content_type, test_data, sequence_number, 
                                    self.client_write_key, self.client_write_mac_key)
        print(f"加密结果长度: {len(encrypted)}")
        
        # 2. 解密（服务端接收）
        decrypted = self._decrypt_cbc(content_type, encrypted, sequence_number,
                                    self.client_write_key, self.client_write_mac_key)
        print(f"解密结果: {decrypted}")
        
        # 验证
        if decrypted == test_data:
            print("✅ CBC加解密测试成功!")
        else:
            print("❌ CBC加解密测试失败!")
            print(f"期望: {test_data}")
            print(f"实际: {decrypted}")
            
    def _encrypt_cbc(self, content_type: int, data: bytes, sequence_number: int,
                     write_key: bytes, mac_key: bytes) -> bytes:
        """CBC加密"""
        # 1. 计算HMAC-SHA1
        seq_num_8bytes = struct.pack("!Q", sequence_number)
        mac_data = (seq_num_8bytes +
                   struct.pack("!BHH", content_type, 0xFEFD, len(data)) +  # DTLS 1.2
                   data)
        
        h = hmac.new(mac_key, mac_data, hashlib.sha1)
        mac = h.digest()
        
        # 2. 添加填充 (PKCS#7)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data + mac) + padder.finalize()
        
        # 3. 生成随机IV
        iv = os.urandom(16)
        
        # 4. AES-CBC加密
        cipher = Cipher(algorithms.AES(write_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 5. 返回 IV + 加密数据
        return iv + encrypted_data
        
    def _decrypt_cbc(self, content_type: int, encrypted_data: bytes, sequence_number: int,
                     write_key: bytes, mac_key: bytes) -> bytes:
        """CBC解密"""
        if len(encrypted_data) < 16:
            raise ValueError("加密数据太短")
        
        # 1. 提取IV和密文
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # 2. AES-CBC解密
        cipher = Cipher(algorithms.AES(write_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 3. 移除填充
        unpadder = padding.PKCS7(128).unpadder()
        data_with_mac = unpadder.update(padded_data) + unpadder.finalize()
        
        # 4. 分离数据和MAC
        if len(data_with_mac) < 20:
            raise ValueError("解密数据太短，无法包含MAC")
        
        data = data_with_mac[:-20]
        received_mac = data_with_mac[-20:]
        
        # 5. 验证MAC
        seq_num_8bytes = struct.pack("!Q", sequence_number)
        mac_data = (seq_num_8bytes +
                   struct.pack("!BHH", content_type, 0xFEFD, len(data)) +
                   data)
        
        h = hmac.new(mac_key, mac_data, hashlib.sha1)
        computed_mac = h.digest()
        
        if received_mac != computed_mac:
            raise ValueError("MAC验证失败")
        
        return data

def main():
    print("DTLS密钥派生和加解密测试")
    print("=" * 50)
    
    test = DTLSKeyTest()
    
    # 1. 派生主密钥
    test.derive_master_secret()
    
    # 2. 派生密钥材料
    test.derive_key_material()
    
    # 3. 测试CBC加解密
    test.test_cbc_encrypt_decrypt()
    
    print("\n测试完成!")

if __name__ == "__main__":
    main()
