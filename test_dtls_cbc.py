#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端CBC模式测试脚本
"""

import logging
import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def test_cbc_encryption():
    """测试CBC加密模式"""
    print("=== DTLS客户端CBC模式测试 ===")
    
    # 创建DTLS客户端
    client = CompleteDTLSClient()
    
    # 模拟设置CBC密码套件
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    
    # 重新初始化记录层以支持CBC
    from dtls_client_complete import DTLSRecord
    client.record_layer = DTLSRecord(client.cipher_suite)
    
    # 模拟密钥材料
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.master_secret = b'C' * 48
    
    print(f"密码套件: {hex(client.cipher_suite)}")
    print(f"客户端随机数: {client.client_random.hex()}")
    print(f"服务器随机数: {client.server_random.hex()}")
    print(f"主密钥: {client.master_secret.hex()}")
    
    # 派生密钥材料
    try:
        client.derive_key_material()
        print("\n=== 密钥派生成功 ===")
        print(f"客户端写密钥: {client.client_write_key.hex()}")
        print(f"客户端写IV: {client.client_write_iv.hex()}")
        print(f"客户端写MAC密钥: {client.client_write_mac_key.hex()}")
        
        # 启用加密
        mac_key = getattr(client, 'client_write_mac_key', None)
        client.record_layer.enable_encryption(
            client.client_write_key, 
            client.client_write_iv, 
            mac_key
        )
        
        print("\n=== 加密测试 ===")
        
        # 测试数据
        test_data = b"Hello, DTLS CBC Mode!"
        print(f"原始数据: {test_data}")
        print(f"原始数据长度: {len(test_data)}")
        
        # 加密数据
        encrypted = client.record_layer._encrypt_data_cbc(
            DTLSConstants.APPLICATION_DATA, 
            test_data
        )
        
        print(f"加密后数据: {encrypted.hex()}")
        print(f"加密后长度: {len(encrypted)}")
        
        # 分析加密结果
        if len(encrypted) >= 16:
            iv = encrypted[:16]
            ciphertext = encrypted[16:]
            print(f"IV: {iv.hex()}")
            print(f"密文: {ciphertext.hex()}")
        
        print("\n=== CBC模式测试完成 ===")
        
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

def test_gcm_encryption():
    """测试GCM加密模式"""
    print("\n=== DTLS客户端GCM模式测试 ===")
    
    # 创建DTLS客户端
    client = CompleteDTLSClient()
    
    # 模拟设置GCM密码套件
    client.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
    
    # 重新初始化记录层
    from dtls_client_complete import DTLSRecord
    client.record_layer = DTLSRecord(client.cipher_suite)
    
    # 模拟密钥材料
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.master_secret = b'C' * 48
    
    print(f"密码套件: {hex(client.cipher_suite)}")
    
    # 派生密钥材料
    try:
        client.derive_key_material()
        print("\n=== 密钥派生成功 ===")
        print(f"客户端写密钥: {client.client_write_key.hex()}")
        print(f"客户端写IV: {client.client_write_iv.hex()}")
        
        # 启用加密
        client.record_layer.enable_encryption(
            client.client_write_key, 
            client.client_write_iv
        )
        
        print("\n=== 加密测试 ===")
        
        # 测试数据
        test_data = b"Hello, DTLS GCM Mode!"
        print(f"原始数据: {test_data}")
        print(f"原始数据长度: {len(test_data)}")
        
        # 加密数据
        encrypted = client.record_layer._encrypt_data_gcm(
            DTLSConstants.APPLICATION_DATA, 
            test_data
        )
        
        print(f"加密后数据: {encrypted.hex()}")
        print(f"加密后长度: {len(encrypted)}")
        
        print("\n=== GCM模式测试完成 ===")
        
    except Exception as e:
        print(f"测试失败: {e}")
        import traceback
        traceback.print_exc()

def main():
    """主函数"""
    print("DTLS客户端加密模式测试")
    print("=" * 50)
    
    # 测试CBC模式
    test_cbc_encryption()
    
    # 测试GCM模式
    test_gcm_encryption()
    
    print("\n所有测试完成!")

if __name__ == "__main__":
    main()
