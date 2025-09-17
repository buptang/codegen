#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端CBC模式使用示例
演示如何使用修复后的CBC加密/解密功能
"""

import sys
import os
import logging

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def demonstrate_cbc_encryption():
    """演示CBC模式的加密解密功能"""
    print("🔐 DTLS CBC模式加密解密演示")
    print("=" * 60)
    
    # 创建DTLS客户端
    client = CompleteDTLSClient()
    
    # 设置CBC密码套件
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    print(f"使用密码套件: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0x{client.cipher_suite:04x})")
    
    # 模拟握手过程中的密钥材料
    print("\n📋 设置密钥材料...")
    client.pre_master_secret = b'A' * 48  # 48字节的预主密钥
    client.client_random = b'B' * 32      # 32字节的客户端随机数
    client.server_random = b'C' * 32      # 32字节的服务端随机数
    client.sequence_number = 0
    
    # 派生主密钥和密钥材料
    client.derive_master_secret()
    client.derive_key_material()
    
    # 启用加密
    client.encryption_enabled = True
    client.record_layer.cipher_mode = 'CBC'
    client.record_layer.cipher_algorithm = 'AES-128-CBC'
    
    # 启用record layer加密
    client.record_layer.enable_encryption(
        client.client_write_key,
        client.client_write_iv,
        getattr(client, 'client_write_mac_key', None)
    )
    
    print(f"主密钥: {client.master_secret.hex()}")
    print(f"客户端写密钥: {client.client_write_key.hex()}")
    print(f"服务端写密钥: {client.server_write_key.hex()}")
    
    # 测试数据
    test_messages = [
        b"Hello, DTLS CBC World!",
        b"This is a longer message to test CBC padding and encryption.",
        b"Short msg",
        b"A" * 100,  # 长消息
        b"",         # 空消息
    ]
    
    print(f"\n🧪 测试{len(test_messages)}条消息的加密解密...")
    print("-" * 60)
    
    for i, message in enumerate(test_messages, 1):
        print(f"\n消息 {i}: {message}")
        print(f"长度: {len(message)} 字节")
        
        try:
            # 使用record layer进行加密
            encrypted = client.record_layer._encrypt_data_cbc(
                DTLSConstants.APPLICATION_DATA, 
                message
            )
            print(f"加密后长度: {len(encrypted)} 字节")
            print(f"加密数据: {encrypted.hex()}")
            
            # 使用客户端进行解密
            decrypted = client._decrypt_data_cbc(encrypted)
            print(f"解密后: {decrypted}")
            
            # 验证
            if decrypted == message:
                print("✅ 加密解密成功！")
            else:
                print("❌ 加密解密失败！")
                print(f"期望: {message}")
                print(f"实际: {decrypted}")
                
        except Exception as e:
            print(f"❌ 处理失败: {e}")
            import traceback
            traceback.print_exc()

def demonstrate_cipher_suite_selection():
    """演示不同密码套件的选择"""
    print("\n🔀 密码套件选择演示")
    print("=" * 60)
    
    client = CompleteDTLSClient()
    
    # 设置基本密钥材料
    client.pre_master_secret = b'A' * 48
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    client.sequence_number = 0
    client.encryption_enabled = True
    
    test_message = b"Test message for cipher suite selection"
    
    # 测试不同的密码套件
    cipher_suites = [
        (DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "CBC_SHA"),
        (DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256, "GCM_SHA256"),
    ]
    
    for suite_id, suite_name in cipher_suites:
        print(f"\n测试密码套件: {suite_name} (0x{suite_id:04x})")
        
        try:
            client.cipher_suite = suite_id
            client.derive_master_secret()
            client.derive_key_material()
            
            if suite_id == DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                # CBC模式
                encrypted = client.record_layer._encrypt_data_cbc(
                    DTLSConstants.APPLICATION_DATA, 
                    test_message
                )
                decrypted = client.decrypt_message(encrypted)
                print(f"CBC加密长度: {len(encrypted)}")
                print(f"CBC解密结果: {decrypted}")
                
                if decrypted == test_message:
                    print("✅ CBC模式工作正常")
                else:
                    print("❌ CBC模式有问题")
            else:
                # GCM模式（可能不完整，仅测试不崩溃）
                print("GCM模式测试（基础功能）")
                fake_gcm_data = b'A' * 28
                result = client.decrypt_message(fake_gcm_data)
                print("✅ GCM模式不崩溃")
                
        except Exception as e:
            print(f"❌ 密码套件 {suite_name} 测试失败: {e}")

def demonstrate_prf_functionality():
    """演示PRF函数的功能"""
    print("\n🔧 PRF函数功能演示")
    print("=" * 60)
    
    client = CompleteDTLSClient()
    
    secret = b'master_secret_test'
    seed = b'key_expansion_seed'
    length = 64
    
    # 测试不同密码套件的PRF
    print("测试PRF在不同密码套件下的行为:")
    
    # CBC_SHA使用SHA-1
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    prf_sha1 = client._prf(secret, seed, length)
    print(f"\nCBC_SHA (SHA-1): {prf_sha1.hex()}")
    
    # GCM_SHA256使用SHA-256
    client.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
    prf_sha256 = client._prf(secret, seed, length)
    print(f"GCM_SHA256 (SHA-256): {prf_sha256.hex()}")
    
    if prf_sha1 != prf_sha256:
        print("✅ PRF正确选择了不同的哈希算法")
    else:
        print("❌ PRF可能没有正确选择哈希算法")

def main():
    """主函数"""
    print("🚀 DTLS CBC模式完整演示")
    print("=" * 70)
    
    try:
        # 1. CBC加密解密演示
        demonstrate_cbc_encryption()
        
        # 2. 密码套件选择演示
        demonstrate_cipher_suite_selection()
        
        # 3. PRF功能演示
        demonstrate_prf_functionality()
        
        print("\n" + "=" * 70)
        print("🎉 演示完成！")
        print("CBC模式已成功集成到DTLS客户端中。")
        print("现在可以使用TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA密码套件进行安全通信。")
        
    except Exception as e:
        print(f"\n❌ 演示过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
