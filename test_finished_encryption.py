#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Finished消息加密功能
验证CBC和GCM模式下Finished消息是否正确加密
"""

import sys
import os
import logging

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_finished_encryption():
    """测试Finished消息加密"""
    print("=" * 60)
    print("🔐 测试Finished消息加密功能")
    print("=" * 60)
    
    # 创建DTLS客户端
    client = CompleteDTLSClient()
    
    # 模拟握手过程中的状态设置
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    
    # 测试CBC模式
    print("\n📊 测试1: AES-128-CBC + HMAC-SHA1模式")
    print("-" * 40)
    
    # 设置CBC密码套件
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    client.record_layer.cipher_suite = client.cipher_suite
    
    # 派生密钥
    client.derive_master_secret()
    client.derive_key_material()
    
    # 启用加密
    mac_key = getattr(client, 'client_write_mac_key', None)
    client.record_layer.enable_encryption(
        client.client_write_key,
        client.client_write_iv,
        mac_key
    )
    
    # 创建Finished消息
    finished_msg = client.create_finished_message()
    print(f"✅ Finished消息创建成功: {len(finished_msg)}字节")
    
    # 创建加密记录
    encrypted_record = client.record_layer.create_record(
        DTLSConstants.HANDSHAKE, finished_msg
    )
    print(f"✅ 加密记录创建成功: {len(encrypted_record)}字节")
    
    # 验证加密
    if len(encrypted_record) > len(finished_msg) + 13:  # 13字节DTLS头部
        print(f"✅ CBC加密成功")
        print(f"   原始Finished消息: {len(finished_msg)}字节")
        print(f"   加密后记录: {len(encrypted_record)}字节")
        print(f"   加密开销: {len(encrypted_record) - len(finished_msg) - 13}字节")
    else:
        print("❌ CBC加密失败 - 数据未被加密")
    
    # 测试GCM模式
    print("\n📊 测试2: AES-128-GCM模式")
    print("-" * 40)
    
    # 重新创建客户端
    client2 = CompleteDTLSClient()
    client2.client_random = b'A' * 32
    client2.server_random = b'B' * 32
    client2.pre_master_secret = b'C' * 48
    
    # 设置GCM密码套件
    client2.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
    client2.record_layer.cipher_suite = client2.cipher_suite
    
    # 派生密钥
    client2.derive_master_secret()
    client2.derive_key_material()
    
    # 启用加密
    client2.record_layer.enable_encryption(
        client2.client_write_key,
        client2.client_write_iv
    )
    
    # 创建Finished消息
    finished_msg2 = client2.create_finished_message()
    print(f"✅ Finished消息创建成功: {len(finished_msg2)}字节")
    
    # 创建加密记录
    encrypted_record2 = client2.record_layer.create_record(
        DTLSConstants.HANDSHAKE, finished_msg2
    )
    print(f"✅ 加密记录创建成功: {len(encrypted_record2)}字节")
    
    # 验证加密
    if len(encrypted_record2) > len(finished_msg2) + 13:  # 13字节DTLS头部
        print(f"✅ GCM加密成功")
        print(f"   原始Finished消息: {len(finished_msg2)}字节")
        print(f"   加密后记录: {len(encrypted_record2)}字节")
        print(f"   加密开销: {len(encrypted_record2) - len(finished_msg2) - 13}字节")
    else:
        print("❌ GCM加密失败 - 数据未被加密")
    
    # 对比测试
    print("\n📊 加密模式对比")
    print("-" * 40)
    print(f"CBC模式 - 原始: {len(finished_msg)}字节 → 加密后: {len(encrypted_record)}字节")
    print(f"GCM模式 - 原始: {len(finished_msg2)}字节 → 加密后: {len(encrypted_record2)}字节")
    
    if len(encrypted_record) > len(finished_msg) + 13 and len(encrypted_record2) > len(finished_msg2) + 13:
        print("🎉 所有测试通过！Finished消息加密功能正常")
        return True
    else:
        print("❌ 测试失败！Finished消息加密存在问题")
        return False

def test_encryption_state():
    """测试加密状态设置"""
    print("\n🔍 测试加密状态设置")
    print("-" * 40)
    
    client = CompleteDTLSClient()
    
    # 测试初始状态
    print(f"初始加密状态: {client.record_layer.encryption_enabled}")
    print(f"初始cipher属性: {hasattr(client.record_layer, 'cipher')}")
    print(f"初始cipher_algorithm属性: {hasattr(client.record_layer, 'cipher_algorithm')}")
    
    # 设置CBC模式
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    client.record_layer.cipher_suite = client.cipher_suite
    
    # 模拟密钥材料
    client.client_write_key = b'A' * 16
    client.client_write_iv = b'B' * 16
    client.client_write_mac_key = b'C' * 20
    
    # 启用加密
    client.record_layer.enable_encryption(
        client.client_write_key,
        client.client_write_iv,
        client.client_write_mac_key
    )
    
    print(f"CBC模式加密状态: {client.record_layer.encryption_enabled}")
    print(f"CBC模式cipher属性: {hasattr(client.record_layer, 'cipher')}")
    print(f"CBC模式cipher_algorithm属性: {hasattr(client.record_layer, 'cipher_algorithm')}")
    print(f"CBC模式cipher_mode: {getattr(client.record_layer, 'cipher_mode', 'None')}")
    
    # 测试GCM模式
    client2 = CompleteDTLSClient()
    client2.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
    client2.record_layer.cipher_suite = client2.cipher_suite
    
    client2.client_write_key = b'A' * 16
    client2.client_write_iv = b'B' * 4
    
    client2.record_layer.enable_encryption(
        client2.client_write_key,
        client2.client_write_iv
    )
    
    print(f"GCM模式加密状态: {client2.record_layer.encryption_enabled}")
    print(f"GCM模式cipher属性: {hasattr(client2.record_layer, 'cipher')}")
    print(f"GCM模式cipher_algorithm属性: {hasattr(client2.record_layer, 'cipher_algorithm')}")
    print(f"GCM模式cipher_mode: {getattr(client2.record_layer, 'cipher_mode', 'None')}")

if __name__ == "__main__":
    print("🧪 Finished消息加密测试")
    print("=" * 60)
    
    try:
        # 测试加密状态
        test_encryption_state()
        
        # 测试Finished消息加密
        success = test_finished_encryption()
        
        if success:
            print("\n🎉 所有测试通过！")
            sys.exit(0)
        else:
            print("\n❌ 测试失败！")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

