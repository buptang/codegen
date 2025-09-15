#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试CBC模式修复效果
"""

import sys
import os
import logging

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_cbc_encryption_decryption():
    """测试CBC模式的完整加密解密流程"""
    print("🔐 测试CBC模式加密解密流程")
    print("=" * 50)
    
    client = CompleteDTLSClient()
    
    # 设置测试数据
    client.pre_master_secret = b'A' * 32
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    client.sequence_number = 0
    
    # 派生密钥
    client.derive_master_secret()
    client.derive_key_material()
    
    # 设置加密算法
    client.cipher_algorithm = "AES-128-CBC"
    client.encryption_enabled = True
    
    # 测试数据
    test_data = b"Hello, DTLS CBC World! This is a test message for CBC encryption and decryption."
    content_type = DTLSConstants.APPLICATION_DATA
    
    print(f"原始数据: {test_data}")
    print(f"数据长度: {len(test_data)}字节")
    
    try:
        # 1. 测试加密
        print("\n1. 测试加密...")
        encrypted = client.record_layer._encrypt_data_cbc(content_type, test_data)
        print(f"   加密成功: {len(encrypted)}字节")
        print(f"   加密数据前32字节: {encrypted[:32].hex()}")
        
        # 2. 测试解密
        print("\n2. 测试解密...")
        decrypted = client._decrypt_data_cbc(encrypted)
        print(f"   解密成功: {len(decrypted)}字节")
        print(f"   解密数据: {decrypted}")
        
        # 3. 验证数据完整性
        print("\n3. 验证数据完整性...")
        if decrypted == test_data:
            print("   ✅ 数据完整性验证成功！")
            return True
        else:
            print("   ❌ 数据完整性验证失败！")
            print(f"   期望: {test_data}")
            print(f"   实际: {decrypted}")
            return False
            
    except Exception as e:
        print(f"   ❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_decrypt_message_routing():
    """测试decrypt_message函数的路由功能"""
    print("\n🔀 测试decrypt_message路由功能")
    print("=" * 50)
    
    client = CompleteDTLSClient()
    
    # 设置测试数据
    client.pre_master_secret = b'A' * 32
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    client.sequence_number = 0
    client.cipher_algorithm = "AES-128-CBC"
    client.encryption_enabled = True
    
    # 派生密钥
    client.derive_master_secret()
    client.derive_key_material()
    
    test_data = b"Test routing message"
    
    try:
        # 测试CBC路由
        print("1. 测试CBC密码套件路由...")
        client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        encrypted_cbc = client.record_layer._encrypt_data_cbc(DTLSConstants.APPLICATION_DATA, test_data)
        decrypted_cbc = client.decrypt_message(encrypted_cbc)
        
        if decrypted_cbc == test_data:
            print("   ✅ CBC路由测试成功")
        else:
            print("   ❌ CBC路由测试失败")
            return False
        
        # 测试GCM路由（如果有GCM密钥）
        print("2. 测试GCM密码套件路由...")
        client.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
        
        # 为GCM模式重新派生密钥
        client.derive_key_material()
        
        # 创建一个模拟的GCM加密数据（简单测试）
        fake_gcm_data = b'A' * 28  # 最小GCM数据长度
        decrypted_gcm = client.decrypt_message(fake_gcm_data)
        
        # GCM解密可能失败，但不应该崩溃
        print("   ✅ GCM路由测试完成（无崩溃）")
        
        return True
        
    except Exception as e:
        print(f"   ❌ 路由测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_prf_hash_selection():
    """测试PRF函数的哈希算法选择"""
    print("\n🔧 测试PRF哈希算法选择")
    print("=" * 50)
    
    client = CompleteDTLSClient()
    
    secret = b'test_secret'
    seed = b'test_seed'
    length = 32
    
    try:
        # 测试CBC_SHA使用SHA-1
        print("1. 测试CBC_SHA密码套件使用SHA-1...")
        client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        result_sha1 = client._prf(secret, seed, length)
        print(f"   SHA-1结果: {result_sha1.hex()}")
        
        # 测试GCM_SHA256使用SHA-256
        print("2. 测试GCM_SHA256密码套件使用SHA-256...")
        client.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
        result_sha256 = client._prf(secret, seed, length)
        print(f"   SHA-256结果: {result_sha256.hex()}")
        
        # 验证结果不同
        if result_sha1 != result_sha256:
            print("   ✅ PRF哈希算法选择正确（结果不同）")
            return True
        else:
            print("   ❌ PRF哈希算法选择可能有问题（结果相同）")
            return False
            
    except Exception as e:
        print(f"   ❌ PRF测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_method_availability():
    """测试新方法是否可用"""
    print("\n📋 测试方法可用性")
    print("=" * 50)
    
    client = CompleteDTLSClient()
    
    # 检查新方法是否存在
    methods_to_check = [
        ('_decrypt_data_cbc', client),
        ('decrypt_message', client),
        ('_encrypt_data_cbc', client.record_layer)
    ]
    
    all_available = True
    for method_name, obj in methods_to_check:
        if hasattr(obj, method_name):
            print(f"   ✅ {method_name} 方法可用")
        else:
            print(f"   ❌ {method_name} 方法不可用")
            all_available = False
    
    return all_available

def main():
    """主测试函数"""
    print("🧪 CBC模式修复效果测试")
    print("=" * 70)
    
    tests = [
        ("方法可用性测试", test_method_availability),
        ("PRF哈希算法选择测试", test_prf_hash_selection),
        ("CBC加密解密测试", test_cbc_encryption_decryption),
        ("decrypt_message路由测试", test_decrypt_message_routing),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n🔍 执行: {test_name}")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"   ❌ 测试异常: {e}")
            results.append((test_name, False))
    
    # 总结结果
    print("\n" + "=" * 70)
    print("📊 测试结果总结:")
    print("=" * 70)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"   {test_name}: {status}")
        if result:
            passed += 1
    
    print(f"\n总计: {passed}/{total} 测试通过")
    
    if passed == total:
        print("🎉 所有测试通过！CBC模式修复成功！")
        return True
    else:
        print("⚠️ 部分测试失败，需要进一步调试")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
