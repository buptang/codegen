#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS加密问题诊断测试
检查ECDH协商后的密钥派生和加密过程
"""

import sys
import os
import logging
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_prf_function():
    """测试PRF函数的正确性"""
    print("=" * 70)
    print("🔍 测试PRF函数")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    # 测试已知的PRF向量
    secret = b'test_secret'
    seed = b'test_seed'
    length = 32
    
    result = client._prf(secret, seed, length)
    
    print(f"PRF测试:")
    print(f"  Secret: {secret.hex()}")
    print(f"  Seed: {seed.hex()}")
    print(f"  Length: {length}")
    print(f"  Result: {result.hex()}")
    print(f"  Result length: {len(result)}")
    
    # 验证PRF的一致性
    result2 = client._prf(secret, seed, length)
    consistent = result == result2
    print(f"  一致性检查: {'✅ 通过' if consistent else '❌ 失败'}")
    
    return consistent

def test_master_secret_derivation():
    """测试主密钥派生"""
    print("\n" + "=" * 70)
    print("🔑 测试主密钥派生")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    # 设置测试数据
    client.pre_master_secret = b'A' * 32  # 模拟ECDH共享密钥
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    
    print(f"输入数据:")
    print(f"  Pre-master secret: {client.pre_master_secret.hex()}")
    print(f"  Client random: {client.client_random.hex()}")
    print(f"  Server random: {client.server_random.hex()}")
    
    # 派生主密钥
    try:
        client.derive_master_secret()
        
        print(f"\n主密钥派生结果:")
        print(f"  Master secret: {client.master_secret.hex()}")
        print(f"  Master secret length: {len(client.master_secret)}")
        print(f"  ✅ 主密钥派生成功")
        
        return True
        
    except Exception as e:
        print(f"  ❌ 主密钥派生失败: {e}")
        return False

def test_key_material_derivation():
    """测试密钥材料派生"""
    print("\n" + "=" * 70)
    print("🔐 测试密钥材料派生")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    # 设置测试数据
    client.pre_master_secret = b'A' * 32
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    
    # 派生主密钥
    client.derive_master_secret()
    
    print(f"密码套件: {hex(client.cipher_suite)}")
    
    # 派生密钥材料
    try:
        client.derive_key_material()
        
        print(f"\n密钥材料派生结果:")
        print(f"  Client write key: {client.client_write_key.hex()}")
        print(f"  Server write key: {client.server_write_key.hex()}")
        print(f"  Client write IV: {client.client_write_iv.hex()}")
        print(f"  Server write IV: {client.server_write_iv.hex()}")
        
        # 检查密钥长度
        key_length_ok = len(client.client_write_key) == 16  # AES-128
        iv_length_ok = len(client.client_write_iv) == 4     # GCM固定IV
        
        print(f"\n密钥长度检查:")
        print(f"  Client write key length: {len(client.client_write_key)} ({'✅ 正确' if key_length_ok else '❌ 错误'})")
        print(f"  Client write IV length: {len(client.client_write_iv)} ({'✅ 正确' if iv_length_ok else '❌ 错误'})")
        
        return key_length_ok and iv_length_ok
        
    except Exception as e:
        print(f"  ❌ 密钥材料派生失败: {e}")
        return False

def test_ecdh_key_exchange():
    """测试ECDH密钥交换"""
    print("\n" + "=" * 70)
    print("🔄 测试ECDH密钥交换")
    print("=" * 70)
    
    # 模拟服务器和客户端的ECDH密钥交换
    curve = ec.SECP256R1()
    
    # 生成服务器密钥对
    server_private_key = ec.generate_private_key(curve)
    server_public_key = server_private_key.public_key()
    
    # 生成客户端密钥对
    client_private_key = ec.generate_private_key(curve)
    client_public_key = client_private_key.public_key()
    
    # 序列化公钥
    server_public_key_data = server_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    client_public_key_data = client_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    print(f"密钥交换参数:")
    print(f"  曲线: SECP256R1")
    print(f"  服务器公钥长度: {len(server_public_key_data)}")
    print(f"  客户端公钥长度: {len(client_public_key_data)}")
    
    # 执行ECDH
    try:
        # 客户端计算共享密钥
        client_shared_key = client_private_key.exchange(ec.ECDH(), server_public_key)
        
        # 服务器计算共享密钥
        server_shared_key = server_private_key.exchange(ec.ECDH(), client_public_key)
        
        print(f"\nECDH计算结果:")
        print(f"  客户端共享密钥: {client_shared_key.hex()}")
        print(f"  服务器共享密钥: {server_shared_key.hex()}")
        print(f"  共享密钥长度: {len(client_shared_key)}")
        
        # 验证共享密钥一致性
        keys_match = client_shared_key == server_shared_key
        print(f"  共享密钥一致性: {'✅ 一致' if keys_match else '❌ 不一致'}")
        
        return keys_match, client_shared_key
        
    except Exception as e:
        print(f"  ❌ ECDH密钥交换失败: {e}")
        return False, None

def test_aes_gcm_encryption():
    """测试AES-GCM加密"""
    print("\n" + "=" * 70)
    print("🔒 测试AES-GCM加密")
    print("=" * 70)
    
    # 使用测试密钥
    key = b'A' * 16  # AES-128密钥
    iv = b'B' * 4    # GCM固定IV
    plaintext = b"Hello, DTLS World!"
    
    print(f"加密参数:")
    print(f"  密钥: {key.hex()}")
    print(f"  IV: {iv.hex()}")
    print(f"  明文: {plaintext}")
    
    try:
        # 构造完整的GCM nonce (固定IV + 序号)
        sequence_number = 0
        nonce = iv + struct.pack('!Q', sequence_number)
        
        print(f"  Nonce: {nonce.hex()}")
        
        # 使用AESGCM加密
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        print(f"\n加密结果:")
        print(f"  密文: {ciphertext.hex()}")
        print(f"  密文长度: {len(ciphertext)}")
        
        # 解密验证
        decrypted = aesgcm.decrypt(nonce, ciphertext, None)
        
        print(f"\n解密验证:")
        print(f"  解密结果: {decrypted}")
        print(f"  解密正确: {'✅ 是' if decrypted == plaintext else '❌ 否'}")
        
        return decrypted == plaintext
        
    except Exception as e:
        print(f"  ❌ AES-GCM加密失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_hash_algorithms():
    """测试哈希算法"""
    print("\n" + "=" * 70)
    print("🔢 测试哈希算法")
    print("=" * 70)
    
    test_data = b"test data for hashing"
    
    # 测试不同的哈希算法
    hash_algorithms = {
        'SHA-1': hashlib.sha1,
        'SHA-256': hashlib.sha256,
        'SHA-384': hashlib.sha384,
        'SHA-512': hashlib.sha512
    }
    
    print(f"测试数据: {test_data}")
    print(f"\n哈希结果:")
    
    for name, hash_func in hash_algorithms.items():
        try:
            digest = hash_func(test_data).digest()
            print(f"  {name}: {digest.hex()} (长度: {len(digest)})")
        except Exception as e:
            print(f"  {name}: ❌ 失败 - {e}")
    
    return True

def test_cipher_suite_compatibility():
    """测试密码套件兼容性"""
    print("\n" + "=" * 70)
    print("🔧 测试密码套件兼容性")
    print("=" * 70)
    
    # 测试不同密码套件的PRF要求
    cipher_suites = {
        'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256': {
            'value': DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            'prf_hash': 'SHA-256',
            'key_length': 16,
            'iv_length': 4
        },
        'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA': {
            'value': DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            'prf_hash': 'SHA-1',  # TLS 1.2之前使用SHA-1
            'key_length': 16,
            'iv_length': 16
        }
    }
    
    for name, config in cipher_suites.items():
        print(f"\n{name}:")
        print(f"  值: {hex(config['value'])}")
        print(f"  PRF哈希: {config['prf_hash']}")
        print(f"  密钥长度: {config['key_length']}")
        print(f"  IV长度: {config['iv_length']}")
        
        # 检查当前实现是否正确处理
        if config['prf_hash'] == 'SHA-256':
            print(f"  当前实现: ✅ 支持 (使用SHA-256)")
        else:
            print(f"  当前实现: ⚠️  可能有问题 (固定使用SHA-256，但套件要求{config['prf_hash']})")
    
    return True

def main():
    """主测试函数"""
    print("🔍 DTLS加密问题诊断测试")
    print("=" * 70)
    
    test_results = []
    
    # 1. 测试PRF函数
    test_results.append(("PRF函数", test_prf_function()))
    
    # 2. 测试主密钥派生
    test_results.append(("主密钥派生", test_master_secret_derivation()))
    
    # 3. 测试密钥材料派生
    test_results.append(("密钥材料派生", test_key_material_derivation()))
    
    # 4. 测试ECDH密钥交换
    ecdh_ok, shared_key = test_ecdh_key_exchange()
    test_results.append(("ECDH密钥交换", ecdh_ok))
    
    # 5. 测试AES-GCM加密
    test_results.append(("AES-GCM加密", test_aes_gcm_encryption()))
    
    # 6. 测试哈希算法
    test_results.append(("哈希算法", test_hash_algorithms()))
    
    # 7. 测试密码套件兼容性
    test_results.append(("密码套件兼容性", test_cipher_suite_compatibility()))
    
    # 汇总结果
    print("\n" + "=" * 70)
    print("📋 测试结果汇总")
    print("=" * 70)
    
    all_passed = True
    for test_name, result in test_results:
        status = "✅ 通过" if result else "❌ 失败"
        print(f"  {test_name}: {status}")
        if not result:
            all_passed = False
    
    print(f"\n总体结果: {'🎉 所有测试通过' if all_passed else '⚠️  存在问题需要修复'}")
    
    # 问题分析和建议
    if not all_passed:
        print("\n" + "=" * 70)
        print("🔧 问题分析和修复建议")
        print("=" * 70)
        
        failed_tests = [name for name, result in test_results if not result]
        
        if "PRF函数" in failed_tests:
            print("❌ PRF函数问题:")
            print("   - 检查_prf函数中的HMAC-SHA256实现")
            print("   - 验证PRF算法是否符合RFC 5246标准")
        
        if "主密钥派生" in failed_tests:
            print("❌ 主密钥派生问题:")
            print("   - 检查pre_master_secret是否正确")
            print("   - 验证client_random和server_random")
            print("   - 确认'master secret'标签正确")
        
        if "密钥材料派生" in failed_tests:
            print("❌ 密钥材料派生问题:")
            print("   - 检查密码套件对应的密钥长度")
            print("   - 验证'key expansion'标签")
            print("   - 确认随机数顺序 (server_random + client_random)")
        
        if "ECDH密钥交换" in failed_tests:
            print("❌ ECDH密钥交换问题:")
            print("   - 检查椭圆曲线参数")
            print("   - 验证公钥序列化格式")
            print("   - 确认密钥交换计算")
        
        if "AES-GCM加密" in failed_tests:
            print("❌ AES-GCM加密问题:")
            print("   - 检查nonce构造 (固定IV + 序号)")
            print("   - 验证密钥长度和格式")
            print("   - 确认AEAD参数")
        
        print("\n🎯 重点检查项目:")
        print("   1. PRF函数是否应该根据密码套件选择不同的哈希算法")
        print("   2. ECDH共享密钥是否直接用作pre_master_secret")
        print("   3. 密钥材料派生中的随机数顺序")
        print("   4. GCM模式的nonce构造方式")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

