#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
分析TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA密码套件的问题
"""

import sys
import os
import logging
import struct

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def analyze_cbc_implementation():
    """分析CBC模式实现的问题"""
    print("🔍 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 问题分析")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    # 设置测试数据
    client.pre_master_secret = b'A' * 32
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    
    # 派生主密钥和密钥材料
    client.derive_master_secret()
    client.derive_key_material()
    
    print("\n📋 密钥材料检查:")
    print(f"   密码套件: {hex(client.cipher_suite)} (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)")
    print(f"   客户端MAC密钥: {len(client.client_write_mac_key)}字节 - {client.client_write_mac_key.hex()}")
    print(f"   服务端MAC密钥: {len(client.server_write_mac_key)}字节 - {client.server_write_mac_key.hex()}")
    print(f"   客户端加密密钥: {len(client.client_write_key)}字节 - {client.client_write_key.hex()}")
    print(f"   服务端加密密钥: {len(client.server_write_key)}字节 - {client.server_write_key.hex()}")
    print(f"   客户端IV: {len(client.client_write_iv)}字节 - {client.client_write_iv.hex()}")
    print(f"   服务端IV: {len(client.server_write_iv)}字节 - {client.server_write_iv.hex()}")
    
    # 检查密钥长度是否正确
    issues = []
    if len(client.client_write_mac_key) != 20:
        issues.append(f"❌ MAC密钥长度错误: {len(client.client_write_mac_key)} (期望: 20)")
    else:
        print("   ✅ MAC密钥长度正确: 20字节 (HMAC-SHA1)")
        
    if len(client.client_write_key) != 16:
        issues.append(f"❌ 加密密钥长度错误: {len(client.client_write_key)} (期望: 16)")
    else:
        print("   ✅ 加密密钥长度正确: 16字节 (AES-128)")
        
    if len(client.client_write_iv) != 16:
        issues.append(f"❌ IV长度错误: {len(client.client_write_iv)} (期望: 16)")
    else:
        print("   ✅ IV长度正确: 16字节 (AES块大小)")
    
    return issues

def test_cbc_encryption():
    """测试CBC模式加密"""
    print("\n🔐 CBC加密测试:")
    print("-" * 50)
    
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
    
    # 测试数据
    test_data = b"Hello, DTLS CBC World!"
    content_type = DTLSConstants.APPLICATION_DATA
    
    print(f"   原始数据: {test_data}")
    print(f"   数据长度: {len(test_data)}字节")
    print(f"   内容类型: {content_type}")
    
    try:
        # 执行CBC加密
        encrypted = client._encrypt_data_cbc(content_type, test_data)
        print(f"   加密成功: {len(encrypted)}字节")
        print(f"   加密数据: {encrypted.hex()}")
        
        # 分析加密数据结构
        if len(encrypted) >= 16:
            iv = encrypted[:16]
            ciphertext = encrypted[16:]
            print(f"   IV: {iv.hex()} ({len(iv)}字节)")
            print(f"   密文: {ciphertext.hex()} ({len(ciphertext)}字节)")
            
            # 检查密文长度是否是16的倍数
            if len(ciphertext) % 16 == 0:
                print("   ✅ 密文长度是AES块大小的倍数")
            else:
                print(f"   ❌ 密文长度不是16的倍数: {len(ciphertext)}")
        
        return encrypted
        
    except Exception as e:
        print(f"   ❌ 加密失败: {e}")
        import traceback
        traceback.print_exc()
        return None

def analyze_decrypt_function():
    """分析解密函数的问题"""
    print("\n🔓 解密函数分析:")
    print("-" * 50)
    
    client = CompleteDTLSClient()
    
    # 检查解密函数实现
    import inspect
    decrypt_source = inspect.getsource(client.decrypt_message)
    
    print("   当前解密函数实现:")
    print("   " + "\n   ".join(decrypt_source.split('\n')[:10]))
    
    # 检查是否只支持GCM
    if "GCM" in decrypt_source and "CBC" not in decrypt_source:
        print("\n   ❌ 问题发现: 解密函数只实现了GCM模式!")
        print("   ❌ 缺少CBC模式的解密实现")
        print("   ❌ 这是导致CBC密码套件解密失败的根本原因")
        return False
    else:
        print("\n   ✅ 解密函数支持多种模式")
        return True

def analyze_prf_function():
    """分析PRF函数对CBC_SHA的支持"""
    print("\n🔧 PRF函数分析:")
    print("-" * 50)
    
    client = CompleteDTLSClient()
    
    # 检查PRF函数实现
    import inspect
    prf_source = inspect.getsource(client._prf)
    
    print("   当前PRF函数实现:")
    lines = prf_source.split('\n')[:15]
    for line in lines:
        if line.strip():
            print("   " + line)
    
    # 检查哈希算法
    if "SHA256" in prf_source or "sha256" in prf_source:
        print("\n   ⚠️ PRF函数使用SHA-256")
        print("   ⚠️ TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA要求使用SHA-1")
        print("   ⚠️ 这可能导致密钥派生不正确")
        return False
    else:
        print("\n   ✅ PRF函数实现看起来正确")
        return True

def main():
    """主分析函数"""
    print("🔍 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 完整问题分析")
    print("=" * 70)
    
    # 1. 分析密钥派生
    key_issues = analyze_cbc_implementation()
    
    # 2. 测试加密功能
    encrypted_data = test_cbc_encryption()
    
    # 3. 分析解密函数
    decrypt_ok = analyze_decrypt_function()
    
    # 4. 分析PRF函数
    prf_ok = analyze_prf_function()
    
    # 总结问题
    print("\n" + "=" * 70)
    print("📊 问题总结:")
    print("=" * 70)
    
    all_issues = []
    
    if key_issues:
        all_issues.extend(key_issues)
    
    if not decrypt_ok:
        all_issues.append("❌ 解密函数缺少CBC模式支持")
    
    if not prf_ok:
        all_issues.append("❌ PRF函数可能使用错误的哈希算法")
    
    if encrypted_data is None:
        all_issues.append("❌ CBC加密功能异常")
    
    if all_issues:
        print("发现的问题:")
        for issue in all_issues:
            print(f"   {issue}")
        
        print(f"\n🎯 主要问题:")
        if not decrypt_ok:
            print("   1. 解密函数只支持GCM模式，不支持CBC模式")
            print("   2. 这是导致CBC密码套件解密失败的根本原因")
            print("   3. 需要实现CBC模式的解密功能")
        
        if not prf_ok:
            print("   4. PRF函数可能使用了错误的哈希算法")
            print("   5. CBC_SHA密码套件应该使用SHA-1而不是SHA-256")
    else:
        print("✅ 未发现明显问题，需要进一步调试")
    
    return len(all_issues) == 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

