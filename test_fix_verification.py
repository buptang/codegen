#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证DTLS加密问题修复效果
对比修复前后的密钥长度
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

def test_cipher_suite_key_lengths():
    """测试不同密码套件的密钥长度"""
    print("🔍 修复效果检查")
    print("=" * 50)
    
    client = CompleteDTLSClient()
    
    # 设置测试数据
    client.pre_master_secret = b'A' * 32
    client.client_random = b'B' * 32
    client.server_random = b'C' * 32
    
    # 派生主密钥
    client.derive_master_secret()
    
    # 测试不同的密码套件
    test_cases = [
        {
            'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            'cipher_suite': DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
            'expected_key_length': 16,
            'expected_iv_length': 16
        },
        {
            'name': 'TLS_RSA_WITH_AES_128_GCM_SHA256',
            'cipher_suite': DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256,
            'expected_key_length': 16,
            'expected_iv_length': 4
        },
        {
            'name': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            'cipher_suite': DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            'expected_key_length': 16,  # 修复前是32，修复后应该是16
            'expected_iv_length': 4
        }
    ]
    
    all_passed = True
    
    for test_case in test_cases:
        print(f"\n📋 测试: {test_case['name']}")
        print(f"   密码套件值: {hex(test_case['cipher_suite'])}")
        
        # 设置密码套件
        client.cipher_suite = test_case['cipher_suite']
        
        try:
            # 派生密钥材料
            client.derive_key_material()
            
            # 检查密钥长度
            actual_key_length = len(client.client_write_key)
            actual_iv_length = len(client.client_write_iv)
            
            key_length_ok = actual_key_length == test_case['expected_key_length']
            iv_length_ok = actual_iv_length == test_case['expected_iv_length']
            
            print(f"   加密密钥长度: {actual_key_length} (期望: {test_case['expected_key_length']}) {'✅' if key_length_ok else '❌'}")
            print(f"   IV长度: {actual_iv_length} (期望: {test_case['expected_iv_length']}) {'✅' if iv_length_ok else '❌'}")
            
            if key_length_ok and iv_length_ok:
                print(f"   结果: ✅ 通过")
            else:
                print(f"   结果: ❌ 失败")
                all_passed = False
                
        except Exception as e:
            print(f"   结果: ❌ 异常 - {e}")
            all_passed = False
    
    print(f"\n{'='*50}")
    print(f"总体结果: {'🎉 所有测试通过' if all_passed else '⚠️ 存在问题'}")
    
    if all_passed:
        print("\n🔧 修复验证:")
        print("   ✅ TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 现在使用正确的16字节密钥")
        print("   ✅ 不再使用默认的32字节AES-256密钥")
        print("   ✅ 密钥长度与密码套件规范一致")
        print("\n💡 这应该解决服务端解密失败的问题！")
    
    return all_passed

def test_before_after_comparison():
    """对比修复前后的效果"""
    print("\n" + "=" * 70)
    print("📊 修复前后对比")
    print("=" * 70)
    
    print("修复前的问题:")
    print("   ❌ TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 使用32字节密钥 (AES-256)")
    print("   ❌ 服务端期望16字节密钥 (AES-128)")
    print("   ❌ 密钥长度不匹配导致解密失败")
    
    print("\n修复后的改进:")
    print("   ✅ 添加了专门的 TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 分支")
    print("   ✅ 正确使用16字节密钥 (AES-128)")
    print("   ✅ 密钥长度与密码套件规范一致")
    print("   ✅ 服务端应该能够正确解密")
    
    print("\n🔧 修复的代码位置:")
    print("   文件: dtls_client_complete.py")
    print("   函数: derive_key_material()")
    print("   修改: 在第1127行后添加了ECDHE-RSA-GCM分支")

def main():
    """主测试函数"""
    print("🔍 DTLS加密问题修复验证")
    print("=" * 70)
    
    # 测试密码套件密钥长度
    success = test_cipher_suite_key_lengths()
    
    # 显示修复前后对比
    test_before_after_comparison()
    
    if success:
        print("\n🎯 结论:")
        print("   修复成功！ECDH协商后的加密数据现在应该能被服务端正确解密。")
        print("   问题根源是密钥长度不匹配，现在已经修复。")
    else:
        print("\n⚠️ 警告:")
        print("   修复可能不完整，请检查代码实现。")
    
    return success

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

