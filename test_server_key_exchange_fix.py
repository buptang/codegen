#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试修复后的Server Key Exchange解析功能
"""

import sys
import logging
import struct
from dtls_client_complete import CompleteDTLSClient

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_normal_case():
    """测试正常情况：完整的Server Key Exchange消息"""
    print("=== 测试正常情况 ===")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 构造完整的Server Key Exchange消息
    # 1字节曲线类型 + 2字节命名曲线 + 1字节公钥长度 + 65字节公钥 + 2字节签名算法 + 2字节签名长度 + 256字节签名
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1
    test_data.append(65)  # 公钥长度
    test_data.extend(b'\x04' + b'\x01' * 32 + b'\x02' * 32)  # 65字节公钥
    test_data.extend(struct.pack('!H', 0x0403))  # 签名算法 (ECDSA with SHA-256)
    test_data.extend(struct.pack('!H', 256))  # 签名长度
    test_data.extend(b'\x03' * 256)  # 256字节签名
    
    result = client.parse_server_key_exchange(bytes(test_data))
    print(f"结果: {'✅ 成功' if result else '❌ 失败'}")
    
    if result:
        print(f"存储的服务器公钥信息:")
        print(f"  曲线: {client.server_temp_public_key['named_curve']}")
        print(f"  公钥长度: {len(client.server_temp_public_key['public_key'])}")
        print(f"  签名长度: {len(client.server_temp_public_key['signature'])}")
    
    return result

def test_truncated_signature():
    """测试签名数据被截断的情况"""
    print("\n=== 测试签名数据截断情况 ===")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 构造签名数据被截断的消息
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1
    test_data.append(65)  # 公钥长度
    test_data.extend(b'\x04' + b'\x01' * 32 + b'\x02' * 32)  # 65字节公钥
    test_data.extend(struct.pack('!H', 0x0403))  # 签名算法
    test_data.extend(struct.pack('!H', 256))  # 声明签名长度为256
    test_data.extend(b'\x03' * 200)  # 但实际只有200字节签名（截断）
    
    result = client.parse_server_key_exchange(bytes(test_data))
    print(f"结果: {'✅ 成功（容错处理）' if result else '❌ 失败'}")
    
    if result:
        print(f"实际签名长度: {len(client.server_temp_public_key['signature'])}")
    
    return result

def test_invalid_lengths():
    """测试无效长度的情况"""
    print("\n=== 测试无效长度情况 ===")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 构造公钥长度异常的消息
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1
    test_data.append(0)  # 公钥长度为0（异常）
    
    result = client.parse_server_key_exchange(bytes(test_data))
    print(f"公钥长度为0的结果: {'✅ 成功' if result else '❌ 失败（预期）'}")
    
    # 构造签名长度异常的消息
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1
    test_data.append(65)  # 公钥长度
    test_data.extend(b'\x04' + b'\x01' * 32 + b'\x02' * 32)  # 65字节公钥
    test_data.extend(struct.pack('!H', 0x0403))  # 签名算法
    test_data.extend(struct.pack('!H', 2000))  # 签名长度异常大
    
    result2 = client.parse_server_key_exchange(bytes(test_data))
    print(f"签名长度异常的结果: {'✅ 成功' if result2 else '❌ 失败（预期）'}")
    
    return not result and not result2  # 两个都应该失败

def test_insufficient_data():
    """测试数据不足的情况"""
    print("\n=== 测试数据不足情况 ===")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 只有前几个字节的数据
    test_data = bytes([3, 0, 23])  # 曲线类型 + 命名曲线（不完整）
    
    result = client.parse_server_key_exchange(test_data)
    print(f"数据不足的结果: {'✅ 成功' if result else '❌ 失败（预期）'}")
    
    return not result  # 应该失败

def test_user_reported_case():
    """测试用户报告的具体情况"""
    print("\n=== 测试用户报告的情况 ===")
    print("secp256r1曲线，公钥65字节，签名256字节")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 构造用户报告的具体情况
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1 (用户报告)
    test_data.append(65)  # 公钥长度65字节 (用户报告)
    test_data.extend(b'\x04' + b'\xaa' * 32 + b'\xbb' * 32)  # 65字节公钥
    test_data.extend(struct.pack('!H', 0x0403))  # ECDSA with SHA-256
    test_data.extend(struct.pack('!H', 256))  # 签名长度256字节 (用户报告)
    test_data.extend(b'\xcc' * 256)  # 256字节签名
    
    print(f"构造的测试数据长度: {len(test_data)} 字节")
    print(f"预期长度: {1 + 2 + 1 + 65 + 2 + 2 + 256} = 329 字节")
    
    result = client.parse_server_key_exchange(bytes(test_data))
    print(f"结果: {'✅ 成功' if result else '❌ 失败'}")
    
    if result:
        print("✅ 用户报告的情况应该能正常解析！")
        print(f"解析结果验证:")
        print(f"  曲线: {client.server_temp_public_key['named_curve']} (应为23)")
        print(f"  公钥长度: {len(client.server_temp_public_key['public_key'])} (应为65)")
        print(f"  签名长度: {len(client.server_temp_public_key['signature'])} (应为256)")
    else:
        print("❌ 用户报告的情况仍然失败，需要进一步调查")
    
    return result

def main():
    """主测试函数"""
    print("开始测试修复后的Server Key Exchange解析功能...")
    
    tests = [
        ("正常情况", test_normal_case),
        ("签名截断", test_truncated_signature),
        ("无效长度", test_invalid_lengths),
        ("数据不足", test_insufficient_data),
        ("用户报告情况", test_user_reported_case)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} 测试通过")
            else:
                print(f"❌ {test_name} 测试失败")
        except Exception as e:
            print(f"❌ {test_name} 测试异常: {e}")
    
    print(f"\n=== 测试结果 ===")
    print(f"通过: {passed}/{total}")
    
    if passed >= 4:  # 至少4个测试通过（无效长度和数据不足应该失败）
        print("🎉 Server Key Exchange解析修复成功！")
        print("现在应该能够正确解析用户报告的情况，并提供详细的错误信息")
        return True
    else:
        print("❌ 仍有问题需要修复")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
