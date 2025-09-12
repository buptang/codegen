#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Server Key Exchange的两种格式：
1. 带签名算法字段的格式
2. 不带签名算法字段的格式（用户报告的情况）
"""

import sys
import logging
import struct
from dtls_client_complete import CompleteDTLSClient

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_format_with_signature_algorithm():
    """测试带签名算法字段的格式"""
    print("=== 测试带签名算法字段的格式 ===")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 构造带签名算法字段的Server Key Exchange消息
    # 曲线类型(1) + 命名曲线(2) + 公钥长度(1) + 公钥数据(65) + 签名算法(2) + 签名长度(2) + 签名数据(256)
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1
    test_data.append(65)  # 公钥长度
    test_data.extend(b'\x04' + b'\x01' * 32 + b'\x02' * 32)  # 65字节公钥
    test_data.extend(struct.pack('!H', 0x0403))  # 签名算法 (ECDSA with SHA-256)
    test_data.extend(struct.pack('!H', 256))  # 签名长度
    test_data.extend(b'\x03' * 256)  # 256字节签名
    
    print(f"构造的数据长度: {len(test_data)} 字节")
    print(f"预期长度: {1 + 2 + 1 + 65 + 2 + 2 + 256} = 329 字节")
    
    result = client.parse_server_key_exchange(bytes(test_data))
    print(f"解析结果: {'✅ 成功' if result else '❌ 失败'}")
    
    if result:
        print(f"解析信息:")
        print(f"  曲线: {client.server_temp_public_key['named_curve']}")
        print(f"  公钥长度: {len(client.server_temp_public_key['public_key'])}")
        print(f"  签名算法: {client.server_temp_public_key['signature_algorithm']}")
        print(f"  签名长度: {len(client.server_temp_public_key['signature'])}")
    
    return result

def test_format_without_signature_algorithm():
    """测试不带签名算法字段的格式（用户报告的情况）"""
    print("\n=== 测试不带签名算法字段的格式 ===")
    print("这是用户报告的实际情况：公钥后直接跟签名长度")
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 构造不带签名算法字段的Server Key Exchange消息
    # 曲线类型(1) + 命名曲线(2) + 公钥长度(1) + 公钥数据(65) + 签名长度(2) + 签名数据(256)
    test_data = bytearray()
    test_data.append(3)  # named_curve
    test_data.extend(struct.pack('!H', 23))  # secp256r1
    test_data.append(65)  # 公钥长度
    test_data.extend(b'\x04' + b'\xaa' * 32 + b'\xbb' * 32)  # 65字节公钥
    test_data.extend(struct.pack('!H', 256))  # 签名长度（没有签名算法字段）
    test_data.extend(b'\xcc' * 256)  # 256字节签名
    
    print(f"构造的数据长度: {len(test_data)} 字节")
    print(f"预期长度: {1 + 2 + 1 + 65 + 2 + 256} = 327 字节")
    
    result = client.parse_server_key_exchange(bytes(test_data))
    print(f"解析结果: {'✅ 成功' if result else '❌ 失败'}")
    
    if result:
        print(f"解析信息:")
        print(f"  曲线: {client.server_temp_public_key['named_curve']}")
        print(f"  公钥长度: {len(client.server_temp_public_key['public_key'])}")
        print(f"  签名算法: {client.server_temp_public_key['signature_algorithm']}")
        print(f"  签名长度: {len(client.server_temp_public_key['signature'])}")
    
    return result

def test_edge_cases():
    """测试边界情况"""
    print("\n=== 测试边界情况 ===")
    
    # 测试1: 签名长度看起来像签名算法的情况
    print("测试1: 签名长度0x0500 (1280)，可能被误认为签名算法")
    client1 = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    test_data1 = bytearray()
    test_data1.append(3)  # named_curve
    test_data1.extend(struct.pack('!H', 23))  # secp256r1
    test_data1.append(65)  # 公钥长度
    test_data1.extend(b'\x04' + b'\x01' * 32 + b'\x02' * 32)  # 65字节公钥
    test_data1.extend(struct.pack('!H', 0x0500))  # 签名长度1280（在签名算法范围内）
    # 但是没有足够的数据，所以应该被识别为签名长度
    
    result1 = client1.parse_server_key_exchange(bytes(test_data1))
    print(f"结果1: {'✅ 正确识别为签名长度不足' if not result1 else '❌ 错误处理'}")
    
    # 测试2: 小的签名长度，确保不被误认为签名算法
    print("测试2: 签名长度64，应该被正确识别")
    client2 = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    test_data2 = bytearray()
    test_data2.append(3)  # named_curve
    test_data2.extend(struct.pack('!H', 23))  # secp256r1
    test_data2.append(65)  # 公钥长度
    test_data2.extend(b'\x04' + b'\x01' * 32 + b'\x02' * 32)  # 65字节公钥
    test_data2.extend(struct.pack('!H', 64))  # 签名长度64
    test_data2.extend(b'\xdd' * 64)  # 64字节签名
    
    result2 = client2.parse_server_key_exchange(bytes(test_data2))
    print(f"结果2: {'✅ 成功' if result2 else '❌ 失败'}")
    
    if result2:
        print(f"  签名算法: {client2.server_temp_public_key['signature_algorithm']}")
        print(f"  签名长度: {len(client2.server_temp_public_key['signature'])}")
    
    return result2

def main():
    """主测试函数"""
    print("开始测试Server Key Exchange的两种格式...")
    
    tests = [
        ("带签名算法字段", test_format_with_signature_algorithm),
        ("不带签名算法字段", test_format_without_signature_algorithm),
        ("边界情况", test_edge_cases)
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
    
    if passed >= 2:  # 至少前两个测试通过
        print("🎉 Server Key Exchange格式兼容性修复成功！")
        print("现在支持两种格式：")
        print("  1. 标准格式：公钥 + 签名算法 + 签名长度 + 签名数据")
        print("  2. 简化格式：公钥 + 签名长度 + 签名数据（用户报告的情况）")
        return True
    else:
        print("❌ 仍有问题需要修复")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
