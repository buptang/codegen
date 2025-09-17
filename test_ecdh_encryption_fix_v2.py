#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试ECDH公钥修复和加密功能 - 修复版
"""

import sys
import logging
from dtls_client_complete import CompleteDTLSClient, DTLSConstants
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# 配置日志
logging.basicConfig(level=logging.INFO)  # 减少日志输出
logger = logging.getLogger(__name__)

def generate_valid_server_public_key():
    """生成有效的服务器椭圆曲线公钥"""
    # 生成一个真实的secp256r1密钥对作为模拟服务器密钥
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()
    
    # 序列化公钥
    server_public_key_data = server_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    return server_public_key_data

def test_ecdh_public_key_serialization():
    """测试ECDH公钥序列化修复"""
    print("=== 测试ECDH公钥序列化修复 ===")
    
    # 创建客户端
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 使用真实的服务器椭圆曲线公钥
    server_public_key_data = generate_valid_server_public_key()
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': server_public_key_data
    }
    
    try:
        # 测试ECDH密钥交换创建
        client_key_exchange = client._create_ecdh_client_key_exchange()
        
        if client_key_exchange:
            print(f"✅ ECDH Client Key Exchange创建成功，长度: {len(client_key_exchange)} 字节")
            
            # 检查客户端公钥是否正确生成
            if hasattr(client, 'client_ecdh_public_key') and client.client_ecdh_public_key:
                # 使用标准方式序列化公钥
                public_key_data = client.client_ecdh_public_key.public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint
                )
                print(f"✅ 客户端公钥序列化成功，长度: {len(public_key_data)} 字节")
                print(f"   公钥数据前16字节: {public_key_data[:16].hex()}")
                
                # 验证公钥不是全零
                if public_key_data != b'\x00' * len(public_key_data) and public_key_data[0] == 0x04:
                    print("✅ 公钥数据非零且格式正确，修复成功！")
                    
                    # 验证预主密钥生成
                    if hasattr(client, 'pre_master_secret') and client.pre_master_secret:
                        print(f"✅ 预主密钥生成成功，长度: {len(client.pre_master_secret)} 字节")
                        return True
                    else:
                        print("❌ 预主密钥未生成")
                        return False
                else:
                    print("❌ 公钥数据格式错误")
                    return False
            else:
                print("❌ 客户端公钥未生成")
                return False
        else:
            print("❌ ECDH Client Key Exchange创建失败")
            return False
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

def test_record_layer_encryption():
    """测试记录层加密功能"""
    print("\n=== 测试记录层加密功能 ===")
    
    # 创建客户端
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    try:
        # 模拟密钥材料
        client.client_write_key = b'\x01' * 16  # 128位密钥
        client.client_write_iv = b'\x02' * 4    # 4字节IV
        
        # 记录加密前的状态
        old_epoch = client.record_layer.epoch
        old_seq = client.record_layer.sequence_number
        
        # 测试启用加密
        client.record_layer.enable_encryption(client.client_write_key, client.client_write_iv)
        
        if client.record_layer.encryption_enabled:
            print("✅ 记录层加密已启用")
            print(f"   Epoch: {old_epoch} -> {client.record_layer.epoch}")
            print(f"   序列号: {old_seq} -> {client.record_layer.sequence_number}")
            
            # 测试加密数据
            test_data = b"Hello DTLS Encryption!"
            encrypted_record = client.record_layer.create_record(
                DTLSConstants.HANDSHAKE, test_data)
            
            print(f"✅ 加密记录创建成功，长度: {len(encrypted_record)} 字节")
            print(f"   原始数据长度: {len(test_data)} 字节")
            print(f"   加密开销: {len(encrypted_record) - 13 - len(test_data)} 字节")
            
            # 验证记录格式和加密
            if len(encrypted_record) > 13 + len(test_data):  # 应该有加密开销
                print("✅ 数据已加密（有加密开销）")
                return True
            else:
                print("❌ 数据可能未加密")
                return False
        else:
            print("❌ 记录层加密未启用")
            return False
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

def test_bundled_messages_with_encryption():
    """测试合并消息包含加密"""
    print("\n=== 测试合并消息包含加密 ===")
    
    # 创建客户端
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    try:
        # 模拟必要的状态
        client.client_random = b'\x01' * 32
        client.server_random = b'\x02' * 32
        client.pre_master_secret = b'\x03' * 48
        client.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
        
        # 使用真实的服务器椭圆曲线公钥
        server_public_key_data = generate_valid_server_public_key()
        client.server_temp_public_key = {
            'named_curve': 23,  # secp256r1
            'public_key': server_public_key_data
        }
        
        # 创建合并消息包
        bundled_message = client.create_bundled_client_messages()
        
        if bundled_message:
            print(f"✅ 合并消息包创建成功，总长度: {len(bundled_message)} 字节")
            
            # 分析记录结构
            records = []
            offset = 0
            while offset < len(bundled_message):
                if offset + 13 <= len(bundled_message):
                    # 读取记录头
                    content_type = bundled_message[offset]
                    epoch = int.from_bytes(bundled_message[offset+3:offset+5], 'big')
                    record_length = int.from_bytes(bundled_message[offset+11:offset+13], 'big')
                    
                    records.append({
                        'type': content_type,
                        'epoch': epoch,
                        'length': record_length
                    })
                    
                    offset += 13 + record_length
                else:
                    break
            
            if len(records) == 3:
                print("✅ 包含3个记录：")
                for i, record in enumerate(records):
                    type_name = {
                        DTLSConstants.HANDSHAKE: "Handshake",
                        DTLSConstants.CHANGE_CIPHER_SPEC: "Change Cipher Spec"
                    }.get(record['type'], f"Type {record['type']}")
                    
                    print(f"   {i+1}. {type_name} (Epoch: {record['epoch']}, 长度: {record['length']})")
                
                # 验证Finished消息使用了新的epoch（加密）
                if records[2]['epoch'] > records[0]['epoch']:
                    print("✅ Finished消息使用新epoch，已加密！")
                    return True
                else:
                    print("❌ Finished消息epoch未更新")
                    return False
            else:
                print(f"❌ 记录数量错误: {len(records)}")
                return False
        else:
            print("❌ 合并消息包创建失败")
            return False
            
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

def main():
    """主测试函数"""
    print("开始测试ECDH和加密修复...")
    
    tests = [
        test_ecdh_public_key_serialization,
        test_record_layer_encryption,
        test_bundled_messages_with_encryption
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print(f"\n=== 测试结果 ===")
    print(f"通过: {passed}/{total}")
    
    if passed == total:
        print("🎉 所有测试通过！ECDH公钥和加密修复成功！")
        return True
    else:
        print("❌ 部分测试失败，需要进一步修复")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

