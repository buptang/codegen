#!/usr/bin/env python3
"""
测试ECDH功能的简单脚本
"""

import sys
import logging
from dtls_client_complete import CompleteDTLSClient, DTLSConstants
from cryptography.hazmat.primitives.asymmetric import ec

def test_ecdh_key_generation():
    """测试ECDH密钥生成功能"""
    print("🔐 测试ECDH密钥生成功能")
    print("=" * 40)
    
    # 创建DTLS客户端
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 生成有效的服务器临时公钥
    from cryptography.hazmat.primitives.asymmetric import ec
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()
    server_public_numbers = server_public_key.public_numbers()
    
    # 序列化服务器公钥
    coord_length = 32  # secp256r1的坐标长度
    x_bytes = server_public_numbers.x.to_bytes(coord_length, 'big')
    y_bytes = server_public_numbers.y.to_bytes(coord_length, 'big')
    server_public_key_data = b'\x04' + x_bytes + y_bytes
    
    # 模拟服务器临时公钥信息
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': server_public_key_data,  # 有效的公钥数据
        'signature_algorithm': 0x0401,  # RSA-PKCS1-SHA256
        'signature': b'\x00' * 256  # 模拟签名
    }
    
    try:
        # 测试ECDH Client Key Exchange创建
        print("📝 测试ECDH Client Key Exchange创建...")
        client_key_exchange = client._create_ecdh_client_key_exchange()
        
        if client_key_exchange:
            print(f"✅ ECDH Client Key Exchange创建成功")
            print(f"   消息长度: {len(client_key_exchange)} 字节")
            print(f"   预主密钥长度: {len(client.pre_master_secret) if client.pre_master_secret else 0} 字节")
            
            # 检查客户端密钥对是否生成
            if client.client_ecdh_private_key and client.client_ecdh_public_key:
                print("✅ 客户端ECDH密钥对生成成功")
                curve = client.client_ecdh_private_key.curve
                print(f"   使用的椭圆曲线: {curve.name}")
                print(f"   密钥大小: {curve.key_size} 位")
            else:
                print("❌ 客户端ECDH密钥对生成失败")
        else:
            print("❌ ECDH Client Key Exchange创建失败")
            
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

def test_bundled_messages():
    """测试合并消息功能"""
    print("\n📦 测试合并消息功能")
    print("=" * 40)
    
    # 创建DTLS客户端
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 设置必要的状态
    client.client_random = b'\x00' * 32
    client.server_random = b'\x00' * 32
    client.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
    
    # 生成有效的服务器临时公钥（用于ECDH）
    from cryptography.hazmat.primitives.asymmetric import ec
    server_private_key = ec.generate_private_key(ec.SECP256R1())
    server_public_key = server_private_key.public_key()
    server_public_numbers = server_public_key.public_numbers()
    
    # 序列化服务器公钥
    coord_length = 32  # secp256r1的坐标长度
    x_bytes = server_public_numbers.x.to_bytes(coord_length, 'big')
    y_bytes = server_public_numbers.y.to_bytes(coord_length, 'big')
    server_public_key_data = b'\x04' + x_bytes + y_bytes
    
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': server_public_key_data,  # 有效的公钥数据
        'signature_algorithm': 0x0401,
        'signature': b'\x00' * 256
    }
    
    try:
        print("📝 测试合并消息包创建...")
        bundled_messages = client.create_bundled_client_messages()
        
        if bundled_messages:
            print(f"✅ 合并消息包创建成功")
            print(f"   总长度: {len(bundled_messages)} 字节")
            
            # 分析消息包结构
            print("📊 消息包结构分析:")
            offset = 0
            message_count = 0
            
            while offset < len(bundled_messages) and message_count < 3:
                if offset + 13 <= len(bundled_messages):  # DTLS记录头长度
                    content_type = bundled_messages[offset]
                    version = int.from_bytes(bundled_messages[offset+1:offset+3], 'big')
                    epoch = int.from_bytes(bundled_messages[offset+3:offset+5], 'big')
                    sequence = int.from_bytes(bundled_messages[offset+5:offset+11], 'big')
                    length = int.from_bytes(bundled_messages[offset+11:offset+13], 'big')
                    
                    content_type_names = {
                        20: "Change Cipher Spec",
                        22: "Handshake"
                    }
                    
                    print(f"   消息 {message_count + 1}: {content_type_names.get(content_type, f'Unknown({content_type})')}")
                    print(f"     长度: {length} 字节")
                    print(f"     版本: 0x{version:04x}")
                    print(f"     序列号: {sequence}")
                    
                    offset += 13 + length
                    message_count += 1
                else:
                    break
                    
            print(f"   解析出 {message_count} 个消息")
            
        else:
            print("❌ 合并消息包创建失败")
            
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()

def test_curve_support():
    """测试支持的椭圆曲线"""
    print("\n🔄 测试椭圆曲线支持")
    print("=" * 40)
    
    client = CompleteDTLSClient('localhost', 4433, 'localhost')
    
    # 测试不同的椭圆曲线
    curves_to_test = [
        (23, "secp256r1", ec.SECP256R1()),
        (24, "secp384r1", ec.SECP384R1()),
        (25, "secp521r1", ec.SECP521R1()),
    ]
    
    for curve_id, curve_name, curve_obj in curves_to_test:
        print(f"📝 测试椭圆曲线: {curve_name} (ID: {curve_id})")
        
        try:
            # 生成密钥对
            private_key = ec.generate_private_key(curve_obj)
            public_key = private_key.public_key()
            
            # 序列化公钥
            public_numbers = public_key.public_numbers()
            coord_length = (curve_obj.key_size + 7) // 8
            
            x_bytes = public_numbers.x.to_bytes(coord_length, 'big')
            y_bytes = public_numbers.y.to_bytes(coord_length, 'big')
            public_key_data = b'\x04' + x_bytes + y_bytes
            
            print(f"   ✅ 密钥生成成功")
            print(f"   密钥大小: {curve_obj.key_size} 位")
            print(f"   公钥长度: {len(public_key_data)} 字节")
            
            # 测试重构公钥
            reconstructed_key = client._reconstruct_server_public_key(public_key_data, curve_obj)
            print(f"   ✅ 公钥重构成功")
            
        except Exception as e:
            print(f"   ❌ 测试失败: {e}")

if __name__ == "__main__":
    # 配置日志
    logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
    
    print("🧪 DTLS客户端ECDH功能测试")
    print("=" * 50)
    
    # 运行测试
    test_ecdh_key_generation()
    test_bundled_messages()
    test_curve_support()
    
    print("\n🎉 测试完成！")
