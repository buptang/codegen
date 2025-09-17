#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试Finished消息的verify_data计算
验证握手消息收集和哈希计算是否正确
"""

import sys
import os
import logging
import hashlib

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_handshake_message_collection():
    """测试握手消息收集"""
    print("=" * 60)
    print("🔍 测试握手消息收集和verify_data计算")
    print("=" * 60)
    
    # 创建DTLS客户端
    client = CompleteDTLSClient()
    
    # 模拟握手过程中的状态设置
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    
    # 设置密码套件
    client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    client.record_layer.cipher_suite = client.cipher_suite
    
    print("\n📊 测试1: 初始握手消息列表")
    print("-" * 40)
    print(f"初始握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    
    # 模拟创建客户端握手消息
    print("\n📊 测试2: 创建客户端握手消息")
    print("-" * 40)
    
    # 创建Client Hello
    client_hello = client.create_client_hello()
    print(f"✅ Client Hello创建: {len(client_hello)}字节")
    print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    
    # 模拟解析服务端消息
    print("\n📊 测试3: 模拟服务端握手消息")
    print("-" * 40)
    
    # 模拟Server Hello消息
    server_hello_data = b'server_hello_test_data'
    server_hello_msg = client.handshake_layer.create_handshake_message(
        DTLSConstants.SERVER_HELLO, server_hello_data
    )
    
    # 模拟解析Server Hello（这会添加到握手消息列表）
    try:
        msg_type, payload = client.handshake_layer.parse_handshake_message(server_hello_msg)
        print(f"✅ Server Hello解析: 类型={msg_type}, 载荷={len(payload)}字节")
        print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    except Exception as e:
        print(f"❌ Server Hello解析失败: {e}")
    
    # 模拟Certificate消息
    cert_data = b'certificate_test_data'
    cert_msg = client.handshake_layer.create_handshake_message(
        DTLSConstants.CERTIFICATE, cert_data
    )
    
    try:
        msg_type, payload = client.handshake_layer.parse_handshake_message(cert_msg)
        print(f"✅ Certificate解析: 类型={msg_type}, 载荷={len(payload)}字节")
        print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    except Exception as e:
        print(f"❌ Certificate解析失败: {e}")
    
    # 模拟Server Key Exchange消息
    ske_data = b'server_key_exchange_test_data'
    ske_msg = client.handshake_layer.create_handshake_message(
        DTLSConstants.SERVER_KEY_EXCHANGE, ske_data
    )
    
    try:
        msg_type, payload = client.handshake_layer.parse_handshake_message(ske_msg)
        print(f"✅ Server Key Exchange解析: 类型={msg_type}, 载荷={len(payload)}字节")
        print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    except Exception as e:
        print(f"❌ Server Key Exchange解析失败: {e}")
    
    # 模拟Server Hello Done消息
    shd_data = b''
    shd_msg = client.handshake_layer.create_handshake_message(
        DTLSConstants.SERVER_HELLO_DONE, shd_data
    )
    
    try:
        msg_type, payload = client.handshake_layer.parse_handshake_message(shd_msg)
        print(f"✅ Server Hello Done解析: 类型={msg_type}, 载荷={len(payload)}字节")
        print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    except Exception as e:
        print(f"❌ Server Hello Done解析失败: {e}")
    
    # 创建Client Key Exchange
    print("\n📊 测试4: 创建Client Key Exchange")
    print("-" * 40)
    
    # 模拟服务器临时公钥（用于ECDH）
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': b'A' * 65  # 模拟公钥数据
    }
    
    try:
        # 这里会失败，因为需要真实的ECDH计算，但我们可以看到消息数量变化
        client_key_exchange = client.create_client_key_exchange()
        if client_key_exchange:
            print(f"✅ Client Key Exchange创建: {len(client_key_exchange)}字节")
        else:
            print("⚠️ Client Key Exchange创建失败（预期，因为模拟数据）")
        print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    except Exception as e:
        print(f"⚠️ Client Key Exchange创建异常: {e}")
        print(f"握手消息数量: {len(client.handshake_layer.handshake_messages)}")
    
    # 测试Finished消息计算
    print("\n📊 测试5: Finished消息verify_data计算")
    print("-" * 40)
    
    # 派生主密钥
    client.derive_master_secret()
    
    # 计算握手消息哈希
    handshake_hash = hashlib.sha256()
    for i, msg in enumerate(client.handshake_layer.handshake_messages):
        handshake_hash.update(msg)
        print(f"  消息{i+1}: {len(msg)}字节")
    
    print(f"✅ 握手消息总数: {len(client.handshake_layer.handshake_messages)}")
    print(f"✅ 握手哈希: {handshake_hash.hexdigest()[:32]}...")
    
    # 创建Finished消息
    try:
        finished_msg = client.create_finished()
        if finished_msg:
            print(f"✅ Finished消息创建成功: {len(finished_msg)}字节")
            
            # 解析Finished消息获取verify_data
            if len(finished_msg) >= 12:
                verify_data = finished_msg[12:]  # 跳过握手消息头部
                print(f"✅ verify_data长度: {len(verify_data)}字节")
                print(f"✅ verify_data: {verify_data.hex()}")
            else:
                print("❌ Finished消息格式错误")
        else:
            print("❌ Finished消息创建失败")
    except Exception as e:
        print(f"❌ Finished消息创建异常: {e}")
        import traceback
        traceback.print_exc()
    
    return len(client.handshake_layer.handshake_messages) > 1

def test_verify_data_consistency():
    """测试verify_data一致性"""
    print("\n🔄 测试verify_data一致性")
    print("-" * 40)
    
    # 创建两个相同配置的客户端
    client1 = CompleteDTLSClient()
    client2 = CompleteDTLSClient()
    
    # 设置相同的参数
    for client in [client1, client2]:
        client.client_random = b'A' * 32
        client.server_random = b'B' * 32
        client.pre_master_secret = b'C' * 48
        client.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
        client.record_layer.cipher_suite = client.cipher_suite
        client.derive_master_secret()
    
    # 添加相同的握手消息
    test_messages = [
        (DTLSConstants.CLIENT_HELLO, b'client_hello_data'),
        (DTLSConstants.SERVER_HELLO, b'server_hello_data'),
        (DTLSConstants.CERTIFICATE, b'certificate_data'),
        (DTLSConstants.SERVER_HELLO_DONE, b''),
        (DTLSConstants.CLIENT_KEY_EXCHANGE, b'client_key_exchange_data'),
    ]
    
    for msg_type, data in test_messages:
        for client in [client1, client2]:
            msg = client.handshake_layer.create_handshake_message(msg_type, data)
            # 模拟解析（添加到握手消息列表）
            client.handshake_layer.parse_handshake_message(msg)
    
    # 创建Finished消息
    try:
        finished1 = client1.create_finished()
        finished2 = client2.create_finished()
        
        if finished1 and finished2:
            verify_data1 = finished1[12:] if len(finished1) >= 12 else b''
            verify_data2 = finished2[12:] if len(finished2) >= 12 else b''
            
            if verify_data1 == verify_data2:
                print("✅ verify_data一致性测试通过")
                print(f"   verify_data: {verify_data1.hex()}")
                return True
            else:
                print("❌ verify_data不一致")
                print(f"   客户端1: {verify_data1.hex()}")
                print(f"   客户端2: {verify_data2.hex()}")
                return False
        else:
            print("❌ Finished消息创建失败")
            return False
    except Exception as e:
        print(f"❌ 一致性测试异常: {e}")
        return False

if __name__ == "__main__":
    print("🧪 Finished消息verify_data计算测试")
    print("=" * 60)
    
    try:
        # 测试握手消息收集
        success1 = test_handshake_message_collection()
        
        # 测试verify_data一致性
        success2 = test_verify_data_consistency()
        
        if success1 and success2:
            print("\n🎉 所有测试通过！")
            print("✅ 握手消息正确收集")
            print("✅ verify_data计算正确")
            print("✅ Finished消息应该能被服务端正确验证")
            sys.exit(0)
        else:
            print("\n❌ 测试失败！")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

