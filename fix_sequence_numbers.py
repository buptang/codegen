#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
修复DTLS握手消息序号问题
确保客户端握手消息序号正确递增
"""

import sys
import os
import logging
import struct

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def extract_handshake_sequence(handshake_msg: bytes) -> int:
    """从握手消息中提取序号"""
    if len(handshake_msg) < 6:
        return -1
    return struct.unpack('!H', handshake_msg[4:6])[0]

def test_correct_sequence_flow():
    """测试正确的序号流程（不使用create_handshake_message创建服务器消息）"""
    print("=" * 70)
    print("🔧 测试修复后的握手消息序号")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    print(f"\n📊 初始状态:")
    print(f"   握手层序号: {client.handshake_layer.message_sequence}")
    
    # 步骤1: 第一次Client Hello (无Cookie)
    print(f"\n🔸 步骤1: 创建第一次Client Hello (无Cookie)")
    client_hello_1 = client.create_client_hello()
    hs_seq_1 = extract_handshake_sequence(client_hello_1)
    print(f"   握手消息序号: {hs_seq_1}")
    print(f"   握手层状态: {client.handshake_layer.message_sequence}")
    
    # 步骤2: 模拟收到Hello Verify Request，设置Cookie
    print(f"\n🔸 步骤2: 设置Cookie (模拟Hello Verify Request)")
    client.cookie = b'test_cookie_12345'
    
    # 步骤3: 第二次Client Hello (带Cookie)
    print(f"\n🔸 步骤3: 创建第二次Client Hello (带Cookie)")
    client_hello_2 = client.create_client_hello()
    hs_seq_2 = extract_handshake_sequence(client_hello_2)
    print(f"   握手消息序号: {hs_seq_2}")
    print(f"   握手层状态: {client.handshake_layer.message_sequence}")
    
    # 步骤4: 模拟服务器响应 - 正确的方式（直接添加到握手消息列表）
    print(f"\n🔸 步骤4: 模拟服务器握手消息（正确方式）")
    
    # 创建模拟的服务器握手消息（不使用create_handshake_message）
    def create_mock_server_message(msg_type: int, data: bytes, msg_seq: int) -> bytes:
        """创建模拟的服务器握手消息，不影响客户端序号"""
        length = len(data)
        message = (struct.pack("!B", msg_type) + 
                  struct.pack("!I", length)[1:] +  # 3字节长度
                  struct.pack("!H", msg_seq) +     # 服务器的消息序号
                  struct.pack("!I", 0)[1:] +       # 3字节fragment_offset
                  struct.pack("!I", length)[1:] +  # 3字节fragment_length
                  data)
        return message
    
    # 模拟服务器消息（使用服务器的序号）
    server_messages = [
        (DTLSConstants.SERVER_HELLO, b'server_hello_data', 0),
        (DTLSConstants.CERTIFICATE, b'certificate_data', 1),
        (DTLSConstants.SERVER_KEY_EXCHANGE, b'server_key_exchange_data', 2),
        (DTLSConstants.SERVER_HELLO_DONE, b'', 3)
    ]
    
    for msg_type, data, server_seq in server_messages:
        # 创建服务器消息（不影响客户端序号）
        server_msg = create_mock_server_message(msg_type, data, server_seq)
        # 解析并添加到握手消息列表
        client.handshake_layer.parse_handshake_message(server_msg)
    
    print(f"   处理服务器消息后客户端握手层状态: {client.handshake_layer.message_sequence}")
    print(f"   握手消息总数: {len(client.handshake_layer.handshake_messages)}")
    
    # 步骤5: 设置必要的密钥材料
    print(f"\n🔸 步骤5: 设置密钥材料")
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    
    # 设置有效的服务器临时公钥
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    
    curve = ec.SECP256R1()
    server_private_key = ec.generate_private_key(curve)
    server_public_key = server_private_key.public_key()
    
    server_public_key_data = server_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': server_public_key_data
    }
    
    print(f"   当前握手层序号: {client.handshake_layer.message_sequence}")
    
    # 步骤6: 创建Client Key Exchange
    print(f"\n🔸 步骤6: 创建Client Key Exchange")
    client_key_exchange = client.create_client_key_exchange()
    
    if client_key_exchange:
        hs_seq_3 = extract_handshake_sequence(client_key_exchange)
        print(f"   ✅ Client Key Exchange创建成功")
        print(f"   握手消息序号: {hs_seq_3}")
        print(f"   握手层状态: {client.handshake_layer.message_sequence}")
    else:
        print(f"   ❌ Client Key Exchange创建失败")
        return False
    
    # 步骤7: 派生密钥并创建Finished消息
    print(f"\n🔸 步骤7: 派生密钥并创建Finished消息")
    client.derive_master_secret()
    client.derive_key_material()
    
    finished_msg = client.create_finished()
    
    if finished_msg:
        hs_seq_4 = extract_handshake_sequence(finished_msg)
        print(f"   ✅ Finished消息创建成功")
        print(f"   握手消息序号: {hs_seq_4}")
        print(f"   握手层状态: {client.handshake_layer.message_sequence}")
    else:
        print(f"   ❌ Finished消息创建失败")
        return False
    
    # 分析结果
    print(f"\n📋 序号分析结果")
    print("=" * 70)
    
    expected_sequences = [0, 1, 2, 3]  # 期望的客户端握手消息序号
    actual_sequences = [hs_seq_1, hs_seq_2, hs_seq_3, hs_seq_4]
    
    print(f"客户端握手消息序号:")
    print(f"   期望: {expected_sequences}")
    print(f"   实际: {actual_sequences}")
    
    # 检查是否正确
    if actual_sequences == expected_sequences:
        print(f"\n✅ 握手消息序号完全正确！")
        print(f"✅ Client Hello #1: {hs_seq_1}")
        print(f"✅ Client Hello #2: {hs_seq_2}")
        print(f"✅ Client Key Exchange: {hs_seq_3}")
        print(f"✅ Finished: {hs_seq_4}")
        return True
    else:
        print(f"\n❌ 握手消息序号仍有问题！")
        for i, (expected, actual) in enumerate(zip(expected_sequences, actual_sequences)):
            if expected != actual:
                print(f"   消息{i}: 期望{expected}, 实际{actual}")
        return False

def test_bundled_messages_with_correct_sequence():
    """测试合并消息包的正确序号"""
    print(f"\n🎁 测试合并消息包的正确序号")
    print("-" * 50)
    
    client = CompleteDTLSClient()
    
    # 设置必要的状态
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    
    # 设置有效的服务器临时公钥
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    
    curve = ec.SECP256R1()
    server_private_key = ec.generate_private_key(curve)
    server_public_key = server_private_key.public_key()
    
    server_public_key_data = server_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    client.server_temp_public_key = {
        'named_curve': 23,
        'public_key': server_public_key_data
    }
    
    # 创建两个Client Hello来推进序号到正确位置
    client.create_client_hello()  # 序号0
    client.cookie = b'test'
    client.create_client_hello()  # 序号1
    
    print(f"创建Client Hello后握手层序号: {client.handshake_layer.message_sequence}")
    
    # 模拟服务器消息（不影响客户端序号）
    def create_mock_server_message(msg_type: int, data: bytes, msg_seq: int) -> bytes:
        length = len(data)
        message = (struct.pack("!B", msg_type) + 
                  struct.pack("!I", length)[1:] +
                  struct.pack("!H", msg_seq) +
                  struct.pack("!I", 0)[1:] +
                  struct.pack("!I", length)[1:] +
                  data)
        return message
    
    # 添加服务器消息到握手消息列表
    server_messages = [
        (DTLSConstants.SERVER_HELLO, b'server_hello_data', 0),
        (DTLSConstants.CERTIFICATE, b'certificate_data', 1),
        (DTLSConstants.SERVER_KEY_EXCHANGE, b'server_key_exchange_data', 2),
        (DTLSConstants.SERVER_HELLO_DONE, b'', 3)
    ]
    
    for msg_type, data, server_seq in server_messages:
        server_msg = create_mock_server_message(msg_type, data, server_seq)
        client.handshake_layer.parse_handshake_message(server_msg)
    
    print(f"添加服务器消息后握手层序号: {client.handshake_layer.message_sequence}")
    
    # 创建合并消息包
    try:
        bundled = client.create_bundled_client_messages()
        if bundled:
            print("✅ 合并消息包创建成功")
            print(f"合并后握手层序号: {client.handshake_layer.message_sequence}")
            
            # 期望：Client Key Exchange(2) + Finished(3)
            expected_final_seq = 4  # 创建了2个客户端消息后的序号
            if client.handshake_layer.message_sequence == expected_final_seq:
                print("✅ 合并消息包中的序号正确")
                return True
            else:
                print(f"❌ 合并消息包序号错误: 期望{expected_final_seq}, 实际{client.handshake_layer.message_sequence}")
                return False
        else:
            print("❌ 合并消息包创建失败")
            return False
    except Exception as e:
        print(f"❌ 合并消息包创建异常: {e}")
        return False

if __name__ == "__main__":
    print("🔧 DTLS握手消息序号修复测试")
    
    try:
        # 测试正确的序号流程
        success1 = test_correct_sequence_flow()
        
        # 测试合并消息包序号
        success2 = test_bundled_messages_with_correct_sequence()
        
        if success1 and success2:
            print("\n🎉 序号修复成功！")
            print("✅ 客户端握手消息序号正确递增")
            print("✅ 服务器消息不影响客户端序号")
            print("✅ 合并消息包序号正确")
            print("\n💡 修复方案:")
            print("1. 服务器消息通过parse_handshake_message添加到握手消息列表")
            print("2. 不使用create_handshake_message创建服务器消息")
            print("3. 客户端握手消息序号独立管理")
            sys.exit(0)
        else:
            print("\n❌ 序号修复失败！")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

