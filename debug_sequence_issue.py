#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
调试DTLS握手序号问题
模拟真实握手流程，找出序号错误的根本原因
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
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def extract_handshake_sequence(handshake_msg: bytes) -> int:
    """从握手消息中提取序号"""
    if len(handshake_msg) < 6:
        return -1
    return struct.unpack('!H', handshake_msg[4:6])[0]

def extract_record_sequence(record: bytes) -> int:
    """从记录中提取记录层序号"""
    if len(record) < 11:
        return -1
    return int.from_bytes(record[5:11], 'big')

def debug_real_handshake_flow():
    """调试真实握手流程中的序号问题"""
    print("=" * 70)
    print("🔍 调试真实DTLS握手流程序号问题")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    print(f"\n📊 初始状态:")
    print(f"   握手层序号: {client.handshake_layer.message_sequence}")
    print(f"   记录层序号: {client.record_layer.sequence_number}")
    print(f"   记录层epoch: {client.record_layer.epoch}")
    
    # 步骤1: 第一次Client Hello (无Cookie)
    print(f"\n🔸 步骤1: 创建第一次Client Hello (无Cookie)")
    client_hello_1 = client.create_client_hello()
    hs_seq_1 = extract_handshake_sequence(client_hello_1)
    
    record_1 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_hello_1)
    rec_seq_1 = extract_record_sequence(record_1)
    
    print(f"   握手消息序号: {hs_seq_1}")
    print(f"   记录层序号: {rec_seq_1}")
    print(f"   握手层状态: {client.handshake_layer.message_sequence}")
    print(f"   记录层状态: {client.record_layer.sequence_number}")
    
    # 步骤2: 模拟收到Hello Verify Request，设置Cookie
    print(f"\n🔸 步骤2: 设置Cookie (模拟Hello Verify Request)")
    client.cookie = b'test_cookie_12345'
    
    # 步骤3: 第二次Client Hello (带Cookie)
    print(f"\n🔸 步骤3: 创建第二次Client Hello (带Cookie)")
    client_hello_2 = client.create_client_hello()
    hs_seq_2 = extract_handshake_sequence(client_hello_2)
    
    record_2 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_hello_2)
    rec_seq_2 = extract_record_sequence(record_2)
    
    print(f"   握手消息序号: {hs_seq_2}")
    print(f"   记录层序号: {rec_seq_2}")
    print(f"   握手层状态: {client.handshake_layer.message_sequence}")
    print(f"   记录层状态: {client.record_layer.sequence_number}")
    
    # 步骤4: 模拟服务器响应 (Server Hello, Certificate, Server Key Exchange, Server Hello Done)
    print(f"\n🔸 步骤4: 模拟服务器握手消息")
    
    # 模拟服务器消息（这些会增加握手消息列表但不影响客户端序号）
    server_messages = [
        (DTLSConstants.SERVER_HELLO, b'server_hello_data'),
        (DTLSConstants.CERTIFICATE, b'certificate_data'),
        (DTLSConstants.SERVER_KEY_EXCHANGE, b'server_key_exchange_data'),
        (DTLSConstants.SERVER_HELLO_DONE, b'')
    ]
    
    for msg_type, data in server_messages:
        # 创建服务器消息（用于测试）
        server_msg = client.handshake_layer.create_handshake_message(msg_type, data)
        # 模拟解析（这会添加到握手消息列表）
        client.handshake_layer.parse_handshake_message(server_msg)
    
    print(f"   处理服务器消息后握手层状态: {client.handshake_layer.message_sequence}")
    print(f"   握手消息总数: {len(client.handshake_layer.handshake_messages)}")
    
    # 步骤5: 设置必要的密钥材料
    print(f"\n🔸 步骤5: 设置密钥材料")
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    
    # 设置有效的服务器临时公钥
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import serialization
    
    # 生成真实的ECDH密钥对用于测试
    curve = ec.SECP256R1()
    server_private_key = ec.generate_private_key(curve)
    server_public_key = server_private_key.public_key()
    
    # 序列化服务器公钥
    server_public_key_data = server_public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': server_public_key_data
    }
    
    print(f"   设置密钥材料完成")
    print(f"   当前握手层序号: {client.handshake_layer.message_sequence}")
    
    # 步骤6: 创建Client Key Exchange
    print(f"\n🔸 步骤6: 创建Client Key Exchange")
    client_key_exchange = client.create_client_key_exchange()
    
    if client_key_exchange:
        hs_seq_3 = extract_handshake_sequence(client_key_exchange)
        print(f"   ✅ Client Key Exchange创建成功")
        print(f"   握手消息序号: {hs_seq_3}")
        print(f"   握手层状态: {client.handshake_layer.message_sequence}")
        
        # 创建记录
        record_3 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_key_exchange)
        rec_seq_3 = extract_record_sequence(record_3)
        print(f"   记录层序号: {rec_seq_3}")
        print(f"   记录层状态: {client.record_layer.sequence_number}")
    else:
        print(f"   ❌ Client Key Exchange创建失败")
        return False
    
    # 步骤7: 派生密钥
    print(f"\n🔸 步骤7: 派生密钥")
    client.derive_master_secret()
    client.derive_key_material()
    print(f"   密钥派生完成")
    
    # 步骤8: 创建Change Cipher Spec
    print(f"\n🔸 步骤8: 创建Change Cipher Spec")
    change_cipher_spec = struct.pack('!B', 1)
    record_4 = client.record_layer.create_record(DTLSConstants.CHANGE_CIPHER_SPEC, change_cipher_spec)
    rec_seq_4 = extract_record_sequence(record_4)
    
    print(f"   Change Cipher Spec创建完成")
    print(f"   记录层序号: {rec_seq_4}")
    print(f"   记录层状态: {client.record_layer.sequence_number}")
    print(f"   握手层状态: {client.handshake_layer.message_sequence} (应该不变)")
    
    # 步骤9: 启用加密
    print(f"\n🔸 步骤9: 启用加密")
    print(f"   启用前 - 记录层序号: {client.record_layer.sequence_number}, epoch: {client.record_layer.epoch}")
    
    mac_key = getattr(client, 'client_write_mac_key', None)
    client.record_layer.enable_encryption(client.client_write_key, client.client_write_iv, mac_key)
    
    print(f"   启用后 - 记录层序号: {client.record_layer.sequence_number}, epoch: {client.record_layer.epoch}")
    print(f"   握手层状态: {client.handshake_layer.message_sequence} (应该不变)")
    
    # 步骤10: 创建Finished消息
    print(f"\n🔸 步骤10: 创建Finished消息")
    finished_msg = client.create_finished()
    
    if finished_msg:
        hs_seq_5 = extract_handshake_sequence(finished_msg)
        print(f"   ✅ Finished消息创建成功")
        print(f"   握手消息序号: {hs_seq_5}")
        print(f"   握手层状态: {client.handshake_layer.message_sequence}")
        
        # 创建加密记录
        record_5 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, finished_msg)
        rec_seq_5 = extract_record_sequence(record_5)
        print(f"   记录层序号: {rec_seq_5}")
        print(f"   记录层状态: {client.record_layer.sequence_number}")
    else:
        print(f"   ❌ Finished消息创建失败")
        return False
    
    # 总结分析
    print(f"\n📋 序号分析总结")
    print("=" * 70)
    
    expected_handshake_seqs = [0, 1, 2, 3]  # Client Hello #1, #2, Client Key Exchange, Finished
    actual_handshake_seqs = [hs_seq_1, hs_seq_2, hs_seq_3, hs_seq_5]
    
    expected_record_seqs_epoch0 = [0, 1, 2, 3]  # 前4个记录在epoch 0
    expected_record_seqs_epoch1 = [0]  # Finished在epoch 1
    actual_record_seqs = [rec_seq_1, rec_seq_2, rec_seq_3, rec_seq_4, rec_seq_5]
    
    print(f"握手消息序号:")
    print(f"   期望: {expected_handshake_seqs}")
    print(f"   实际: {actual_handshake_seqs}")
    
    print(f"记录层序号:")
    print(f"   实际: {actual_record_seqs}")
    print(f"   说明: 前4个在epoch 0，最后1个在epoch 1")
    
    # 检查是否正确
    handshake_correct = actual_handshake_seqs == expected_handshake_seqs
    
    if handshake_correct:
        print(f"\n✅ 握手消息序号完全正确！")
        print(f"✅ 问题不在序号管理，可能在其他地方")
        return True
    else:
        print(f"\n❌ 握手消息序号存在问题！")
        for i, (expected, actual) in enumerate(zip(expected_handshake_seqs, actual_handshake_seqs)):
            if expected != actual:
                print(f"   消息{i}: 期望{expected}, 实际{actual}")
        return False

if __name__ == "__main__":
    print("🔍 DTLS握手序号问题调试")
    
    try:
        success = debug_real_handshake_flow()
        
        if success:
            print("\n🎉 序号管理正常！")
            print("问题可能在于:")
            print("1. 实际握手流程与测试不同")
            print("2. 网络传输过程中的问题")
            print("3. 服务端对序号的特殊要求")
            sys.exit(0)
        else:
            print("\n❌ 发现序号管理问题！")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 调试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

