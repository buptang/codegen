#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试DTLS握手消息序号分配
验证握手消息序号是否正确递增
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
    # 握手消息格式: type(1) + length(3) + message_seq(2) + ...
    return struct.unpack('!H', handshake_msg[4:6])[0]

def test_handshake_sequence_numbers():
    """测试握手消息序号分配"""
    print("=" * 60)
    print("🔢 测试DTLS握手消息序号分配")
    print("=" * 60)
    
    # 创建DTLS客户端
    client = CompleteDTLSClient()
    
    print("\n📊 测试握手消息序号递增")
    print("-" * 40)
    
    # 模拟完整握手流程的消息创建
    messages = []
    
    # 1. 第一次Client Hello (无Cookie)
    print("1. 创建第一次Client Hello (无Cookie)")
    client_hello_1 = client.create_client_hello()
    seq1 = extract_handshake_sequence(client_hello_1)
    messages.append(("Client Hello #1", seq1))
    print(f"   序号: {seq1}")
    
    # 2. 模拟收到Hello Verify Request，设置Cookie
    client.cookie = b'test_cookie'
    
    # 3. 第二次Client Hello (带Cookie)
    print("2. 创建第二次Client Hello (带Cookie)")
    client_hello_2 = client.create_client_hello()
    seq2 = extract_handshake_sequence(client_hello_2)
    messages.append(("Client Hello #2", seq2))
    print(f"   序号: {seq2}")
    
    # 4. 模拟服务器临时公钥（用于Client Key Exchange）
    client.server_temp_public_key = {
        'named_curve': 23,  # secp256r1
        'public_key': b'\x04' + b'A' * 64  # 模拟未压缩点格式
    }
    
    # 5. Client Key Exchange
    print("3. 创建Client Key Exchange")
    try:
        client_key_exchange = client.create_client_key_exchange()
        if client_key_exchange:
            seq3 = extract_handshake_sequence(client_key_exchange)
            messages.append(("Client Key Exchange", seq3))
            print(f"   序号: {seq3}")
        else:
            print("   ❌ Client Key Exchange创建失败")
            seq3 = -1
    except Exception as e:
        print(f"   ❌ Client Key Exchange创建异常: {e}")
        seq3 = -1
    
    # 6. 模拟派生密钥
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    client.derive_master_secret()
    
    # 7. Finished消息
    print("4. 创建Finished消息")
    try:
        finished_msg = client.create_finished()
        if finished_msg:
            seq4 = extract_handshake_sequence(finished_msg)
            messages.append(("Finished", seq4))
            print(f"   序号: {seq4}")
        else:
            print("   ❌ Finished消息创建失败")
            seq4 = -1
    except Exception as e:
        print(f"   ❌ Finished消息创建异常: {e}")
        seq4 = -1
    
    # 分析序号分配
    print("\n📋 序号分配分析")
    print("-" * 40)
    
    expected_sequences = [0, 1, 2, 3]  # 期望的序号
    actual_sequences = [seq for _, seq in messages if seq != -1]
    
    print("期望序号: ", expected_sequences)
    print("实际序号: ", actual_sequences)
    
    # 检查序号是否正确
    correct = True
    for i, (msg_name, actual_seq) in enumerate(messages):
        if actual_seq == -1:
            print(f"❌ {msg_name}: 消息创建失败")
            correct = False
        elif i < len(expected_sequences) and actual_seq != expected_sequences[i]:
            print(f"❌ {msg_name}: 期望序号{expected_sequences[i]}, 实际序号{actual_seq}")
            correct = False
        else:
            print(f"✅ {msg_name}: 序号{actual_seq} (正确)")
    
    # 检查序号连续性
    print("\n🔍 序号连续性检查")
    print("-" * 40)
    
    valid_sequences = [seq for seq in actual_sequences if seq != -1]
    if len(valid_sequences) > 1:
        is_continuous = all(valid_sequences[i] == valid_sequences[i-1] + 1 
                           for i in range(1, len(valid_sequences)))
        if is_continuous:
            print("✅ 序号连续递增")
        else:
            print("❌ 序号不连续")
            correct = False
    
    return correct

def test_bundled_messages_sequence():
    """测试合并消息包中的序号"""
    print("\n🎁 测试合并消息包序号")
    print("-" * 40)
    
    client = CompleteDTLSClient()
    
    # 设置必要的状态
    client.client_random = b'A' * 32
    client.server_random = b'B' * 32
    client.pre_master_secret = b'C' * 48
    client.server_temp_public_key = {
        'named_curve': 23,
        'public_key': b'\x04' + b'A' * 64
    }
    
    # 先创建两个Client Hello来推进序号
    client.create_client_hello()  # 序号0
    client.cookie = b'test'
    client.create_client_hello()  # 序号1
    
    print(f"当前握手层序号: {client.handshake_layer.message_sequence}")
    
    # 创建合并消息包
    try:
        bundled = client.create_bundled_client_messages()
        if bundled:
            print("✅ 合并消息包创建成功")
            print(f"合并后握手层序号: {client.handshake_layer.message_sequence}")
            
            # 分析合并消息包中的序号
            # 这需要解析记录层和握手层消息
            print("📦 合并消息包分析:")
            print(f"   总长度: {len(bundled)}字节")
            
            # 简单检查：如果序号从2开始，说明正确
            if client.handshake_layer.message_sequence > 2:
                print("✅ 序号在合并消息创建后正确递增")
                return True
            else:
                print("❌ 序号在合并消息创建后未正确递增")
                return False
        else:
            print("❌ 合并消息包创建失败")
            return False
    except Exception as e:
        print(f"❌ 合并消息包创建异常: {e}")
        return False

def test_record_vs_handshake_sequence():
    """测试记录层序号vs握手消息序号"""
    print("\n🔄 测试记录层序号 vs 握手消息序号")
    print("-" * 40)
    
    client = CompleteDTLSClient()
    
    print(f"初始记录层序号: {client.record_layer.sequence_number}")
    print(f"初始握手层序号: {client.handshake_layer.message_sequence}")
    
    # 创建几个握手消息
    msg1 = client.create_client_hello()
    record1 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, msg1)
    
    client.cookie = b'test'
    msg2 = client.create_client_hello()
    record2 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, msg2)
    
    print(f"创建2个消息后:")
    print(f"  记录层序号: {client.record_layer.sequence_number}")
    print(f"  握手层序号: {client.handshake_layer.message_sequence}")
    
    # 启用加密（这会重置记录层序号）
    client.client_write_key = b'A' * 16
    client.client_write_iv = b'B' * 16
    client.record_layer.enable_encryption(
        client.client_write_key, 
        client.client_write_iv
    )
    
    print(f"启用加密后:")
    print(f"  记录层序号: {client.record_layer.sequence_number} (应该重置为0)")
    print(f"  握手层序号: {client.handshake_layer.message_sequence} (应该保持不变)")
    
    # 验证握手层序号没有被重置
    if client.handshake_layer.message_sequence == 2:
        print("✅ 握手层序号在启用加密后保持正确")
        return True
    else:
        print("❌ 握手层序号在启用加密后被错误重置")
        return False

if __name__ == "__main__":
    print("🧪 DTLS握手消息序号测试")
    print("=" * 60)
    
    try:
        # 测试基本序号分配
        success1 = test_handshake_sequence_numbers()
        
        # 测试合并消息包序号
        success2 = test_bundled_messages_sequence()
        
        # 测试记录层vs握手层序号
        success3 = test_record_vs_handshake_sequence()
        
        if success1 and success2 and success3:
            print("\n🎉 所有序号测试通过！")
            print("✅ 握手消息序号正确递增")
            print("✅ 合并消息包序号正确")
            print("✅ 记录层和握手层序号独立管理")
            sys.exit(0)
        else:
            print("\n❌ 序号测试失败！")
            print("需要修复握手消息序号管理")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

