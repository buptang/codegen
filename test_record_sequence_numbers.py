#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试DTLS记录层序号问题
验证Client Key Exchange和Change Cipher Spec的记录层序号
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

def extract_record_sequence(record: bytes) -> tuple:
    """从DTLS记录中提取序号和epoch"""
    if len(record) < 11:
        return -1, -1
    
    # DTLS记录格式: type(1) + version(2) + epoch(2) + sequence(6) + length(2) + data
    epoch = struct.unpack('!H', record[3:5])[0]
    sequence = int.from_bytes(record[5:11], 'big')
    return epoch, sequence

def test_record_layer_sequences():
    """测试记录层序号分配"""
    print("=" * 70)
    print("🔍 测试DTLS记录层序号分配")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    print(f"\n📊 初始记录层状态:")
    print(f"   序号: {client.record_layer.sequence_number}")
    print(f"   epoch: {client.record_layer.epoch}")
    
    # 模拟完整握手流程的记录创建
    records = []
    
    # 1. 第一次Client Hello (无Cookie)
    print(f"\n🔸 步骤1: 创建第一次Client Hello记录")
    client_hello_1 = client.create_client_hello()
    record_1 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_hello_1)
    epoch_1, seq_1 = extract_record_sequence(record_1)
    records.append(("Client Hello #1", epoch_1, seq_1))
    
    print(f"   记录层序号: {seq_1}, epoch: {epoch_1}")
    print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 2. 第二次Client Hello (带Cookie)
    print(f"\n🔸 步骤2: 创建第二次Client Hello记录")
    client.cookie = b'test_cookie'
    client_hello_2 = client.create_client_hello()
    record_2 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_hello_2)
    epoch_2, seq_2 = extract_record_sequence(record_2)
    records.append(("Client Hello #2", epoch_2, seq_2))
    
    print(f"   记录层序号: {seq_2}, epoch: {epoch_2}")
    print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 3. 设置必要的密钥材料
    print(f"\n🔸 步骤3: 设置密钥材料")
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
    
    # 4. 单独创建Client Key Exchange记录
    print(f"\n🔸 步骤4: 创建Client Key Exchange记录")
    client_key_exchange = client.create_client_key_exchange()
    if client_key_exchange:
        record_3 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_key_exchange)
        epoch_3, seq_3 = extract_record_sequence(record_3)
        records.append(("Client Key Exchange", epoch_3, seq_3))
        
        print(f"   记录层序号: {seq_3}, epoch: {epoch_3}")
        print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    else:
        print("   ❌ Client Key Exchange创建失败")
        return False
    
    # 5. 创建Change Cipher Spec记录
    print(f"\n🔸 步骤5: 创建Change Cipher Spec记录")
    change_cipher_spec = struct.pack('!B', 1)
    record_4 = client.record_layer.create_record(DTLSConstants.CHANGE_CIPHER_SPEC, change_cipher_spec)
    epoch_4, seq_4 = extract_record_sequence(record_4)
    records.append(("Change Cipher Spec", epoch_4, seq_4))
    
    print(f"   记录层序号: {seq_4}, epoch: {epoch_4}")
    print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 6. 派生密钥并启用加密
    print(f"\n🔸 步骤6: 启用加密")
    client.derive_master_secret()
    client.derive_key_material()
    
    print(f"   启用前: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    mac_key = getattr(client, 'client_write_mac_key', None)
    client.record_layer.enable_encryption(client.client_write_key, client.record_layer.client_write_iv, mac_key)
    
    print(f"   启用后: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 7. 创建Finished记录（加密）
    print(f"\n🔸 步骤7: 创建Finished记录（加密）")
    finished_msg = client.create_finished()
    if finished_msg:
        record_5 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, finished_msg)
        epoch_5, seq_5 = extract_record_sequence(record_5)
        records.append(("Finished", epoch_5, seq_5))
        
        print(f"   记录层序号: {seq_5}, epoch: {epoch_5}")
        print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    else:
        print("   ❌ Finished消息创建失败")
        return False
    
    # 分析结果
    print(f"\n📋 记录层序号分析")
    print("=" * 70)
    
    expected_sequences = [
        ("Client Hello #1", 0, 0),
        ("Client Hello #2", 0, 1), 
        ("Client Key Exchange", 0, 2),
        ("Change Cipher Spec", 0, 3),
        ("Finished", 1, 0)  # 新epoch，序号重置
    ]
    
    print("期望的记录层序号:")
    for name, exp_epoch, exp_seq in expected_sequences:
        print(f"   {name}: epoch={exp_epoch}, 序号={exp_seq}")
    
    print("\n实际的记录层序号:")
    for name, actual_epoch, actual_seq in records:
        print(f"   {name}: epoch={actual_epoch}, 序号={actual_seq}")
    
    # 检查是否正确
    print(f"\n🔍 序号正确性检查:")
    all_correct = True
    
    for i, ((exp_name, exp_epoch, exp_seq), (act_name, act_epoch, act_seq)) in enumerate(zip(expected_sequences, records)):
        if exp_epoch == act_epoch and exp_seq == act_seq:
            print(f"   ✅ {act_name}: epoch={act_epoch}, 序号={act_seq} (正确)")
        else:
            print(f"   ❌ {act_name}: 期望epoch={exp_epoch},序号={exp_seq}, 实际epoch={act_epoch},序号={act_seq}")
            all_correct = False
    
    return all_correct

def test_bundled_messages_record_sequences():
    """测试合并消息包的记录层序号"""
    print(f"\n🎁 测试合并消息包的记录层序号")
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
    
    # 先创建两个Client Hello来推进记录层序号
    client.create_client_hello()  # 握手消息序号0
    client.record_layer.create_record(DTLSConstants.HANDSHAKE, b'dummy1')  # 记录层序号0
    
    client.cookie = b'test'
    client.create_client_hello()  # 握手消息序号1
    client.record_layer.create_record(DTLSConstants.HANDSHAKE, b'dummy2')  # 记录层序号1
    
    print(f"创建Client Hello后记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 创建合并消息包
    try:
        bundled = client.create_bundled_client_messages()
        if bundled:
            print("✅ 合并消息包创建成功")
            
            # 分析合并消息包中的记录
            print(f"\n📦 分析合并消息包:")
            print(f"   总长度: {len(bundled)}字节")
            
            # 解析每个记录
            offset = 0
            record_count = 0
            
            while offset < len(bundled):
                if offset + 13 > len(bundled):  # 最小记录头部长度
                    break
                
                # 提取记录头部信息
                content_type = bundled[offset]
                version = struct.unpack('!H', bundled[offset+1:offset+3])[0]
                epoch = struct.unpack('!H', bundled[offset+3:offset+5])[0]
                sequence = int.from_bytes(bundled[offset+5:offset+11], 'big')
                length = struct.unpack('!H', bundled[offset+11:offset+13])[0]
                
                record_count += 1
                
                # 确定记录类型
                if content_type == DTLSConstants.HANDSHAKE:
                    record_type = "Handshake"
                elif content_type == DTLSConstants.CHANGE_CIPHER_SPEC:
                    record_type = "Change Cipher Spec"
                else:
                    record_type = f"Unknown({content_type})"
                
                print(f"   记录{record_count}: {record_type}, epoch={epoch}, 序号={sequence}, 长度={length}")
                
                offset += 13 + length
            
            print(f"\n合并消息包包含{record_count}个记录")
            return True
        else:
            print("❌ 合并消息包创建失败")
            return False
    except Exception as e:
        print(f"❌ 合并消息包创建异常: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🔍 DTLS记录层序号测试")
    
    try:
        # 测试单独的记录层序号
        success1 = test_record_layer_sequences()
        
        # 测试合并消息包的记录层序号
        success2 = test_bundled_messages_record_sequences()
        
        if success1 and success2:
            print("\n🎉 记录层序号测试通过！")
            print("✅ 所有记录的epoch和序号都正确")
            sys.exit(0)
        else:
            print("\n❌ 记录层序号测试失败！")
            print("需要修复记录层序号管理")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

