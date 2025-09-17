#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试修复parse_server_hello中的序号重置问题
验证修复后Client Key Exchange和Change Cipher Spec的记录层序号正确
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

def test_sequence_fix():
    """测试修复后的序号问题"""
    print("=" * 70)
    print("🔧 测试修复parse_server_hello序号重置问题")
    print("=" * 70)
    
    client = CompleteDTLSClient()
    
    print(f"\n📊 初始记录层状态:")
    print(f"   序号: {client.record_layer.sequence_number}")
    print(f"   epoch: {client.record_layer.epoch}")
    
    # 1. 创建第一次Client Hello
    print(f"\n🔸 步骤1: 创建第一次Client Hello")
    client_hello_1 = client.create_client_hello()
    record_1 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_hello_1)
    epoch_1, seq_1 = extract_record_sequence(record_1)
    
    print(f"   记录层序号: {seq_1}, epoch: {epoch_1}")
    print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 2. 创建第二次Client Hello (带Cookie)
    print(f"\n🔸 步骤2: 创建第二次Client Hello (带Cookie)")
    client.cookie = b'test_cookie'
    client_hello_2 = client.create_client_hello()
    record_2 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_hello_2)
    epoch_2, seq_2 = extract_record_sequence(record_2)
    
    print(f"   记录层序号: {seq_2}, epoch: {epoch_2}")
    print(f"   记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 3. 模拟parse_server_hello（这里会设置密码套件）
    print(f"\n🔸 步骤3: 模拟parse_server_hello设置密码套件")
    print(f"   修复前记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 模拟Server Hello数据
    server_hello_data = bytearray()
    server_hello_data.extend(struct.pack('!H', DTLSConstants.DTLS_1_0))  # 版本
    server_hello_data.extend(b'B' * 32)  # 服务器随机数
    server_hello_data.extend(struct.pack('!B', 0))  # 会话ID长度
    server_hello_data.extend(struct.pack('!H', DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256))  # 密码套件
    server_hello_data.extend(struct.pack('!B', 0))  # 压缩方法
    
    # 调用parse_server_hello
    success = client.parse_server_hello(bytes(server_hello_data))
    
    print(f"   parse_server_hello结果: {success}")
    print(f"   修复后记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    print(f"   密码套件: {hex(client.cipher_suite)}")
    
    # 4. 设置必要的密钥材料
    print(f"\n🔸 步骤4: 设置密钥材料")
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
    
    # 5. 创建Client Key Exchange
    print(f"\n🔸 步骤5: 创建Client Key Exchange")
    print(f"   创建前记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    client_key_exchange = client.create_client_key_exchange()
    if client_key_exchange:
        record_3 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, client_key_exchange)
        epoch_3, seq_3 = extract_record_sequence(record_3)
        
        print(f"   ✅ Client Key Exchange创建成功")
        print(f"   记录层序号: {seq_3}, epoch: {epoch_3}")
        print(f"   创建后记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    else:
        print(f"   ❌ Client Key Exchange创建失败")
        return False
    
    # 6. 创建Change Cipher Spec
    print(f"\n🔸 步骤6: 创建Change Cipher Spec")
    print(f"   创建前记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    change_cipher_spec = struct.pack('!B', 1)
    record_4 = client.record_layer.create_record(DTLSConstants.CHANGE_CIPHER_SPEC, change_cipher_spec)
    epoch_4, seq_4 = extract_record_sequence(record_4)
    
    print(f"   记录层序号: {seq_4}, epoch: {epoch_4}")
    print(f"   创建后记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 7. 启用加密
    print(f"\n🔸 步骤7: 启用加密")
    client.derive_master_secret()
    client.derive_key_material()
    
    print(f"   启用前: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    mac_key = getattr(client, 'client_write_mac_key', None)
    client.record_layer.enable_encryption(client.client_write_key, client.record_layer.client_write_iv, mac_key)
    
    print(f"   启用后: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    
    # 8. 创建Finished记录（加密）
    print(f"\n🔸 步骤8: 创建Finished记录（加密）")
    finished_msg = client.create_finished()
    if finished_msg:
        record_5 = client.record_layer.create_record(DTLSConstants.HANDSHAKE, finished_msg)
        epoch_5, seq_5 = extract_record_sequence(record_5)
        
        print(f"   记录层序号: {seq_5}, epoch: {epoch_5}")
        print(f"   创建后记录层状态: 序号={client.record_layer.sequence_number}, epoch={client.record_layer.epoch}")
    else:
        print(f"   ❌ Finished消息创建失败")
        return False
    
    # 分析结果
    print(f"\n📋 修复后的记录层序号分析")
    print("=" * 70)
    
    expected_sequences = [
        ("Client Hello #1", 0, 0),
        ("Client Hello #2", 0, 1), 
        ("Client Key Exchange", 0, 2),  # 这里应该是2，不是0
        ("Change Cipher Spec", 0, 3),  # 这里应该是3，不是1
        ("Finished", 1, 0)  # 新epoch，序号重置
    ]
    
    actual_sequences = [
        ("Client Hello #1", epoch_1, seq_1),
        ("Client Hello #2", epoch_2, seq_2),
        ("Client Key Exchange", epoch_3, seq_3),
        ("Change Cipher Spec", epoch_4, seq_4),
        ("Finished", epoch_5, seq_5)
    ]
    
    print("期望的记录层序号:")
    for name, exp_epoch, exp_seq in expected_sequences:
        print(f"   {name}: epoch={exp_epoch}, 序号={exp_seq}")
    
    print("\n实际的记录层序号:")
    for name, actual_epoch, actual_seq in actual_sequences:
        print(f"   {name}: epoch={actual_epoch}, 序号={actual_seq}")
    
    # 检查是否正确
    print(f"\n🔍 修复效果检查:")
    all_correct = True
    
    for i, ((exp_name, exp_epoch, exp_seq), (act_name, act_epoch, act_seq)) in enumerate(zip(expected_sequences, actual_sequences)):
        if exp_epoch == act_epoch and exp_seq == act_seq:
            print(f"   ✅ {act_name}: epoch={act_epoch}, 序号={act_seq} (正确)")
        else:
            print(f"   ❌ {act_name}: 期望epoch={exp_epoch},序号={exp_seq}, 实际epoch={act_epoch},序号={act_seq}")
            all_correct = False
    
    if all_correct:
        print(f"\n🎉 修复成功！所有记录层序号都正确！")
        print(f"✅ Client Key Exchange: epoch=0, 序号=2 (修复前是0)")
        print(f"✅ Change Cipher Spec: epoch=0, 序号=3 (修复前是1)")
        print(f"✅ Finished: epoch=1, 序号=0 (正确)")
    else:
        print(f"\n❌ 修复失败，仍有序号问题")
    
    return all_correct

if __name__ == "__main__":
    print("🔧 DTLS序号修复测试")
    
    try:
        success = test_sequence_fix()
        
        if success:
            print("\n🎉 序号修复测试通过！")
            print("✅ parse_server_hello不再重置记录层序号")
            print("✅ Client Key Exchange和Change Cipher Spec序号正确")
            print("✅ 修复了用户报告的序号问题")
            sys.exit(0)
        else:
            print("\n❌ 序号修复测试失败！")
            sys.exit(1)
            
    except Exception as e:
        print(f"\n💥 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

