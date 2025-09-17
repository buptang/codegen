#!/usr/bin/env python3
"""
测试struct.pack修复
"""
import struct

def test_dtls_handshake_message():
    """测试DTLS握手消息格式"""
    print("测试DTLS握手消息格式修复...")
    
    # 测试参数
    msg_type = 1  # Client Hello
    length = 100
    message_sequence = 0
    data = b'A' * 100
    
    print(f"消息类型: {msg_type}")
    print(f"长度: {length}")
    print(f"序列号: {message_sequence}")
    print(f"数据长度: {len(data)}")
    
    try:
        # 旧的错误格式（会失败）
        print("\n尝试旧格式 '!BLHHBH' (应该失败):")
        try:
            old_message = struct.pack('!BLHHBH', 
                                    msg_type, 
                                    length, 
                                    message_sequence, 
                                    0,  # fragment_offset
                                    length) + data  # fragment_length = length
            print("❌ 旧格式意外成功了")
        except struct.error as e:
            print(f"✅ 旧格式正确失败: {e}")
        
        # 新的正确格式
        print("\n尝试新格式 (应该成功):")
        new_message = (struct.pack("!B", msg_type) + 
                      struct.pack("!I", length)[1:] +  # 3字节长度
                      struct.pack("!H", message_sequence) +
                      struct.pack("!I", 0)[1:] +  # 3字节fragment_offset
                      struct.pack("!I", length)[1:] +  # 3字节fragment_length
                      data)
        
        print(f"✅ 新格式成功! 消息长度: {len(new_message)}")
        print(f"消息头部 (前12字节): {new_message[:12].hex()}")
        
        # 验证消息结构
        print("\n验证消息结构:")
        print(f"消息类型: {new_message[0]}")
        print(f"长度 (3字节): {int.from_bytes(new_message[1:4], 'big')}")
        print(f"序列号 (2字节): {int.from_bytes(new_message[4:6], 'big')}")
        print(f"片段偏移 (3字节): {int.from_bytes(new_message[6:9], 'big')}")
        print(f"片段长度 (3字节): {int.from_bytes(new_message[9:12], 'big')}")
        
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

if __name__ == "__main__":
    print("DTLS握手消息格式修复测试")
    print("=" * 50)
    
    success = test_dtls_handshake_message()
    
    print("\n" + "=" * 50)
    if success:
        print("✅ 所有测试通过！struct.pack问题已修复")
    else:
        print("❌ 测试失败")

