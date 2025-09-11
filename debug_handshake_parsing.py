#!/usr/bin/env python3
"""
调试握手消息解析
"""
import struct
from dtls_client_complete import CompleteDTLSClient, DTLSConstants, DTLSRecord, DTLSHandshake

def create_test_client_hello():
    """创建测试用的Client Hello消息"""
    # 创建DTLS组件
    record_layer = DTLSRecord()
    handshake_layer = DTLSHandshake()
    
    # 创建Client Hello数据
    client_version = struct.pack('!H', DTLSConstants.DTLS_1_2)
    random = b'A' * 32
    session_id_length = struct.pack('!B', 0)
    cipher_suites_length = struct.pack('!H', 2)
    cipher_suite = struct.pack('!H', DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256)
    compression_methods_length = struct.pack('!B', 1)
    compression_method = struct.pack('!B', DTLSConstants.COMPRESSION_NULL)
    extensions_length = struct.pack('!H', 0)
    
    client_hello_data = (client_version + random + session_id_length +
                        cipher_suites_length + cipher_suite +
                        compression_methods_length + compression_method +
                        extensions_length)
    
    print(f"Client Hello数据长度: {len(client_hello_data)}")
    print(f"Client Hello数据 (hex): {client_hello_data.hex()}")
    
    # 创建握手消息
    handshake_msg = handshake_layer.create_handshake_message(DTLSConstants.CLIENT_HELLO, client_hello_data)
    print(f"握手消息长度: {len(handshake_msg)}")
    print(f"握手消息 (hex): {handshake_msg.hex()}")
    
    # 创建DTLS记录
    dtls_record = record_layer.create_record(DTLSConstants.HANDSHAKE, handshake_msg)
    print(f"DTLS记录长度: {len(dtls_record)}")
    print(f"DTLS记录 (hex): {dtls_record.hex()}")
    
    return dtls_record

def test_parsing():
    """测试解析过程"""
    print("测试握手消息解析")
    print("=" * 50)
    
    # 创建测试消息
    dtls_record = create_test_client_hello()
    
    print("\n--- 解析DTLS记录 ---")
    record_layer = DTLSRecord()
    try:
        content_type, payload = record_layer.parse_record(dtls_record)
        print(f"✅ DTLS记录解析成功:")
        print(f"  内容类型: {content_type}")
        print(f"  载荷长度: {len(payload)}")
        print(f"  载荷 (hex): {payload.hex()}")
        
        print("\n--- 解析握手消息 ---")
        handshake_layer = DTLSHandshake()
        try:
            msg_type, handshake_data = handshake_layer.parse_handshake_message(payload)
            print(f"✅ 握手消息解析成功:")
            print(f"  消息类型: {msg_type}")
            print(f"  握手数据长度: {len(handshake_data)}")
            print(f"  握手数据 (hex): {handshake_data.hex()}")
            
            return True
            
        except Exception as e:
            print(f"❌ 握手消息解析失败: {e}")
            print(f"载荷长度: {len(payload)}")
            if len(payload) >= 12:
                print("载荷前12字节:")
                for i in range(min(12, len(payload))):
                    print(f"  [{i}]: 0x{payload[i]:02X}")
            return False
            
    except Exception as e:
        print(f"❌ DTLS记录解析失败: {e}")
        return False

if __name__ == "__main__":
    test_parsing()

