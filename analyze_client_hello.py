#!/usr/bin/env python3
"""
分析和修复Client Hello消息构造
确保生成的包符合Wireshark和DTLS标准
"""
import struct
import secrets
from dtls_client_complete import DTLSConstants

def analyze_standard_client_hello():
    """分析标准的Client Hello消息格式"""
    print("🔍 分析标准DTLS Client Hello消息格式")
    print("=" * 60)
    
    # 标准的Client Hello应该包含：
    print("📋 Client Hello消息结构:")
    print("1. Protocol Version (2 bytes): DTLS 1.2 = 0xFEFD")
    print("2. Random (32 bytes): 客户端随机数")
    print("3. Session ID Length (1 byte): 通常为0")
    print("4. Session ID (variable): 如果长度为0则无此字段")
    print("5. Cookie Length (1 byte): DTLS特有，可以为0")
    print("6. Cookie (variable): 如果长度为0则无此字段")
    print("7. Cipher Suites Length (2 bytes)")
    print("8. Cipher Suites (variable)")
    print("9. Compression Methods Length (1 byte)")
    print("10. Compression Methods (variable)")
    print("11. Extensions Length (2 bytes): 可选")
    print("12. Extensions (variable): 可选")
    print()

def create_correct_client_hello():
    """创建正确的Client Hello消息"""
    print("🔧 创建符合标准的Client Hello消息")
    print("-" * 40)
    
    # 1. Protocol Version - DTLS 1.2
    version = struct.pack('!H', 0xFEFD)  # DTLS 1.2
    print(f"Protocol Version: {version.hex()}")
    
    # 2. Random (32 bytes)
    client_random = secrets.token_bytes(32)
    print(f"Random: {client_random.hex()}")
    
    # 3. Session ID Length + Session ID
    session_id_length = struct.pack('!B', 0)  # 无会话ID
    session_id = b''
    print(f"Session ID Length: {session_id_length.hex()}")
    
    # 4. Cookie Length + Cookie (DTLS特有)
    cookie_length = struct.pack('!B', 0)  # 无Cookie
    cookie = b''
    print(f"Cookie Length: {cookie_length.hex()}")
    
    # 5. Cipher Suites
    cipher_suites_length = struct.pack('!H', 2)  # 1个密码套件 = 2字节
    cipher_suite = struct.pack('!H', 0x009C)  # TLS_RSA_WITH_AES_128_GCM_SHA256
    cipher_suites = cipher_suites_length + cipher_suite
    print(f"Cipher Suites: {cipher_suites.hex()}")
    
    # 6. Compression Methods
    compression_length = struct.pack('!B', 1)  # 1个压缩方法
    compression_method = struct.pack('!B', 0)  # NULL压缩
    compression_methods = compression_length + compression_method
    print(f"Compression Methods: {compression_methods.hex()}")
    
    # 7. Extensions (可选，这里先不加)
    extensions_length = struct.pack('!H', 0)
    extensions = b''
    print(f"Extensions Length: {extensions_length.hex()}")
    
    # 组装Client Hello数据
    client_hello_data = (version + client_random + session_id_length + session_id +
                        cookie_length + cookie + cipher_suites + compression_methods +
                        extensions_length + extensions)
    
    print(f"\nClient Hello Data Length: {len(client_hello_data)} bytes")
    print(f"Client Hello Data: {client_hello_data.hex()}")
    
    return client_hello_data

def create_dtls_handshake_message(msg_type: int, data: bytes, message_seq: int = 0):
    """创建DTLS握手消息"""
    print(f"\n🔧 创建DTLS握手消息 (类型: {msg_type})")
    print("-" * 40)
    
    length = len(data)
    
    # DTLS握手消息格式:
    # - Message Type (1 byte)
    # - Length (3 bytes)
    # - Message Sequence (2 bytes)
    # - Fragment Offset (3 bytes)
    # - Fragment Length (3 bytes)
    # - Data (variable)
    
    msg_type_bytes = struct.pack('!B', msg_type)
    length_bytes = struct.pack('!I', length)[1:]  # 取后3字节
    message_seq_bytes = struct.pack('!H', message_seq)
    fragment_offset_bytes = struct.pack('!I', 0)[1:]  # 取后3字节，偏移为0
    fragment_length_bytes = struct.pack('!I', length)[1:]  # 取后3字节
    
    handshake_message = (msg_type_bytes + length_bytes + message_seq_bytes +
                        fragment_offset_bytes + fragment_length_bytes + data)
    
    print(f"Message Type: {msg_type_bytes.hex()}")
    print(f"Length: {length_bytes.hex()}")
    print(f"Message Sequence: {message_seq_bytes.hex()}")
    print(f"Fragment Offset: {fragment_offset_bytes.hex()}")
    print(f"Fragment Length: {fragment_length_bytes.hex()}")
    print(f"Handshake Message Length: {len(handshake_message)} bytes")
    print(f"Handshake Message: {handshake_message.hex()}")
    
    return handshake_message

def create_dtls_record(content_type: int, handshake_data: bytes, epoch: int = 0, sequence: int = 0):
    """创建DTLS记录"""
    print(f"\n🔧 创建DTLS记录 (内容类型: {content_type})")
    print("-" * 40)
    
    # DTLS记录格式:
    # - Content Type (1 byte)
    # - Version (2 bytes)
    # - Epoch (2 bytes)
    # - Sequence Number (6 bytes)
    # - Length (2 bytes)
    # - Data (variable)
    
    content_type_bytes = struct.pack('!B', content_type)
    version_bytes = struct.pack('!H', 0xFEFD)  # DTLS 1.2
    epoch_bytes = struct.pack('!H', epoch)
    sequence_bytes = struct.pack('!Q', sequence)[2:]  # 取后6字节
    length_bytes = struct.pack('!H', len(handshake_data))
    
    record = (content_type_bytes + version_bytes + epoch_bytes +
             sequence_bytes + length_bytes + handshake_data)
    
    print(f"Content Type: {content_type_bytes.hex()}")
    print(f"Version: {version_bytes.hex()}")
    print(f"Epoch: {epoch_bytes.hex()}")
    print(f"Sequence Number: {sequence_bytes.hex()}")
    print(f"Length: {length_bytes.hex()}")
    print(f"Record Length: {len(record)} bytes")
    print(f"Record: {record.hex()}")
    
    return record

def main():
    """主函数"""
    print("🔍 DTLS Client Hello消息分析和修复工具")
    print("=" * 60)
    
    # 1. 分析标准格式
    analyze_standard_client_hello()
    
    # 2. 创建正确的Client Hello
    client_hello_data = create_correct_client_hello()
    
    # 3. 创建握手消息
    handshake_message = create_dtls_handshake_message(1, client_hello_data, 0)  # CLIENT_HELLO = 1
    
    # 4. 创建DTLS记录
    dtls_record = create_dtls_record(22, handshake_message, 0, 0)  # HANDSHAKE = 22
    
    print("\n" + "=" * 60)
    print("✅ 完整的DTLS Client Hello记录已生成")
    print(f"📊 总长度: {len(dtls_record)} bytes")
    print(f"📦 完整记录: {dtls_record.hex()}")
    
    # 保存到文件用于Wireshark分析
    with open('client_hello.bin', 'wb') as f:
        f.write(dtls_record)
    print("💾 已保存到 client_hello.bin 文件")
    
    print("\n🔍 Wireshark分析提示:")
    print("1. 使用 'udp.port == 4433' 过滤器")
    print("2. 右键选择 'Decode As' -> DTLS")
    print("3. 检查协议解析是否正确")

if __name__ == "__main__":
    main()
