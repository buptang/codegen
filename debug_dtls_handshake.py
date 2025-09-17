#!/usr/bin/env python3
"""
调试DTLS握手消息
"""
import socket
import struct
import time
import threading

def create_client_hello():
    """创建一个简单的Client Hello消息"""
    # DTLS记录头: type(1) + version(2) + epoch(2) + sequence(6) + length(2)
    record_type = 22  # Handshake
    version = 0xFEFD  # DTLS 1.2
    epoch = 0
    sequence = 0
    
    # 握手消息: type(1) + length(3) + message_seq(2) + fragment_offset(3) + fragment_length(3) + data
    handshake_type = 1  # Client Hello
    
    # Client Hello数据
    client_version = struct.pack('!H', 0xFEFD)  # DTLS 1.2
    random = b'A' * 32  # 32字节随机数
    session_id_length = struct.pack('!B', 0)
    cipher_suites_length = struct.pack('!H', 2)
    cipher_suite = struct.pack('!H', 0x009C)  # TLS_RSA_WITH_AES_128_GCM_SHA256
    compression_methods_length = struct.pack('!B', 1)
    compression_method = struct.pack('!B', 0)
    extensions_length = struct.pack('!H', 0)
    
    handshake_data = (client_version + random + session_id_length +
                     cipher_suites_length + cipher_suite +
                     compression_methods_length + compression_method +
                     extensions_length)
    
    handshake_length = len(handshake_data)
    
    # 构造握手消息
    handshake_msg = (struct.pack('!B', handshake_type) +
                    struct.pack('!I', handshake_length)[1:] +  # 3字节长度
                    struct.pack('!H', 0) +  # message_seq
                    struct.pack('!I', 0)[1:] +  # fragment_offset (3字节)
                    struct.pack('!I', handshake_length)[1:] +  # fragment_length (3字节)
                    handshake_data)
    
    # 构造DTLS记录
    record_length = len(handshake_msg)
    record = (struct.pack('!B', record_type) +
             struct.pack('!H', version) +
             struct.pack('!H', epoch) +
             struct.pack('!Q', sequence)[2:] +  # 6字节序列号
             struct.pack('!H', record_length) +
             handshake_msg)
    
    return record

def debug_server():
    """调试服务器 - 显示收到的消息"""
    print("启动调试服务器...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 4435))
    
    print("调试服务器监听在 localhost:4435")
    
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            print(f"\n收到来自 {addr} 的消息:")
            print(f"消息长度: {len(data)}")
            print(f"消息内容 (hex): {data.hex()}")
            
            if len(data) >= 13:  # DTLS记录头长度
                # 解析DTLS记录头
                record_type = data[0]
                version = struct.unpack('!H', data[1:3])[0]
                epoch = struct.unpack('!H', data[3:5])[0]
                sequence = int.from_bytes(data[5:11], 'big')
                length = struct.unpack('!H', data[11:13])[0]
                
                print(f"DTLS记录:")
                print(f"  类型: {record_type} ({'Handshake' if record_type == 22 else 'Unknown'})")
                print(f"  版本: 0x{version:04X} ({'DTLS 1.2' if version == 0xFEFD else 'Unknown'})")
                print(f"  Epoch: {epoch}")
                print(f"  序列号: {sequence}")
                print(f"  长度: {length}")
                
                if record_type == 22 and len(data) >= 25:  # 握手消息
                    handshake_data = data[13:]
                    if len(handshake_data) >= 12:
                        hs_type = handshake_data[0]
                        hs_length = int.from_bytes(handshake_data[1:4], 'big')
                        hs_msg_seq = struct.unpack('!H', handshake_data[4:6])[0]
                        hs_frag_offset = int.from_bytes(handshake_data[6:9], 'big')
                        hs_frag_length = int.from_bytes(handshake_data[9:12], 'big')
                        
                        print(f"握手消息:")
                        print(f"  类型: {hs_type} ({'Client Hello' if hs_type == 1 else 'Unknown'})")
                        print(f"  长度: {hs_length}")
                        print(f"  消息序列号: {hs_msg_seq}")
                        print(f"  片段偏移: {hs_frag_offset}")
                        print(f"  片段长度: {hs_frag_length}")
            
            # 发送简单响应
            response = b"Debug response"
            sock.sendto(response, addr)
            print(f"发送响应: {response}")
            
    except KeyboardInterrupt:
        print("\n停止调试服务器")
    finally:
        sock.close()

def test_client_hello():
    """测试Client Hello消息"""
    print("测试Client Hello消息...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # 创建Client Hello
        client_hello = create_client_hello()
        print(f"创建Client Hello消息，长度: {len(client_hello)}")
        print(f"消息内容 (hex): {client_hello.hex()}")
        
        # 发送到调试服务器
        sock.sendto(client_hello, ('localhost', 4435))
        print("✅ 发送Client Hello到调试服务器")
        
        # 接收响应
        response, addr = sock.recvfrom(1024)
        print(f"✅ 收到响应: {response}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

if __name__ == "__main__":
    print("DTLS握手消息调试工具")
    print("=" * 50)
    
    # 在后台启动调试服务器
    server_thread = threading.Thread(target=debug_server, daemon=True)
    server_thread.start()
    
    time.sleep(1)  # 等待服务器启动
    
    # 测试Client Hello
    test_client_hello()
    
    print("\n调试完成，按Ctrl+C退出")

