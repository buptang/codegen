#!/usr/bin/env python3
"""
详细调试DTLS服务器
"""
import socket
import struct
import threading
import time
import sys

def create_client_hello():
    """创建Client Hello消息"""
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

def debug_server_with_logging():
    """带详细日志的调试服务器"""
    print("启动详细调试服务器...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 4436))
    
    print("详细调试服务器监听在 localhost:4436")
    
    try:
        while True:
            data, addr = sock.recvfrom(2048)
            print(f"\n=== 收到来自 {addr} 的消息 ===")
            print(f"消息长度: {len(data)}")
            print(f"消息内容 (hex): {data.hex()}")
            
            try:
                # 模拟服务器的解析过程
                print("\n--- 解析DTLS记录 ---")
                if len(data) < 13:
                    print("❌ 记录太短")
                    continue
                
                content_type = data[0]
                version = struct.unpack("!H", data[1:3])[0]
                epoch = struct.unpack("!H", data[3:5])[0]
                sequence = int.from_bytes(data[5:11], "big")  # 6字节序列号
                length = struct.unpack("!H", data[11:13])[0]
                payload = data[13:13+length]
                
                print(f"✅ DTLS记录解析成功:")
                print(f"  内容类型: {content_type} ({'Handshake' if content_type == 22 else 'Unknown'})")
                print(f"  版本: 0x{version:04X} ({'DTLS 1.2' if version == 0xFEFD else 'Unknown'})")
                print(f"  Epoch: {epoch}")
                print(f"  序列号: {sequence}")
                print(f"  长度: {length}")
                print(f"  载荷长度: {len(payload)}")
                
                if content_type == 22:  # Handshake
                    print("\n--- 解析握手消息 ---")
                    if len(payload) < 12:
                        print("❌ 握手消息太短")
                        continue
                    
                    msg_type = payload[0]
                    msg_length = int.from_bytes(payload[1:4], 'big')
                    msg_seq = int.from_bytes(payload[4:6], 'big')
                    frag_offset = int.from_bytes(payload[6:9], 'big')
                    frag_length = int.from_bytes(payload[9:12], 'big')
                    handshake_data = payload[12:12+frag_length]
                    
                    print(f"✅ 握手消息解析成功:")
                    print(f"  消息类型: {msg_type} ({'Client Hello' if msg_type == 1 else 'Unknown'})")
                    print(f"  消息长度: {msg_length}")
                    print(f"  消息序列号: {msg_seq}")
                    print(f"  片段偏移: {frag_offset}")
                    print(f"  片段长度: {frag_length}")
                    print(f"  握手数据长度: {len(handshake_data)}")
                    
                    if msg_type == 1:  # Client Hello
                        print("\n--- 解析Client Hello ---")
                        if len(handshake_data) < 38:
                            print("❌ Client Hello数据太短")
                            continue
                        
                        client_version = struct.unpack('!H', handshake_data[0:2])[0]
                        client_random = handshake_data[2:34]
                        session_id_len = handshake_data[34]
                        
                        print(f"✅ Client Hello解析成功:")
                        print(f"  客户端版本: 0x{client_version:04X}")
                        print(f"  随机数: {client_random.hex()}")
                        print(f"  会话ID长度: {session_id_len}")
                        
                        # 创建简单的Server Hello响应
                        print("\n--- 创建Server Hello响应 ---")
                        server_version = struct.pack('!H', 0xFEFD)
                        server_random = b'B' * 32
                        server_session_id_len = struct.pack('!B', 0)
                        server_cipher_suite = struct.pack('!H', 0x009C)
                        server_compression = struct.pack('!B', 0)
                        
                        server_hello_data = (server_version + server_random + 
                                           server_session_id_len + server_cipher_suite + 
                                           server_compression)
                        
                        # 构造Server Hello握手消息
                        server_hello_length = len(server_hello_data)
                        server_hello_msg = (struct.pack('!B', 2) +  # Server Hello
                                          struct.pack('!I', server_hello_length)[1:] +
                                          struct.pack('!H', 0) +  # message_seq
                                          struct.pack('!I', 0)[1:] +  # fragment_offset
                                          struct.pack('!I', server_hello_length)[1:] +
                                          server_hello_data)
                        
                        # 构造DTLS记录
                        server_record = (struct.pack('!B', 22) +  # Handshake
                                       struct.pack('!H', 0xFEFD) +  # DTLS 1.2
                                       struct.pack('!H', 0) +  # epoch
                                       struct.pack('!Q', 0)[2:] +  # sequence
                                       struct.pack('!H', len(server_hello_msg)) +
                                       server_hello_msg)
                        
                        print(f"发送Server Hello响应，长度: {len(server_record)}")
                        sock.sendto(server_record, addr)
                        print("✅ Server Hello响应已发送")
                        
            except Exception as e:
                print(f"❌ 解析错误: {e}")
                import traceback
                traceback.print_exc()
            
    except KeyboardInterrupt:
        print("\n停止详细调试服务器")
    finally:
        sock.close()

def test_with_debug_server():
    """使用调试服务器测试"""
    print("使用详细调试服务器测试")
    print("=" * 50)
    
    # 在后台启动调试服务器
    server_thread = threading.Thread(target=debug_server_with_logging, daemon=True)
    server_thread.start()
    
    time.sleep(1)  # 等待服务器启动
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)
        
        # 创建并发送Client Hello
        client_hello = create_client_hello()
        print(f"发送Client Hello到调试服务器，长度: {len(client_hello)}")
        
        sock.sendto(client_hello, ('localhost', 4436))
        print("✅ 发送Client Hello到调试服务器")
        
        # 接收响应
        response, addr = sock.recvfrom(2048)
        print(f"✅ 收到服务器响应!")
        print(f"响应长度: {len(response)}")
        print(f"响应内容 (hex): {response.hex()}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

if __name__ == "__main__":
    test_with_debug_server()
    
    print("\n调试完成，按Ctrl+C退出")

