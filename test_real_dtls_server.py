#!/usr/bin/env python3
"""
测试真实DTLS服务器
"""
import socket
import struct
import subprocess
import time
import sys
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

def test_dtls_server():
    """测试DTLS服务器响应"""
    print("测试DTLS服务器响应...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(10)  # 增加超时时间
        
        # 创建Client Hello
        client_hello = create_client_hello()
        print(f"发送Client Hello到DTLS服务器，长度: {len(client_hello)}")
        
        # 发送到DTLS服务器
        sock.sendto(client_hello, ('localhost', 4433))
        print("✅ 发送Client Hello到DTLS服务器")
        
        # 尝试接收响应
        try:
            response, addr = sock.recvfrom(2048)
            print(f"✅ 收到服务器响应!")
            print(f"响应长度: {len(response)}")
            print(f"响应内容 (hex): {response.hex()}")
            
            # 尝试解析响应
            if len(response) >= 13:
                record_type = response[0]
                version = struct.unpack('!H', response[1:3])[0]
                print(f"响应类型: {record_type} ({'Handshake' if record_type == 22 else 'Unknown'})")
                print(f"响应版本: 0x{version:04X}")
                
                if record_type == 22 and len(response) >= 25:
                    handshake_data = response[13:]
                    if len(handshake_data) >= 1:
                        hs_type = handshake_data[0]
                        print(f"握手消息类型: {hs_type} ({'Server Hello' if hs_type == 2 else 'Unknown'})")
            
            return True
            
        except socket.timeout:
            print("❌ 服务器没有响应（超时）")
            return False
        
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False
    finally:
        sock.close()

def run_server_and_test():
    """运行服务器并测试"""
    print("DTLS服务器响应测试")
    print("=" * 50)
    
    server_process = None
    try:
        # 启动DTLS服务器
        print("🚀 启动DTLS服务器...")
        server_process = subprocess.Popen(
            [sys.executable, "dtls_server_complete.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待服务器启动
        time.sleep(3)
        
        # 检查服务器是否还在运行
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print(f"❌ 服务器启动失败:")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return False
        
        print("✅ 服务器启动成功")
        
        # 测试服务器响应
        success = test_dtls_server()
        
        return success
        
    except Exception as e:
        print(f"❌ 测试过程中出错: {e}")
        return False
    finally:
        # 清理服务器进程
        if server_process and server_process.poll() is None:
            print("\n🛑 停止服务器...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait()
            print("✅ 服务器已停止")

if __name__ == "__main__":
    success = run_server_and_test()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 DTLS服务器响应测试成功!")
    else:
        print("❌ DTLS服务器响应测试失败")
    
    sys.exit(0 if success else 1)

