#!/usr/bin/env python3
"""
调试DTLS连接问题
"""
import socket
import time
import threading

def test_server():
    """测试服务器是否在监听"""
    print("测试服务器连接...")
    
    try:
        # 创建UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        # 发送测试消息
        test_msg = b"Hello Server"
        sock.sendto(test_msg, ('localhost', 4433))
        print("✅ 成功发送测试消息到服务器")
        
        # 尝试接收响应
        try:
            response, addr = sock.recvfrom(1024)
            print(f"✅ 收到服务器响应: {response[:50]}...")
        except socket.timeout:
            print("⚠️ 服务器没有响应（可能正常，因为不是DTLS消息）")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ 连接测试失败: {e}")
        return False

def simple_server():
    """简单的UDP服务器用于测试"""
    print("启动简单UDP服务器...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 4434))  # 使用不同端口
    
    print("简单服务器监听在 localhost:4434")
    
    try:
        while True:
            data, addr = sock.recvfrom(1024)
            print(f"收到来自 {addr} 的消息: {data[:50]}...")
            # 发送简单响应
            sock.sendto(b"Simple response", addr)
    except KeyboardInterrupt:
        print("停止简单服务器")
    finally:
        sock.close()

def test_simple_client():
    """测试简单客户端"""
    print("测试简单客户端...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        
        sock.sendto(b"Hello Simple Server", ('localhost', 4434))
        response, addr = sock.recvfrom(1024)
        print(f"✅ 简单客户端收到响应: {response}")
        
        sock.close()
        return True
        
    except Exception as e:
        print(f"❌ 简单客户端测试失败: {e}")
        return False

if __name__ == "__main__":
    print("DTLS连接调试工具")
    print("=" * 50)
    
    # 首先测试现有服务器
    print("1. 测试现有DTLS服务器连接:")
    test_server()
    
    print("\n2. 启动简单UDP服务器进行基础连接测试:")
    
    # 在后台启动简单服务器
    server_thread = threading.Thread(target=simple_server, daemon=True)
    server_thread.start()
    
    time.sleep(1)  # 等待服务器启动
    
    # 测试简单客户端
    print("3. 测试简单客户端:")
    test_simple_client()
    
    print("\n调试完成")

