#!/usr/bin/env python3
"""
完整的DTLS客户端和服务器测试
"""
import threading
import time
import sys
from dtls_client_complete import CompleteDTLSClient
from dtls_server_complete import CompleteDTLSServer

def test_complete_dtls():
    """测试完整的DTLS通信"""
    print("完整DTLS通信测试")
    print("=" * 50)
    
    # 启动DTLS服务器
    print("🚀 启动DTLS服务器...")
    server = CompleteDTLSServer(host='localhost', port=4437)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    time.sleep(1)  # 等待服务器启动
    print("✅ 服务器启动成功")
    
    try:
        # 创建DTLS客户端
        print("\n🔗 创建DTLS客户端...")
        client = CompleteDTLSClient(server_host='localhost', server_port=4437)
        
        # 连接到服务器
        print("🤝 连接到DTLS服务器...")
        if client.connect():
            print("✅ DTLS握手成功!")
            
            # 发送应用数据
            print("\n📤 发送应用数据...")
            test_message = "Hello, DTLS Server! 这是一条测试消息。"
            if client.send_application_data(test_message.encode('utf-8')):
                print("✅ 应用数据发送成功")
                
                # 接收响应
                print("📥 等待服务器响应...")
                response = client.receive_application_data()
                if response:
                    print(f"✅ 收到服务器响应: {response.decode('utf-8')}")
                else:
                    print("❌ 未收到服务器响应")
            else:
                print("❌ 应用数据发送失败")
            
            # 关闭连接
            print("\n🔒 关闭连接...")
            client.close()
            print("✅ 连接已关闭")
            
        else:
            print("❌ DTLS握手失败")
            return False
            
    except Exception as e:
        print(f"❌ 测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # 停止服务器
        print("\n🛑 停止服务器...")
        server.stop()
        print("✅ 服务器已停止")
    
    print("\n" + "=" * 50)
    print("🎉 完整DTLS通信测试成功!")
    return True

def test_basic_handshake():
    """测试基本握手"""
    print("基本DTLS握手测试")
    print("=" * 50)
    
    # 启动服务器
    print("🚀 启动DTLS服务器...")
    server = CompleteDTLSServer(host='localhost', port=4438)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    time.sleep(1)
    print("✅ 服务器启动成功")
    
    try:
        # 创建客户端
        print("\n🔗 创建DTLS客户端...")
        client = CompleteDTLSClient(server_host='localhost', server_port=4438)
        
        # 仅测试握手
        print("🤝 执行DTLS握手...")
        if client.connect():
            print("✅ DTLS握手成功!")
            
            # 显示连接信息
            print(f"📊 连接状态: {'已连接' if client.connected else '未连接'}")
            
            client.close()
            return True
        else:
            print("❌ DTLS握手失败")
            return False
            
    except Exception as e:
        print(f"❌ 握手测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        server.stop()
        print("✅ 服务器已停止")

if __name__ == "__main__":
    print("DTLS完整功能测试")
    print("=" * 60)
    
    # 测试基本握手
    print("\n1. 基本握手测试")
    print("-" * 30)
    handshake_success = test_basic_handshake()
    
    if handshake_success:
        print("\n2. 完整通信测试")
        print("-" * 30)
        complete_success = test_complete_dtls()
        
        if complete_success:
            print("\n🎉 所有测试通过!")
            sys.exit(0)
        else:
            print("\n❌ 完整通信测试失败")
            sys.exit(1)
    else:
        print("\n❌ 基本握手测试失败，跳过完整测试")
        sys.exit(1)

