#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端演示脚本
展示如何使用DTLS客户端与服务器通信
"""

import sys
import time
from dtls_client_simple import SimpleDTLSClient

def demo_basic_connection():
    """演示基本连接"""
    print("🔗 演示1: 基本DTLS连接")
    print("-" * 30)
    
    client = SimpleDTLSClient()
    
    try:
        print("正在连接到DTLS服务器...")
        if client.connect("127.0.0.1", 4433):
            print("✅ 连接成功!")
            
            # 发送简单消息
            message = "Hello DTLS Server!"
            print(f"📤 发送: {message}")
            client.send_data(message.encode())
            
            # 等待响应
            print("📥 等待响应...")
            response = client.receive_data()
            if response:
                print(f"✅ 收到: {response.decode()}")
            else:
                print("⚠️ 未收到响应")
                
        else:
            print("❌ 连接失败")
            
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.cleanup()
        print("🧹 连接已清理")

def demo_json_communication():
    """演示JSON数据通信"""
    print("\n📋 演示2: JSON数据通信")
    print("-" * 30)
    
    import json
    
    client = SimpleDTLSClient()
    
    try:
        if client.connect("127.0.0.1", 4433):
            print("✅ 连接成功!")
            
            # 发送JSON数据
            data = {
                "type": "greeting",
                "message": "Hello from Python DTLS client",
                "timestamp": time.time(),
                "client_info": {
                    "version": "1.0",
                    "platform": sys.platform
                }
            }
            
            json_str = json.dumps(data, indent=2)
            print(f"📤 发送JSON数据:")
            print(json_str)
            
            client.send_data(json_str.encode())
            
            # 接收响应
            response = client.receive_data()
            if response:
                try:
                    response_data = json.loads(response.decode())
                    print("✅ 收到JSON响应:")
                    print(json.dumps(response_data, indent=2))
                except json.JSONDecodeError:
                    print(f"📥 收到文本响应: {response.decode()}")
            else:
                print("⚠️ 未收到响应")
                
        else:
            print("❌ 连接失败")
            
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.cleanup()

def demo_multiple_messages():
    """演示多条消息发送"""
    print("\n📨 演示3: 多条消息发送")
    print("-" * 30)
    
    client = SimpleDTLSClient()
    
    try:
        if client.connect("127.0.0.1", 4433):
            print("✅ 连接成功!")
            
            messages = [
                "Message 1: Hello",
                "Message 2: How are you?",
                "Message 3: This is a DTLS test",
                "Message 4: Goodbye!"
            ]
            
            for i, msg in enumerate(messages, 1):
                print(f"📤 发送消息 {i}: {msg}")
                client.send_data(msg.encode())
                
                # 短暂等待
                time.sleep(0.5)
                
                # 尝试接收响应
                response = client.receive_data()
                if response:
                    print(f"📥 响应 {i}: {response.decode()}")
                else:
                    print(f"⚠️ 消息 {i} 无响应")
                    
        else:
            print("❌ 连接失败")
            
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.cleanup()

def show_server_setup_guide():
    """显示服务器设置指南"""
    print("🛠️ DTLS服务器设置指南")
    print("=" * 40)
    print()
    print("要测试DTLS客户端，您需要先启动一个DTLS服务器。")
    print("以下是使用OpenSSL创建测试服务器的步骤：")
    print()
    print("1. 生成自签名证书:")
    print("   openssl req -x509 -newkey rsa:2048 -keyout server.key \\")
    print("           -out server.crt -days 365 -nodes")
    print()
    print("2. 启动DTLS服务器:")
    print("   openssl s_server -dtls1_2 -accept 4433 -cert server.crt -key server.key")
    print()
    print("3. 在另一个终端运行此演示脚本:")
    print("   python3 demo.py")
    print()
    print("注意: 服务器将在端口4433上监听DTLS连接")
    print("=" * 40)

def main():
    """主函数"""
    print("🚀 DTLS客户端演示")
    print("=" * 40)
    
    # 显示服务器设置指南
    show_server_setup_guide()
    
    # 询问是否继续
    try:
        response = input("\n是否已启动DTLS服务器并继续演示? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print("演示已取消。请先启动DTLS服务器。")
            return
    except KeyboardInterrupt:
        print("\n演示已取消")
        return
    
    print("\n开始演示...")
    
    try:
        # 运行演示
        demo_basic_connection()
        
        # 询问是否继续下一个演示
        response = input("\n继续JSON通信演示? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            demo_json_communication()
        
        # 询问是否继续多消息演示
        response = input("\n继续多消息演示? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            demo_multiple_messages()
            
    except KeyboardInterrupt:
        print("\n演示被用户中断")
    except Exception as e:
        print(f"\n演示过程中发生错误: {e}")
    
    print("\n🎉 演示完成!")

if __name__ == "__main__":
    main()

