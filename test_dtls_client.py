#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端测试脚本
测试与DTLS服务器的连接和通信
"""

import sys
import os
import logging

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import DTLSClient

def test_dtls_client():
    """测试DTLS客户端功能"""
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建DTLS客户端
    client = DTLSClient()
    
    try:
        # 测试连接到本地DTLS服务器
        print("🔗 尝试连接到DTLS服务器...")
        
        # 这里可以配置不同的服务器地址和端口
        server_host = "127.0.0.1"
        server_port = 4433
        
        if client.connect(server_host, server_port):
            print("✅ DTLS连接建立成功!")
            
            # 测试发送数据
            test_message = "Hello DTLS Server!"
            print(f"📤 发送测试消息: {test_message}")
            
            if client.send_data(test_message.encode()):
                print("✅ 数据发送成功")
                
                # 尝试接收响应
                print("📥 等待服务器响应...")
                response = client.receive_data()
                if response:
                    print(f"✅ 收到响应: {response.decode()}")
                else:
                    print("⚠️ 未收到服务器响应")
            else:
                print("❌ 数据发送失败")
        else:
            print("❌ DTLS连接失败")
            
    except KeyboardInterrupt:
        print("\n⏹️ 用户中断测试")
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
    finally:
        client.cleanup()
        print("🧹 客户端清理完成")

def test_with_openssl_server():
    """使用OpenSSL s_server测试"""
    print("\n" + "="*50)
    print("📋 OpenSSL DTLS服务器测试指南")
    print("="*50)
    print("1. 首先启动OpenSSL DTLS服务器:")
    print("   openssl s_server -dtls1_2 -accept 4433 -cert server.crt -key server.key")
    print()
    print("2. 如果没有证书，可以生成自签名证书:")
    print("   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes")
    print()
    print("3. 然后运行此测试脚本")
    print("="*50)

if __name__ == "__main__":
    print("🚀 DTLS客户端测试")
    print("="*30)
    
    # 显示测试指南
    test_with_openssl_server()
    
    # 询问是否继续测试
    try:
        response = input("\n是否继续进行DTLS客户端测试? (y/N): ").strip().lower()
        if response in ['y', 'yes']:
            test_dtls_client()
        else:
            print("测试已取消")
    except KeyboardInterrupt:
        print("\n测试已取消")

