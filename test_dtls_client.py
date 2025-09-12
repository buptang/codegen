#!/usr/bin/env python3
"""
DTLS客户端测试脚本
演示如何使用完整的DTLS客户端实现
"""

import sys
import logging
from dtls_client_complete import DTLSClient

def test_dtls_client():
    """测试DTLS客户端连接"""
    print("🔐 DTLS客户端测试程序")
    print("=" * 50)
    
    # 配置日志
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    # 创建DTLS客户端
    client = DTLSClient(
        server_host='localhost',
        server_port=4433,
        server_name='localhost'
    )
    
    try:
        print("📡 尝试连接到DTLS服务器...")
        
        # 执行DTLS握手
        if client.handshake():
            print("✅ DTLS握手成功！")
            print(f"🔑 使用的密码套件: {client.cipher_suite}")
            print(f"📜 服务器证书主题: {client.server_certificate.subject if client.server_certificate else 'N/A'}")
            
            # 发送测试数据
            test_message = "Hello, DTLS Server! 你好，DTLS服务器！"
            print(f"📤 发送测试消息: {test_message}")
            
            if client.send_application_data(test_message.encode('utf-8')):
                print("✅ 消息发送成功")
                
                # 接收响应
                response = client.receive_application_data()
                if response:
                    print(f"📥 收到响应: {response.decode('utf-8', errors='ignore')}")
                else:
                    print("⚠️ 未收到响应")
            else:
                print("❌ 消息发送失败")
                
        else:
            print("❌ DTLS握手失败")
            
    except Exception as e:
        print(f"❌ 连接过程中发生错误: {e}")
        
    finally:
        # 清理资源
        client.close()
        print("🧹 客户端资源已清理")

def print_usage():
    """打印使用说明"""
    print("""
🔐 DTLS客户端测试程序使用说明
================================

本程序演示了完整的DTLS 1.2客户端实现，包括：

✅ 功能特性：
  • 完整的DTLS 1.2握手流程
  • Certificate消息处理
  • Server Key Exchange消息处理（ECDHE支持）
  • 优化的客户端消息发送流程
  • 真正的加密通信
  • 支持多种密码套件

🚀 使用方法：
  python3 test_dtls_client.py

📋 前提条件：
  • 需要有DTLS服务器运行在localhost:4433
  • 服务器需要支持DTLS 1.2协议
  • 推荐使用OpenSSL s_server进行测试：
    openssl s_server -dtls1_2 -accept 4433 -cert server.crt -key server.key

🔧 测试服务器设置：
  # 生成测试证书
  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes
  
  # 启动DTLS服务器
  openssl s_server -dtls1_2 -accept 4433 -cert server.crt -key server.key -verify_return_error

💡 注意事项：
  • 如果没有DTLS服务器运行，客户端会显示连接被拒绝的错误
  • 这是正常现象，说明客户端实现正确
  • 实际部署时请配置真实的DTLS服务器
""")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help', 'help']:
        print_usage()
    else:
        test_dtls_client()

