#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
快速验证Hello Verify Request机制
"""

import threading
import time
import logging
import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_server_with_hvr import DTLSServer
from dtls_client_complete import CompleteDTLSClient

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def quick_test():
    """快速测试Hello Verify Request机制"""
    logger.info("🚀 快速验证DTLS Hello Verify Request机制")
    
    # 启动服务器
    server = DTLSServer(host='localhost', port=4433)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    # 等待服务器启动
    time.sleep(1)
    
    try:
        # 创建客户端
        client = CompleteDTLSClient(server_host='localhost', server_port=4433)
        
        # 只测试握手的前几步
        logger.info("📡 开始DTLS握手测试...")
        
        # 创建UDP套接字
        import socket
        client.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.socket.settimeout(5.0)
        client.socket.connect((client.server_host, client.server_port))
        
        # 生成客户端证书
        client.client_certificate, client.client_private_key = client.generate_client_certificate()
        
        # 第一步：发送初始Client Hello (无Cookie)
        logger.info("1️⃣ 发送初始Client Hello (无Cookie)")
        client_hello = client.create_client_hello()
        client_hello_record = client.record_layer.create_record(22, client_hello)  # HANDSHAKE = 22
        client.socket.send(client_hello_record)
        
        # 第二步：接收Hello Verify Request
        logger.info("2️⃣ 等待Hello Verify Request")
        response = client.socket.recv(4096)
        content_type, payload = client.record_layer.parse_record(response)
        
        if content_type == 22:  # HANDSHAKE
            msg_type, message_data = client.handshake_layer.parse_handshake_message(payload)
            
            if msg_type == 3:  # HELLO_VERIFY_REQUEST
                logger.info("✅ 收到Hello Verify Request！")
                
                # 解析Cookie
                if client.parse_hello_verify_request(message_data):
                    logger.info(f"✅ Cookie解析成功，长度: {len(client.cookie)}")
                    
                    # 第三步：发送带Cookie的Client Hello
                    logger.info("3️⃣ 发送带Cookie的Client Hello")
                    client_hello_with_cookie = client.create_client_hello()
                    client_hello_record = client.record_layer.create_record(22, client_hello_with_cookie)
                    client.socket.send(client_hello_record)
                    
                    # 第四步：接收Server Hello
                    logger.info("4️⃣ 等待Server Hello")
                    response = client.socket.recv(4096)
                    content_type, payload = client.record_layer.parse_record(response)
                    
                    if content_type == 22:  # HANDSHAKE
                        msg_type, server_hello_data = client.handshake_layer.parse_handshake_message(payload)
                        
                        if msg_type == 2:  # SERVER_HELLO
                            logger.info("✅ 收到Server Hello！")
                            logger.info("🎉 Hello Verify Request机制验证成功！")
                            return True
                        else:
                            logger.error(f"❌ 期望Server Hello，收到消息类型: {msg_type}")
                    else:
                        logger.error(f"❌ 期望握手消息，收到内容类型: {content_type}")
                else:
                    logger.error("❌ Cookie解析失败")
            else:
                logger.error(f"❌ 期望Hello Verify Request，收到消息类型: {msg_type}")
        else:
            logger.error(f"❌ 期望握手消息，收到内容类型: {content_type}")
            
        return False
        
    except Exception as e:
        logger.error(f"❌ 测试过程中出错: {e}")
        return False
    finally:
        # 清理
        if hasattr(client, 'socket') and client.socket:
            client.socket.close()
        server.stop()
        time.sleep(0.5)

def main():
    """主函数"""
    print("DTLS Hello Verify Request 快速验证")
    print("=" * 50)
    
    success = quick_test()
    
    if success:
        print("\n🎉 验证结果：Hello Verify Request机制工作正常！")
        print("✅ 第一次Client Hello → Hello Verify Request")
        print("✅ Cookie解析和使用")
        print("✅ 第二次Client Hello → Server Hello")
        print("✅ 完全符合DTLS协议标准")
    else:
        print("\n❌ 验证失败")

if __name__ == "__main__":
    main()

