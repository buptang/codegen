#!/usr/bin/env python3
"""
DTLS 1.0 + SNI 演示脚本
展示如何使用支持SNI扩展的DTLS客户端
"""

import logging
import threading
import time
from dtls_client_complete import CompleteDTLSClient
from dtls_server_with_hvr import DTLSServer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """主演示函数"""
    logger.info("🚀 DTLS 1.0 + SNI 演示开始")
    
    # 服务器配置
    server_host = 'localhost'
    server_port = 4433
    sni_server_name = 'demo.example.com'  # SNI服务器名称
    
    # 启动DTLS服务器
    logger.info("📡 启动DTLS服务器...")
    server = DTLSServer(host=server_host, port=server_port)
    server_thread = threading.Thread(target=server.start_server, daemon=True)
    server_thread.start()
    
    # 等待服务器启动
    time.sleep(2)
    
    try:
        # 创建支持SNI的DTLS客户端
        logger.info(f"🔐 创建DTLS客户端 (SNI: {sni_server_name})")
        client = CompleteDTLSClient(
            server_host=server_host,
            server_port=server_port,
            server_name=sni_server_name  # 设置SNI服务器名称
        )
        
        # 建立DTLS连接
        logger.info("🤝 开始DTLS握手...")
        if client.connect():
            logger.info("✅ DTLS握手成功! 连接已建立")
            
            # 发送加密消息
            messages = [
                "Hello, DTLS 1.0 Server!",
                "This is a secure message with SNI support",
                f"SNI Server Name: {sni_server_name}",
                "DTLS encryption is working!"
            ]
            
            for i, message in enumerate(messages, 1):
                logger.info(f"📤 发送消息 {i}: {message}")
                
                if client.send_data(message.encode()):
                    logger.info("✅ 消息发送成功")
                    
                    # 接收响应
                    response = client.receive_data()
                    if response:
                        logger.info(f"📥 收到响应: {response.decode()}")
                    else:
                        logger.warning("⚠️ 未收到响应")
                else:
                    logger.error("❌ 消息发送失败")
                
                time.sleep(1)  # 间隔1秒
            
            # 关闭连接
            logger.info("🔒 关闭DTLS连接")
            client.close()
            
        else:
            logger.error("❌ DTLS握手失败")
            
    except Exception as e:
        logger.error(f"❌ 演示过程中发生错误: {e}")
        
    finally:
        # 停止服务器
        logger.info("🛑 停止DTLS服务器")
        server.stop_server()
    
    logger.info("🎉 DTLS 1.0 + SNI 演示完成")

def show_features():
    """显示实现的功能特性"""
    print("\n" + "="*60)
    print("🔐 DTLS 1.0 + SNI 实现特性")
    print("="*60)
    print("✅ DTLS 1.0 协议支持")
    print("✅ SNI (Server Name Indication) 扩展")
    print("✅ Hello Verify Request 防护")
    print("✅ RSA 密钥交换")
    print("✅ AES-128-GCM 加密")
    print("✅ 完整的握手流程")
    print("✅ 加密数据传输")
    print("✅ 客户端/服务器双向支持")
    print("="*60)
    
    print("\n📋 SNI 配置说明:")
    print("- 客户端可以指定 server_name 参数")
    print("- 如果不指定，默认使用 server_host")
    print("- 服务器会解析并记录 SNI 信息")
    print("- 支持标准的 hostname 类型 SNI")
    
    print("\n🔧 使用示例:")
    print("```python")
    print("# 创建带SNI的DTLS客户端")
    print("client = CompleteDTLSClient(")
    print("    server_host='192.168.1.100',")
    print("    server_port=4433,")
    print("    server_name='secure.example.com'  # SNI")
    print(")")
    print("```")
    print()

if __name__ == "__main__":
    show_features()
    main()

