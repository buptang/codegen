#!/usr/bin/env python3
"""
DTLS SNI功能测试
测试DTLS 1.0客户端与服务器的SNI扩展支持
"""

import threading
import time
import logging
from dtls_client_complete import CompleteDTLSClient
from dtls_server_with_hvr import DTLSServer

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_dtls_sni():
    """测试DTLS SNI功能"""
    
    # 服务器配置
    server_host = 'localhost'
    server_port = 4433
    
    # 测试不同的SNI服务器名称
    test_cases = [
        {
            'name': '测试1: 使用默认服务器名称',
            'server_name': None,  # 使用默认（server_host）
            'expected': server_host
        },
        {
            'name': '测试2: 使用自定义服务器名称',
            'server_name': 'example.com',
            'expected': 'example.com'
        },
        {
            'name': '测试3: 使用域名服务器名称',
            'server_name': 'test.example.org',
            'expected': 'test.example.org'
        }
    ]
    
    for test_case in test_cases:
        logger.info(f"\n{'='*50}")
        logger.info(f"开始 {test_case['name']}")
        logger.info(f"{'='*50}")
        
        # 启动服务器
        server = DTLSServer(host=server_host, port=server_port)
        server_thread = threading.Thread(target=server.start_server, daemon=True)
        server_thread.start()
        
        # 等待服务器启动
        time.sleep(1)
        
        try:
            # 创建客户端（带SNI支持）
            if test_case['server_name']:
                client = CompleteDTLSClient(
                    server_host=server_host, 
                    server_port=server_port,
                    server_name=test_case['server_name']
                )
                logger.info(f"客户端配置SNI服务器名称: {test_case['server_name']}")
            else:
                client = CompleteDTLSClient(
                    server_host=server_host, 
                    server_port=server_port
                )
                logger.info(f"客户端使用默认服务器名称: {server_host}")
            
            # 连接到服务器
            logger.info("开始DTLS握手...")
            if client.connect():
                logger.info("✅ DTLS握手成功!")
                
                # 发送测试消息
                test_message = f"Hello from SNI test: {test_case['name']}"
                logger.info(f"发送消息: {test_message}")
                
                if client.send_data(test_message.encode()):
                    logger.info("✅ 消息发送成功!")
                    
                    # 接收响应
                    response = client.receive_data()
                    if response:
                        logger.info(f"✅ 收到响应: {response.decode()}")
                    else:
                        logger.warning("⚠️ 未收到响应")
                else:
                    logger.error("❌ 消息发送失败")
                
                # 关闭连接
                client.close()
                logger.info("连接已关闭")
                
            else:
                logger.error("❌ DTLS握手失败")
                
        except Exception as e:
            logger.error(f"❌ 测试失败: {e}")
        
        finally:
            # 停止服务器
            server.stop_server()
            time.sleep(1)
        
        logger.info(f"{test_case['name']} 完成\n")

def test_dtls_version():
    """测试DTLS版本"""
    logger.info("\n" + "="*50)
    logger.info("DTLS版本测试")
    logger.info("="*50)
    
    from dtls_client_complete import DTLSConstants as ClientConstants
    from dtls_server_with_hvr import DTLSConstants as ServerConstants
    
    logger.info(f"客户端DTLS版本: 0x{ClientConstants.DTLS_1_0:04X}")
    logger.info(f"服务器DTLS版本: 0x{ServerConstants.DTLS_1_0:04X}")
    
    if ClientConstants.DTLS_1_0 == ServerConstants.DTLS_1_0 == 0xFEFF:
        logger.info("✅ DTLS 1.0版本配置正确")
    else:
        logger.error("❌ DTLS版本配置错误")

def main():
    """主函数"""
    logger.info("DTLS SNI功能测试开始")
    
    # 测试DTLS版本
    test_dtls_version()
    
    # 测试SNI功能
    test_dtls_sni()
    
    logger.info("所有测试完成")

if __name__ == "__main__":
    main()

