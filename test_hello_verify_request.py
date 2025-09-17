#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试DTLS Hello Verify Request机制
验证正确的DTLS握手流程：
1. Client Hello (无Cookie) → Hello Verify Request (带Cookie)
2. Client Hello (带Cookie) → Server Hello + Certificate + ...

作者: Codegen
"""

import threading
import time
import logging
import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_server_with_hvr import DTLSServer
from dtls_client_complete import CompleteDTLSClient as DTLSClient

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_hello_verify_request():
    """测试Hello Verify Request机制"""
    logger.info("=" * 60)
    logger.info("测试DTLS Hello Verify Request机制")
    logger.info("=" * 60)
    
    # 启动服务器
    server = DTLSServer(host='localhost', port=4433)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    # 等待服务器启动
    time.sleep(2)
    
    try:
        # 创建客户端并连接
        logger.info("\n" + "=" * 40)
        logger.info("开始DTLS客户端连接测试")
        logger.info("=" * 40)
        
        client = DTLSClient(server_host='localhost', server_port=4433)
        
        # 执行连接
        success = client.connect(timeout=15.0)
        
        if success:
            logger.info("\n✅ DTLS握手成功！Hello Verify Request机制工作正常")
            
            # 测试发送消息
            logger.info("\n测试加密通信...")
            test_message = "Hello DTLS Server with Hello Verify Request!"
            if client.send_message(test_message):
                logger.info(f"✅ 成功发送消息: {test_message}")
            else:
                logger.error("❌ 发送消息失败")
                
        else:
            logger.error("\n❌ DTLS握手失败")
            
        # 清理客户端
        client.cleanup()
        
    except Exception as e:
        logger.error(f"测试过程中出错: {e}")
    finally:
        # 停止服务器
        server.stop()
        time.sleep(1)
    
    logger.info("\n" + "=" * 60)
    logger.info("Hello Verify Request测试完成")
    logger.info("=" * 60)

def analyze_handshake_flow():
    """分析握手流程"""
    logger.info("\n" + "=" * 50)
    logger.info("DTLS握手流程分析")
    logger.info("=" * 50)
    
    logger.info("正确的DTLS握手流程应该是：")
    logger.info("1. Client → Server: Client Hello (无Cookie)")
    logger.info("2. Server → Client: Hello Verify Request (带Cookie)")
    logger.info("3. Client → Server: Client Hello (带Cookie)")
    logger.info("4. Server → Client: Server Hello")
    logger.info("5. Server → Client: Certificate")
    logger.info("6. Server → Client: Server Hello Done")
    logger.info("7. Client → Server: Client Key Exchange")
    logger.info("8. Client → Server: Change Cipher Spec")
    logger.info("9. Client → Server: Finished")
    logger.info("10. Server → Client: Change Cipher Spec")
    logger.info("11. Server → Client: Finished")
    
    logger.info("\n关键特性：")
    logger.info("- Hello Verify Request防止DoS攻击")
    logger.info("- Cookie验证客户端地址真实性")
    logger.info("- 只有验证通过的客户端才能继续握手")

def main():
    """主函数"""
    print("DTLS Hello Verify Request机制测试")
    print("=" * 50)
    
    # 分析握手流程
    analyze_handshake_flow()
    
    # 执行测试
    test_hello_verify_request()

if __name__ == "__main__":
    main()

