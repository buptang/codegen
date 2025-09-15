#!/usr/bin/env python3
"""
DTLS客户端使用示例
演示修复后的CBC模式功能
"""

import logging
import sys

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """主函数"""
    try:
        # 导入修复后的DTLS客户端
        from dtls_client_complete import CompleteDTLSClient
        
        logger.info("=== DTLS客户端使用示例 ===")
        
        # 创建DTLS客户端实例
        client = CompleteDTLSClient(
            server_host='127.0.0.1',    # 服务器地址
            server_port=4433,           # DTLS端口
            server_name='localhost'     # 服务器名称（用于SNI）
        )
        
        logger.info("创建DTLS客户端成功")
        
        # 尝试连接到DTLS服务器
        logger.info("开始DTLS握手...")
        success = client.connect()
        
        if success:
            logger.info("✅ DTLS握手成功！")
            logger.info("现在可以发送加密消息了")
            
            # 发送测试消息
            messages = [
                "Hello DTLS Server!",
                "This is a test message with CBC encryption.",
                "测试中文消息",
                "Final test message"
            ]
            
            for i, message in enumerate(messages, 1):
                logger.info(f"发送消息 {i}: {message}")
                
                if client.send_message(message):
                    logger.info(f"✅ 消息 {i} 发送成功")
                    
                    # 尝试接收响应
                    response = client.receive_message()
                    if response:
                        logger.info(f"✅ 收到响应 {i}: {response}")
                    else:
                        logger.warning(f"⚠️ 未收到响应 {i}")
                else:
                    logger.error(f"❌ 消息 {i} 发送失败")
                    
        else:
            logger.error("❌ DTLS握手失败")
            logger.info("可能的原因：")
            logger.info("1. 服务器未运行")
            logger.info("2. 网络连接问题")
            logger.info("3. 证书验证失败")
            logger.info("4. 密码套件不匹配")
        
        # 清理连接
        client.close()
        logger.info("DTLS连接已关闭")
        
        return success
        
    except ImportError as e:
        logger.error(f"导入DTLS客户端失败: {e}")
        logger.info("请确保dtls_client_complete.py文件存在")
        return False
        
    except Exception as e:
        logger.error(f"运行过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_cbc_only():
    """仅测试CBC加密功能（不需要服务器）"""
    try:
        from dtls_client_complete import DTLSRecord, DTLSConstants
        
        logger.info("=== CBC加密功能测试 ===")
        
        # 创建记录层实例
        record = DTLSRecord()
        
        # 设置CBC模式
        record.cipher_mode = 'CBC'
        record.cipher_algorithm = 'AES'
        record.encryption_enabled = True
        record.sequence_number = 1
        
        # 设置测试密钥
        record.client_write_key = b'0123456789abcdef'  # 16字节AES-128密钥
        record.client_write_mac_key = b'mac_key_20_bytes_123'  # 20字节HMAC-SHA1密钥
        
        # 测试数据
        test_data = b"Hello DTLS with CBC encryption!"
        content_type = DTLSConstants.HANDSHAKE
        
        logger.info(f"原始数据: {test_data}")
        logger.info(f"数据长度: {len(test_data)}")
        
        # 执行CBC加密
        encrypted_data = record._encrypt_data_cbc(content_type, test_data)
        
        logger.info(f"加密后长度: {len(encrypted_data)}")
        logger.info(f"加密成功: {len(encrypted_data) > len(test_data)}")
        
        # 分析加密结构
        if len(encrypted_data) >= 16:
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]
            
            logger.info(f"IV (前8字节): {iv[:8].hex()}")
            logger.info(f"密文长度: {len(ciphertext)}")
            logger.info(f"填充正确: {len(ciphertext) % 16 == 0}")
        
        logger.info("✅ CBC加密功能测试完成")
        return True
        
    except Exception as e:
        logger.error(f"CBC测试失败: {e}")
        return False

if __name__ == "__main__":
    logger.info("DTLS客户端示例程序")
    logger.info("支持的密码套件包括: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA")
    
    # 首先测试CBC功能
    cbc_success = test_cbc_only()
    
    if cbc_success:
        logger.info("\n" + "="*50)
        # 然后尝试完整的DTLS连接
        dtls_success = main()
        
        if not dtls_success:
            logger.info("\n💡 提示：")
            logger.info("如果握手失败，可以尝试启动一个DTLS服务器：")
            logger.info("openssl s_server -dtls -accept 4433 -cert server.crt -key server.key")
    else:
        logger.error("CBC功能测试失败，请检查代码")
        dtls_success = False
    
    sys.exit(0 if (cbc_success and dtls_success) else 1)

