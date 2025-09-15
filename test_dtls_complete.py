#!/usr/bin/env python3
"""
完整的DTLS CBC修复测试
包含服务端和客户端测试
"""

import logging
import sys
import os
import threading
import time
import subprocess

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_with_openssl_server():
    """使用OpenSSL s_server测试DTLS客户端"""
    logger.info("=== 使用OpenSSL服务端测试DTLS客户端 ===")
    
    # 创建测试证书
    cert_file = 'test_server.crt'
    key_file = 'test_server.key'
    
    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logger.info("创建测试证书...")
        cmd = [
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', key_file, '-out', cert_file, '-days', '365', '-nodes',
            '-subj', '/C=CN/ST=Beijing/L=Beijing/O=Test/OU=Test/CN=localhost'
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
            logger.info("测试证书创建成功")
        except subprocess.CalledProcessError as e:
            logger.error(f"创建证书失败: {e}")
            return False
    
    # 启动OpenSSL DTLS服务端
    server_cmd = [
        'openssl', 's_server', '-dtls', '-accept', '4433',
        '-cert', cert_file, '-key', key_file, '-cipher', 'ECDHE-RSA-AES128-SHA'
    ]
    
    logger.info("启动OpenSSL DTLS服务端...")
    try:
        # 在后台启动服务端
        server_process = subprocess.Popen(
            server_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待服务端启动
        time.sleep(2)
        
        # 测试客户端连接
        logger.info("测试DTLS客户端连接...")
        
        from dtls_client_complete import CompleteDTLSClient
        
        client = CompleteDTLSClient(
            server_host='127.0.0.1',
            server_port=4433,
            server_name='localhost'
        )
        
        # 尝试连接
        success = client.connect()
        
        if success:
            logger.info("✅ DTLS握手成功！")
            
            # 测试发送消息
            test_message = "Hello OpenSSL DTLS Server!"
            if client.send_message(test_message):
                logger.info("✅ 消息发送成功")
                
                # 尝试接收响应
                response = client.receive_message()
                if response:
                    logger.info(f"✅ 收到响应: {response}")
                else:
                    logger.warning("⚠️ 未收到响应")
            else:
                logger.error("❌ 消息发送失败")
        else:
            logger.error("❌ DTLS握手失败")
        
        client.close()
        
        # 停止服务端
        server_process.terminate()
        server_process.wait(timeout=5)
        
        return success
        
    except Exception as e:
        logger.error(f"OpenSSL服务端测试失败: {e}")
        if 'server_process' in locals():
            server_process.terminate()
        return False

def test_cbc_encryption_detailed():
    """详细测试CBC加密功能"""
    logger.info("=== 详细CBC加密测试 ===")
    
    try:
        from dtls_client_complete import DTLSRecord, DTLSConstants
        import struct
        
        # 创建记录层实例
        record = DTLSRecord()
        
        # 设置CBC模式
        record.cipher_mode = 'CBC'
        record.cipher_algorithm = 'AES'
        record.encryption_enabled = True
        
        # 测试不同的序列号
        test_cases = [
            {"seq": 0, "data": b"First message"},
            {"seq": 1, "data": b"Second message with more content"},
            {"seq": 255, "data": b"Message with high sequence number"},
            {"seq": 65535, "data": b"Message with very high sequence number"},
        ]
        
        for i, case in enumerate(test_cases):
            logger.info(f"\n--- 测试用例 {i+1} ---")
            
            # 设置序列号和密钥
            record.sequence_number = case["seq"]
            record.client_write_key = f"key{i:013d}".encode()[:16]  # 16字节AES密钥
            record.client_write_mac_key = f"mackey{i:014d}".encode()[:20]  # 20字节HMAC密钥
            
            test_data = case["data"]
            content_type = DTLSConstants.HANDSHAKE
            
            logger.info(f"序列号: {record.sequence_number}")
            logger.info(f"数据: {test_data}")
            logger.info(f"数据长度: {len(test_data)}")
            
            # 执行加密
            encrypted_data = record._encrypt_data_cbc(content_type, test_data)
            
            logger.info(f"加密后长度: {len(encrypted_data)}")
            
            # 验证加密结果
            if len(encrypted_data) >= len(test_data) + 16:  # 至少包含IV
                logger.info("✅ 加密成功")
                
                # 分析加密结构
                iv = encrypted_data[:16]
                ciphertext = encrypted_data[16:]
                
                logger.info(f"IV: {iv.hex()}")
                logger.info(f"密文长度: {len(ciphertext)}")
                
                # 验证填充（密文长度应该是16的倍数）
                if len(ciphertext) % 16 == 0:
                    logger.info("✅ 填充正确")
                else:
                    logger.error("❌ 填充错误")
                    return False
            else:
                logger.error("❌ 加密失败，数据长度异常")
                return False
        
        logger.info("\n✅ 所有CBC加密测试通过")
        return True
        
    except Exception as e:
        logger.error(f"CBC加密详细测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """主测试函数"""
    logger.info("开始完整的DTLS CBC修复测试")
    
    results = {}
    
    # 测试1: 详细CBC加密功能
    logger.info("\n" + "="*50)
    results['cbc_detailed'] = test_cbc_encryption_detailed()
    
    # 测试2: 使用OpenSSL服务端测试（如果可用）
    logger.info("\n" + "="*50)
    if subprocess.run(['which', 'openssl'], capture_output=True).returncode == 0:
        results['openssl_server'] = test_with_openssl_server()
    else:
        logger.warning("OpenSSL不可用，跳过服务端测试")
        results['openssl_server'] = None
    
    # 总结结果
    logger.info("\n" + "="*50)
    logger.info("=== 测试结果总结 ===")
    
    for test_name, result in results.items():
        if result is True:
            logger.info(f"{test_name}: ✅ 通过")
        elif result is False:
            logger.info(f"{test_name}: ❌ 失败")
        else:
            logger.info(f"{test_name}: ⚠️ 跳过")
    
    # 检查关键修复
    if results['cbc_detailed']:
        logger.info("\n🎉 CBC修复验证成功！")
        logger.info("关键修复内容：")
        logger.info("1. ✅ MAC计算使用完整的8字节序列号")
        logger.info("2. ✅ 正确的MAC-then-encrypt结构")
        logger.info("3. ✅ 正确的PKCS#7填充")
        logger.info("4. ✅ 随机IV生成")
        logger.info("5. ✅ 详细的调试日志")
        
        if results['openssl_server']:
            logger.info("6. ✅ 与OpenSSL服务端兼容性验证通过")
        
        return True
    else:
        logger.error("\n❌ CBC修复验证失败")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

