#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端使用示例
支持AES-128-CBC + HMAC-SHA1 和 AES-GCM 两种加密模式
"""

import logging
import socket
import sys
import os

# 添加当前目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dtls_client_complete import CompleteDTLSClient, DTLSConstants

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def main():
    """主函数 - DTLS客户端使用示例"""
    print("=== DTLS客户端使用示例 ===")
    print("支持的加密模式:")
    print("1. AES-128-CBC + HMAC-SHA1 (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)")
    print("2. AES-128-GCM (TLS_RSA_WITH_AES_128_GCM_SHA256)")
    print("3. AES-256-GCM (默认)")
    print()
    
    # 服务器配置
    server_host = "127.0.0.1"
    server_port = 4433
    
    print(f"尝试连接到DTLS服务器: {server_host}:{server_port}")
    
    try:
        # 创建DTLS客户端
        client = CompleteDTLSClient()
        
        # 连接到服务器
        success = client.connect(server_host, server_port)
        
        if success:
            print("✅ DTLS握手成功完成!")
            print(f"使用的密码套件: {hex(client.cipher_suite)}")
            
            # 根据密码套件显示加密模式
            if client.cipher_suite == DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
                print("🔒 加密模式: AES-128-CBC + HMAC-SHA1")
            elif client.cipher_suite == DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256:
                print("🔒 加密模式: AES-128-GCM")
            else:
                print("🔒 加密模式: AES-256-GCM (默认)")
            
            # 发送应用数据
            test_messages = [
                "Hello, DTLS Server!",
                "This is a test message.",
                "DTLS encryption is working!",
                "支持中文消息测试",
                "Final test message."
            ]
            
            print("\n=== 发送测试消息 ===")
            for i, message in enumerate(test_messages, 1):
                print(f"发送消息 {i}: {message}")
                success = client.send_application_data(message.encode('utf-8'))
                if success:
                    print(f"✅ 消息 {i} 发送成功")
                else:
                    print(f"❌ 消息 {i} 发送失败")
                print()
            
            # 关闭连接
            client.close()
            print("🔌 连接已关闭")
            
        else:
            print("❌ DTLS握手失败")
            
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断")
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        logger.error(f"连接错误: {e}", exc_info=True)

def test_encryption_modes():
    """测试不同的加密模式"""
    print("\n=== 加密模式测试 ===")
    
    # 测试CBC模式
    print("\n1. 测试AES-128-CBC + HMAC-SHA1模式")
    client_cbc = CompleteDTLSClient()
    client_cbc.cipher_suite = DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    
    # 模拟密钥材料
    client_cbc.client_random = b'A' * 32
    client_cbc.server_random = b'B' * 32
    client_cbc.master_secret = b'C' * 48
    
    try:
        # 重新初始化记录层
        from dtls_client_complete import DTLSRecord
        client_cbc.record_layer = DTLSRecord(client_cbc.cipher_suite)
        
        # 派生密钥
        client_cbc.derive_key_material()
        
        # 启用加密
        mac_key = getattr(client_cbc, 'client_write_mac_key', None)
        client_cbc.record_layer.enable_encryption(
            client_cbc.client_write_key,
            client_cbc.client_write_iv,
            mac_key
        )
        
        # 测试加密
        test_data = "Hello, CBC Mode! 你好，CBC模式！".encode('utf-8')
        encrypted = client_cbc.record_layer._encrypt_data_cbc(
            DTLSConstants.APPLICATION_DATA,
            test_data
        )
        
        print(f"✅ CBC加密成功")
        print(f"   原始数据长度: {len(test_data)} 字节")
        print(f"   加密后长度: {len(encrypted)} 字节")
        print(f"   加密开销: {len(encrypted) - len(test_data)} 字节")
        
    except Exception as e:
        print(f"❌ CBC模式测试失败: {e}")
    
    # 测试GCM模式
    print("\n2. 测试AES-128-GCM模式")
    client_gcm = CompleteDTLSClient()
    client_gcm.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
    
    # 模拟密钥材料
    client_gcm.client_random = b'A' * 32
    client_gcm.server_random = b'B' * 32
    client_gcm.master_secret = b'C' * 48
    
    try:
        # 重新初始化记录层
        from dtls_client_complete import DTLSRecord
        client_gcm.record_layer = DTLSRecord(client_gcm.cipher_suite)
        
        # 派生密钥
        client_gcm.derive_key_material()
        
        # 启用加密
        client_gcm.record_layer.enable_encryption(
            client_gcm.client_write_key,
            client_gcm.client_write_iv
        )
        
        # 测试加密
        test_data = "Hello, GCM Mode! 你好，GCM模式！".encode('utf-8')
        encrypted = client_gcm.record_layer._encrypt_data_gcm(
            DTLSConstants.APPLICATION_DATA,
            test_data
        )
        
        print(f"✅ GCM加密成功")
        print(f"   原始数据长度: {len(test_data)} 字节")
        print(f"   加密后长度: {len(encrypted)} 字节")
        print(f"   加密开销: {len(encrypted) - len(test_data)} 字节")
        
    except Exception as e:
        print(f"❌ GCM模式测试失败: {e}")

def show_cipher_suites():
    """显示支持的密码套件"""
    print("\n=== 支持的密码套件 ===")
    
    cipher_suites = [
        (DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "AES-128-CBC + HMAC-SHA1"),
        (DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256, "TLS_RSA_WITH_AES_128_GCM_SHA256", "AES-128-GCM"),
    ]
    
    for suite_id, suite_name, description in cipher_suites:
        print(f"• {hex(suite_id)}: {suite_name}")
        print(f"  描述: {description}")
        print()

if __name__ == "__main__":
    print("DTLS客户端示例程序")
    print("=" * 50)
    
    # 显示支持的密码套件
    show_cipher_suites()
    
    # 测试加密模式
    test_encryption_modes()
    
    print("\n" + "=" * 50)
    print("如果要连接真实的DTLS服务器，请取消注释下面的代码:")
    print("# main()")
    
    # 如果需要连接真实服务器，取消注释下面这行
    # main()

