#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS密码套件测试脚本
测试新增的密码套件支持
"""

import sys
import time
import threading
from dtls_client_complete import DTLSClient, DTLSConstants
from dtls_server_complete import DTLSServer

def test_cipher_suites():
    """测试密码套件功能"""
    print("🔐 开始DTLS密码套件测试")
    
    # 启动服务器
    server = DTLSServer()
    server_thread = threading.Thread(target=server.start, args=('127.0.0.1', 4433))
    server_thread.daemon = True
    server_thread.start()
    
    # 等待服务器启动
    time.sleep(1)
    
    try:
        # 创建客户端
        client = DTLSClient()
        client.server_name = "localhost"
        
        print("📡 连接到DTLS服务器...")
        success = client.connect('127.0.0.1', 4433)
        
        if success:
            print("✅ DTLS握手成功完成！")
            print(f"🔒 协商的密码套件: 0x{client.cipher_suite:04X}")
            
            # 测试发送数据
            test_message = "Hello with new cipher suites!"
            print(f"📤 发送消息: {test_message}")
            
            if client.send_data(test_message.encode('utf-8')):
                print("✅ 数据发送成功")
                
                # 尝试接收响应
                response = client.receive_data()
                if response:
                    print(f"📥 收到响应: {response.decode('utf-8', errors='ignore')}")
                else:
                    print("⚠️ 未收到响应")
            else:
                print("❌ 数据发送失败")
        else:
            print("❌ DTLS握手失败")
            
    except Exception as e:
        print(f"❌ 测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        # 清理资源
        try:
            client.cleanup()
        except:
            pass
        try:
            server.cleanup()
        except:
            pass

def test_cipher_suite_constants():
    """测试密码套件常量"""
    print("\n🔧 测试密码套件常量")
    
    cipher_suites = [
        ("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", DTLSConstants.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 0xC02C),
        ("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", DTLSConstants.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 0xC02B),
        ("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", DTLSConstants.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 0xC030),
        ("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 0xC028),
        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 0xC013),
        ("TLS_EMPTY_RENEGOTIATION_INFO_SCSV", DTLSConstants.TLS_EMPTY_RENEGOTIATION_INFO_SCSV, 0x00FF),
    ]
    
    print("📋 验证密码套件常量:")
    all_correct = True
    
    for name, constant_value, expected_value in cipher_suites:
        if constant_value == expected_value:
            print(f"✅ {name}: 0x{constant_value:04X}")
        else:
            print(f"❌ {name}: 期望 0x{expected_value:04X}, 实际 0x{constant_value:04X}")
            all_correct = False
    
    if all_correct:
        print("🎉 所有密码套件常量验证成功！")
    else:
        print("❌ 部分密码套件常量验证失败")

def test_client_hello_cipher_suites():
    """测试Client Hello中的密码套件"""
    print("\n📨 测试Client Hello密码套件")
    
    try:
        client = DTLSClient()
        client.server_name = "test.example.com"
        
        # 创建Client Hello消息
        client_hello = client.create_client_hello()
        
        print(f"✅ Client Hello创建成功，长度: {len(client_hello)} 字节")
        
        # 简单验证是否包含我们的密码套件
        # 这里我们检查是否包含0xC02C (TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)
        if b'\xC0\x2C' in client_hello:
            print("✅ 找到密码套件 0xC02C (ECDHE-ECDSA-AES256-GCM-SHA384)")
        else:
            print("⚠️ 未找到密码套件 0xC02C")
            
        if b'\xC0\x2B' in client_hello:
            print("✅ 找到密码套件 0xC02B (ECDHE-ECDSA-AES128-GCM-SHA256)")
        else:
            print("⚠️ 未找到密码套件 0xC02B")
            
        if b'\xC0\x30' in client_hello:
            print("✅ 找到密码套件 0xC030 (ECDHE-RSA-AES256-GCM-SHA384)")
        else:
            print("⚠️ 未找到密码套件 0xC030")
            
        if b'\x00\xFF' in client_hello:
            print("✅ 找到重新协商指示 0x00FF")
        else:
            print("⚠️ 未找到重新协商指示 0x00FF")
        
        print("🎯 Client Hello密码套件测试完成")
        
    except Exception as e:
        print(f"❌ Client Hello测试失败: {e}")
        import traceback
        traceback.print_exc()

def main():
    """主函数"""
    print("=" * 60)
    print("🔐 DTLS密码套件完整测试套件")
    print("=" * 60)
    
    # 测试密码套件常量
    test_cipher_suite_constants()
    
    # 测试Client Hello中的密码套件
    test_client_hello_cipher_suites()
    
    # 测试完整的DTLS通信
    test_cipher_suites()
    
    print("\n" + "=" * 60)
    print("🏁 密码套件测试完成")
    print("=" * 60)

if __name__ == "__main__":
    main()

