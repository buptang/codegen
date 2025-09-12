#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端测试脚本
测试完整的DTLS握手流程和扩展功能
"""

import sys
import time
import threading
from dtls_client_complete import DTLSClient
from dtls_server_complete import DTLSServer

def test_dtls_client():
    """测试DTLS客户端"""
    print("🚀 开始DTLS客户端测试")
    
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
        
        # 设置服务器名称（用于SNI扩展）
        client.server_name = "localhost"
        
        print("📡 连接到DTLS服务器...")
        success = client.connect('127.0.0.1', 4433)
        
        if success:
            print("✅ DTLS握手成功完成！")
            
            # 测试发送数据
            test_message = "Hello, DTLS Server! 这是一条测试消息。"
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

def test_extensions():
    """测试扩展功能"""
    print("\n🔧 测试DTLS扩展功能")
    
    client = DTLSClient()
    client.server_name = "test.example.com"
    
    # 测试各种扩展创建
    print("📋 测试扩展创建:")
    
    try:
        # SNI扩展
        sni_ext = client.create_sni_extension("test.example.com")
        print(f"✅ SNI扩展: {len(sni_ext)} 字节")
        
        # EC点格式扩展
        ec_ext = client.create_ec_point_formats_extension()
        print(f"✅ EC点格式扩展: {len(ec_ext)} 字节")
        
        # 支持的椭圆曲线组扩展
        groups_ext = client.create_supported_groups_extension()
        print(f"✅ 支持的椭圆曲线组扩展: {len(groups_ext)} 字节")
        
        # 签名算法扩展
        sig_ext = client.create_signature_algorithms_extension()
        print(f"✅ 签名算法扩展: {len(sig_ext)} 字节")
        
        # OCSP状态请求扩展
        ocsp_ext = client.create_status_request_extension()
        print(f"✅ OCSP状态请求扩展: {len(ocsp_ext)} 字节")
        
        # 先加密后MAC扩展
        etm_ext = client.create_encrypt_then_mac_extension()
        print(f"✅ 先加密后MAC扩展: {len(etm_ext)} 字节")
        
        # 扩展主密钥扩展
        ems_ext = client.create_extended_master_secret_extension()
        print(f"✅ 扩展主密钥扩展: {len(ems_ext)} 字节")
        
        # 会话票据扩展
        ticket_ext = client.create_session_ticket_extension()
        print(f"✅ 会话票据扩展: {len(ticket_ext)} 字节")
        
        print("🎉 所有扩展创建成功！")
        
    except Exception as e:
        print(f"❌ 扩展测试失败: {e}")
        import traceback
        traceback.print_exc()

def main():
    """主函数"""
    print("=" * 60)
    print("🔐 DTLS客户端完整测试套件")
    print("=" * 60)
    
    # 测试扩展功能
    test_extensions()
    
    # 测试完整的DTLS通信
    test_dtls_client()
    
    print("\n" + "=" * 60)
    print("🏁 测试完成")
    print("=" * 60)

if __name__ == "__main__":
    main()

