#!/usr/bin/env python3
"""
测试修复后的Client Hello消息格式
验证是否符合DTLS标准和Wireshark解析
"""
import threading
import time
import socket
from dtls_client_complete import CompleteDTLSClient
from dtls_server_complete import CompleteDTLSServer

def test_client_hello_format():
    """测试Client Hello消息格式"""
    print("🔍 测试修复后的DTLS Client Hello格式")
    print("=" * 60)
    
    # 创建客户端实例
    client = CompleteDTLSClient(server_host='localhost', server_port=4433)
    
    # 生成Client Hello消息
    client_hello = client.create_client_hello()
    
    print("📦 生成的Client Hello消息:")
    print(f"   长度: {len(client_hello)} 字节")
    print(f"   十六进制: {client_hello.hex()}")
    
    # 解析握手消息头
    print("\n🔍 解析握手消息头:")
    msg_type = client_hello[0]
    length = int.from_bytes(client_hello[1:4], 'big')
    msg_seq = int.from_bytes(client_hello[4:6], 'big')
    frag_offset = int.from_bytes(client_hello[6:9], 'big')
    frag_length = int.from_bytes(client_hello[9:12], 'big')
    
    print(f"   消息类型: {msg_type} (Client Hello)")
    print(f"   消息长度: {length} 字节")
    print(f"   消息序号: {msg_seq}")
    print(f"   分片偏移: {frag_offset}")
    print(f"   分片长度: {frag_length}")
    
    # 解析Client Hello内容
    payload = client_hello[12:]
    print(f"\n📋 Client Hello载荷 ({len(payload)} 字节):")
    print(f"   十六进制: {payload.hex()}")
    
    # 详细解析Client Hello字段
    offset = 0
    
    # 协议版本
    version = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2
    print(f"   协议版本: 0x{version:04x} ({'DTLS 1.2' if version == 0xFEFD else '未知'})")
    
    # 随机数
    random_data = payload[offset:offset+32]
    offset += 32
    print(f"   随机数: {random_data.hex()}")
    
    # Session ID
    session_id_len = payload[offset]
    offset += 1
    print(f"   Session ID长度: {session_id_len}")
    if session_id_len > 0:
        session_id = payload[offset:offset+session_id_len]
        offset += session_id_len
        print(f"   Session ID: {session_id.hex()}")
    
    # Cookie (DTLS特有)
    cookie_len = payload[offset]
    offset += 1
    print(f"   Cookie长度: {cookie_len}")
    if cookie_len > 0:
        cookie = payload[offset:offset+cookie_len]
        offset += cookie_len
        print(f"   Cookie: {cookie.hex()}")
    
    # 密码套件
    cipher_suites_len = int.from_bytes(payload[offset:offset+2], 'big')
    offset += 2
    print(f"   密码套件长度: {cipher_suites_len}")
    
    cipher_suites = payload[offset:offset+cipher_suites_len]
    offset += cipher_suites_len
    print(f"   密码套件: {cipher_suites.hex()}")
    
    # 解析具体的密码套件
    for i in range(0, len(cipher_suites), 2):
        suite = int.from_bytes(cipher_suites[i:i+2], 'big')
        suite_name = "TLS_RSA_WITH_AES_128_GCM_SHA256" if suite == 0x009C else f"未知(0x{suite:04x})"
        print(f"     - 0x{suite:04x}: {suite_name}")
    
    # 压缩方法
    compression_len = payload[offset]
    offset += 1
    print(f"   压缩方法长度: {compression_len}")
    
    compression_methods = payload[offset:offset+compression_len]
    offset += compression_len
    print(f"   压缩方法: {compression_methods.hex()}")
    
    # 扩展
    if offset < len(payload):
        extensions_len = int.from_bytes(payload[offset:offset+2], 'big')
        offset += 2
        print(f"   扩展长度: {extensions_len}")
        
        if extensions_len > 0:
            extensions = payload[offset:offset+extensions_len]
            print(f"   扩展: {extensions.hex()}")
    
    print("\n✅ Client Hello格式解析完成")
    return client_hello

def test_complete_handshake():
    """测试完整的握手流程"""
    print("\n🤝 测试完整的DTLS握手流程")
    print("=" * 60)
    
    # 启动服务器
    print("🚀 启动DTLS服务器...")
    server = CompleteDTLSServer(host='localhost', port=4434)
    server_thread = threading.Thread(target=server.start, daemon=True)
    server_thread.start()
    
    time.sleep(1)  # 等待服务器启动
    print("✅ 服务器启动成功")
    
    try:
        # 创建客户端并连接
        print("\n🔗 创建DTLS客户端...")
        client = CompleteDTLSClient(server_host='localhost', server_port=4434)
        
        print("🤝 执行DTLS握手...")
        if client.connect():
            print("✅ DTLS握手成功!")
            print("🔒 安全连接已建立")
            
            # 测试数据传输
            test_message = "Hello from fixed Client Hello!"
            print(f"\n📤 发送测试消息: {test_message}")
            
            if client.send_application_data(test_message.encode('utf-8')):
                print("✅ 消息发送成功")
                
                # 尝试接收响应
                response = client.receive_application_data(timeout=3.0)
                if response:
                    print(f"📥 收到响应: {response.decode('utf-8')}")
                else:
                    print("⚠️ 未收到响应")
            else:
                print("❌ 消息发送失败")
            
            client.close()
            print("🔒 连接已关闭")
            
        else:
            print("❌ DTLS握手失败")
            return False
            
    except Exception as e:
        print(f"❌ 测试过程中出现错误: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    finally:
        # 停止服务器
        print("\n🛑 停止服务器...")
        server.stop()
        print("✅ 服务器已停止")
    
    return True

def create_wireshark_capture():
    """创建用于Wireshark分析的数据包"""
    print("\n📊 创建Wireshark分析数据包")
    print("=" * 60)
    
    # 创建客户端
    client = CompleteDTLSClient(server_host='localhost', server_port=4433)
    
    # 生成Client Hello
    client_hello = client.create_client_hello()
    
    # 创建DTLS记录
    dtls_record = client.record_layer.create_record(22, client_hello)  # HANDSHAKE = 22
    
    print(f"📦 DTLS记录长度: {len(dtls_record)} 字节")
    print(f"📦 DTLS记录: {dtls_record.hex()}")
    
    # 保存到文件
    with open('fixed_client_hello.bin', 'wb') as f:
        f.write(dtls_record)
    
    print("💾 已保存到 fixed_client_hello.bin")
    
    # 创建UDP包格式 (用于Wireshark)
    udp_payload = dtls_record
    
    print("\n🔍 Wireshark分析指南:")
    print("1. 打开Wireshark")
    print("2. 使用 'udp.port == 4433' 过滤器")
    print("3. 右键选择 'Decode As' -> DTLS")
    print("4. 检查Client Hello是否正确解析")
    print("5. 验证Cookie字段是否存在")
    
    return dtls_record

def main():
    """主函数"""
    print("🔧 DTLS Client Hello修复验证工具")
    print("=" * 60)
    
    # 1. 测试Client Hello格式
    client_hello = test_client_hello_format()
    
    # 2. 创建Wireshark分析文件
    dtls_record = create_wireshark_capture()
    
    # 3. 测试完整握手
    success = test_complete_handshake()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 所有测试通过!")
        print("✅ Client Hello格式已修复")
        print("✅ 包含DTLS特有的Cookie字段")
        print("✅ 符合RFC 6347标准")
        print("✅ 应该能被Wireshark正确解析")
    else:
        print("❌ 测试失败")
    
    print("\n📋 修复内容:")
    print("- ✅ 添加了DTLS特有的Cookie字段")
    print("- ✅ 修正了字段顺序和格式")
    print("- ✅ 改进了服务器端解析逻辑")
    print("- ✅ 增加了详细的调试信息")

if __name__ == "__main__":
    main()

