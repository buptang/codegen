#!/usr/bin/env python3
"""
简单的DTLS服务端用于测试CBC修复
"""

import socket
import threading
import logging
import time
import ssl
import os

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SimpleDTLSServer:
    """简单的DTLS服务端"""
    
    def __init__(self, host='127.0.0.1', port=4433):
        self.host = host
        self.port = port
        self.running = False
        self.socket = None
        
    def create_test_certificate(self):
        """创建测试用的自签名证书"""
        cert_file = 'test_server.crt'
        key_file = 'test_server.key'
        
        if not os.path.exists(cert_file) or not os.path.exists(key_file):
            logger.info("创建测试证书...")
            # 使用OpenSSL创建自签名证书
            os.system(f'''
openssl req -x509 -newkey rsa:2048 -keyout {key_file} -out {cert_file} -days 365 -nodes -subj "/C=CN/ST=Beijing/L=Beijing/O=Test/OU=Test/CN=localhost"
            '''.strip())
            
        return cert_file, key_file
    
    def start(self):
        """启动DTLS服务端"""
        try:
            # 创建测试证书
            cert_file, key_file = self.create_test_certificate()
            
            # 创建UDP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            
            logger.info(f"DTLS服务端启动在 {self.host}:{self.port}")
            self.running = True
            
            # 监听连接
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    logger.info(f"收到来自 {addr} 的数据: {len(data)} 字节")
                    
                    # 简单响应（这里只是回显，实际DTLS需要复杂的握手）
                    if data:
                        # 检查是否是DTLS握手消息
                        if len(data) > 13 and data[0] == 22:  # Handshake
                            logger.info("收到DTLS握手消息")
                            # 发送简单的Hello Verify Request响应
                            response = self.create_hello_verify_request()
                            self.socket.sendto(response, addr)
                            logger.info("发送Hello Verify Request")
                        else:
                            # 回显数据
                            self.socket.sendto(data, addr)
                            logger.info(f"回显数据到 {addr}")
                            
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"处理客户端请求时出错: {e}")
                    
        except Exception as e:
            logger.error(f"启动DTLS服务端失败: {e}")
        finally:
            self.stop()
    
    def create_hello_verify_request(self):
        """创建Hello Verify Request消息"""
        # 简化的Hello Verify Request
        # DTLS记录头 + 握手消息头 + Hello Verify Request数据
        
        # Cookie (简单的测试cookie)
        cookie = b'testcookie123456'
        cookie_len = len(cookie)
        
        # Hello Verify Request消息体
        hvr_data = b'\xfe\xfd' + bytes([cookie_len]) + cookie  # version + cookie_len + cookie
        
        # 握手消息头
        msg_type = 3  # Hello Verify Request
        length = len(hvr_data)
        msg_seq = 0
        frag_offset = 0
        frag_length = length
        
        handshake_msg = (bytes([msg_type]) + 
                        length.to_bytes(3, 'big') +
                        msg_seq.to_bytes(2, 'big') +
                        frag_offset.to_bytes(3, 'big') +
                        frag_length.to_bytes(3, 'big') +
                        hvr_data)
        
        # DTLS记录头
        content_type = 22  # Handshake
        version = 0xfefd  # DTLS 1.0
        epoch = 0
        sequence = 0
        record_length = len(handshake_msg)
        
        record = (bytes([content_type]) +
                 version.to_bytes(2, 'big') +
                 epoch.to_bytes(2, 'big') +
                 sequence.to_bytes(6, 'big') +
                 record_length.to_bytes(2, 'big') +
                 handshake_msg)
        
        return record
    
    def stop(self):
        """停止服务端"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("DTLS服务端已停止")

def main():
    """主函数"""
    server = SimpleDTLSServer()
    
    try:
        # 在后台线程启动服务端
        server_thread = threading.Thread(target=server.start)
        server_thread.daemon = True
        server_thread.start()
        
        logger.info("DTLS测试服务端已启动，按Ctrl+C停止")
        
        # 等待用户中断
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("收到中断信号，停止服务端...")
        server.stop()

if __name__ == "__main__":
    main()

