#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的DTLS服务器实现（用于测试）
注意：这是一个简化的实现，仅用于测试目的
"""

import socket
import struct
import logging
import threading
import time
from typing import Dict, Tuple

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DTLSConstants:
    """DTLS协议常量"""
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    CERTIFICATE = 11
    SERVER_HELLO_DONE = 14
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    
    DTLS_1_2 = 0xFEFD

class SimpleDTLSServer:
    """简化的DTLS服务器（仅用于测试）"""
    
    def __init__(self, host='127.0.0.1', port=4433):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.clients = {}  # 存储客户端状态
        
    def start(self):
        """启动服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info(f"DTLS测试服务器启动在 {self.host}:{self.port}")
            logger.info("注意：这是一个简化的测试服务器，不提供真正的DTLS加密")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    logger.info(f"收到来自 {addr} 的数据: {len(data)} 字节")
                    
                    # 在新线程中处理客户端
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(data, addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.error as e:
                    if self.running:
                        logger.error(f"套接字错误: {e}")
                        
        except Exception as e:
            logger.error(f"服务器启动失败: {e}")
        finally:
            self.cleanup()
    
    def handle_client(self, data: bytes, addr: Tuple[str, int]):
        """处理客户端请求"""
        try:
            if len(data) < 5:
                logger.warning(f"来自 {addr} 的数据太短")
                return
            
            content_type = data[0]
            logger.info(f"处理来自 {addr} 的消息类型: {content_type}")
            
            if content_type == DTLSConstants.HANDSHAKE:
                self.handle_handshake(data, addr)
            elif content_type == DTLSConstants.CHANGE_CIPHER_SPEC:
                self.handle_change_cipher_spec(data, addr)
            elif content_type == DTLSConstants.APPLICATION_DATA:
                self.handle_application_data(data, addr)
            else:
                logger.warning(f"未知消息类型: {content_type}")
                
        except Exception as e:
            logger.error(f"处理客户端 {addr} 时出错: {e}")
    
    def handle_handshake(self, data: bytes, addr: Tuple[str, int]):
        """处理握手消息"""
        if len(data) < 9:
            logger.warning("握手消息太短")
            return
        
        msg_type = data[5]
        logger.info(f"握手消息类型: {msg_type}")
        
        if msg_type == DTLSConstants.CLIENT_HELLO:
            self.handle_client_hello(data, addr)
        elif msg_type == DTLSConstants.CLIENT_KEY_EXCHANGE:
            logger.info(f"收到来自 {addr} 的Client Key Exchange")
            # 简化处理：不做任何操作
        elif msg_type == DTLSConstants.FINISHED:
            logger.info(f"收到来自 {addr} 的Finished消息")
            self.send_finished(addr)
        else:
            logger.info(f"收到握手消息类型: {msg_type}")
    
    def handle_client_hello(self, data: bytes, addr: Tuple[str, int]):
        """处理Client Hello"""
        logger.info(f"处理来自 {addr} 的Client Hello")
        
        # 简化解析：检查是否有Cookie
        try:
            # 跳过记录头(5字节)和握手头(4字节)
            offset = 9
            
            # 跳过版本(2字节)和随机数(32字节)
            offset += 34
            
            # Session ID长度
            if offset < len(data):
                session_id_len = data[offset]
                offset += 1 + session_id_len
                
                # Cookie长度
                if offset < len(data):
                    cookie_len = data[offset]
                    
                    if cookie_len == 0:
                        # 没有Cookie，发送Hello Verify Request
                        logger.info(f"发送Hello Verify Request到 {addr}")
                        self.send_hello_verify_request(addr)
                    else:
                        # 有Cookie，发送Server Hello
                        logger.info(f"发送Server Hello到 {addr}")
                        self.send_server_hello(addr)
                        self.send_certificate(addr)
                        self.send_server_hello_done(addr)
                        
        except Exception as e:
            logger.error(f"解析Client Hello失败: {e}")
    
    def send_hello_verify_request(self, addr: Tuple[str, int]):
        """发送Hello Verify Request"""
        # 生成简单的Cookie
        cookie = b"test_cookie_123"
        
        # 构建Hello Verify Request消息
        hvr_data = struct.pack('!H', DTLSConstants.DTLS_1_2)  # 版本
        hvr_data += struct.pack('!B', len(cookie))  # Cookie长度
        hvr_data += cookie  # Cookie
        
        # 发送握手消息
        self.send_handshake_message(DTLSConstants.HELLO_VERIFY_REQUEST, hvr_data, addr)
    
    def send_server_hello(self, addr: Tuple[str, int]):
        """发送Server Hello"""
        import os
        
        # 构建Server Hello消息
        sh_data = struct.pack('!H', DTLSConstants.DTLS_1_2)  # 版本
        sh_data += os.urandom(32)  # 服务器随机数
        sh_data += struct.pack('!B', 0)  # Session ID长度（0）
        sh_data += struct.pack('!H', 0x002F)  # 密码套件
        sh_data += struct.pack('!B', 0)  # 压缩方法
        sh_data += struct.pack('!H', 0)  # 扩展长度
        
        self.send_handshake_message(DTLSConstants.SERVER_HELLO, sh_data, addr)
    
    def send_certificate(self, addr: Tuple[str, int]):
        """发送证书（空证书）"""
        # 发送空证书链
        cert_data = struct.pack('!I', 0)[1:]  # 证书链长度（0）
        self.send_handshake_message(DTLSConstants.CERTIFICATE, cert_data, addr)
    
    def send_server_hello_done(self, addr: Tuple[str, int]):
        """发送Server Hello Done"""
        # Server Hello Done消息为空
        self.send_handshake_message(DTLSConstants.SERVER_HELLO_DONE, b'', addr)
    
    def send_finished(self, addr: Tuple[str, int]):
        """发送Finished消息"""
        # 先发送Change Cipher Spec
        self.send_change_cipher_spec(addr)
        
        # 然后发送Finished
        finished_data = b'\\x00' * 12  # 简化的Finished消息
        self.send_handshake_message(DTLSConstants.FINISHED, finished_data, addr)
    
    def send_handshake_message(self, msg_type: int, data: bytes, addr: Tuple[str, int]):
        """发送握手消息"""
        # 构建握手消息头
        handshake_header = struct.pack('!BBH', msg_type, 0, len(data)) + data
        
        # 构建DTLS记录头
        record_header = struct.pack('!BBHH',
                                  DTLSConstants.HANDSHAKE,
                                  0xFE, 0xFD,  # DTLS 1.2
                                  len(handshake_header))
        
        # 发送消息
        message = record_header + handshake_header
        self.socket.sendto(message, addr)
        logger.info(f"发送握手消息类型 {msg_type} 到 {addr}")
    
    def handle_change_cipher_spec(self, data: bytes, addr: Tuple[str, int]):
        """处理Change Cipher Spec"""
        logger.info(f"收到来自 {addr} 的Change Cipher Spec")
        # 简化处理：不做任何操作
    
    def send_change_cipher_spec(self, addr: Tuple[str, int]):
        """发送Change Cipher Spec"""
        ccs_data = struct.pack('!B', 1)
        
        record_header = struct.pack('!BBHH',
                                  DTLSConstants.CHANGE_CIPHER_SPEC,
                                  0xFE, 0xFD,  # DTLS 1.2
                                  len(ccs_data))
        
        message = record_header + ccs_data
        self.socket.sendto(message, addr)
        logger.info(f"发送Change Cipher Spec到 {addr}")
    
    def handle_application_data(self, data: bytes, addr: Tuple[str, int]):
        """处理应用数据"""
        if len(data) < 5:
            return
        
        payload = data[5:]  # 跳过记录头
        logger.info(f"收到来自 {addr} 的应用数据: {payload}")
        
        try:
            message = payload.decode('utf-8')
            logger.info(f"应用消息: {message}")
            
            # 发送回显响应
            response = f"Echo: {message}"
            self.send_application_data(response.encode(), addr)
            
        except UnicodeDecodeError:
            logger.warning("无法解码应用数据")
    
    def send_application_data(self, data: bytes, addr: Tuple[str, int]):
        """发送应用数据"""
        record_header = struct.pack('!BBHH',
                                  DTLSConstants.APPLICATION_DATA,
                                  0xFE, 0xFD,  # DTLS 1.2
                                  len(data))
        
        message = record_header + data
        self.socket.sendto(message, addr)
        logger.info(f"发送应用数据到 {addr}: {data}")
    
    def stop(self):
        """停止服务器"""
        self.running = False
        if self.socket:
            self.socket.close()
    
    def cleanup(self):
        """清理资源"""
        if self.socket:
            self.socket.close()
            self.socket = None
        logger.info("服务器已停止")

def main():
    """主函数"""
    print("🚀 简单DTLS测试服务器")
    print("=" * 30)
    print("注意：这是一个简化的测试服务器，不提供真正的DTLS加密")
    print("仅用于测试DTLS客户端的握手流程")
    print()
    
    server = SimpleDTLSServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\\n⏹️ 服务器被用户停止")
    except Exception as e:
        print(f"❌ 服务器错误: {e}")
    finally:
        server.stop()

if __name__ == "__main__":
    main()

