#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS测试服务器
用于测试DTLS客户端连接

作者: Codegen
"""

import socket
import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DTLSTestServer:
    def __init__(self, host='localhost', port=4433):
        self.host = host
        self.port = port
        self.running = False
        
    def start(self):
        """启动测试服务器"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.host, self.port))
        self.running = True
        
        logger.info(f"DTLS测试服务器启动在 {self.host}:{self.port}")
        
        while self.running:
            try:
                data, addr = self.socket.recvfrom(4096)
                threading.Thread(target=self.handle_client, args=(data, addr)).start()
            except Exception as e:
                if self.running:
                    logger.error(f"服务器错误: {e}")
                    
    def handle_client(self, data, addr):
        """处理客户端消息"""
        try:
            message = data.decode('utf-8')
            logger.info(f"收到来自 {addr} 的消息: {message}")
            
            # 简单回显
            response = f"Echo: {message}"
            self.socket.sendto(response.encode('utf-8'), addr)
            
        except Exception as e:
            logger.error(f"处理客户端消息失败: {e}")
            
    def stop(self):
        """停止服务器"""
        self.running = False
        if hasattr(self, 'socket'):
            self.socket.close()

if __name__ == "__main__":
    server = DTLSTestServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
        print("服务器已停止")
