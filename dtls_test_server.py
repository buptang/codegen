#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简单的DTLS测试服务器
用于测试DTLS客户端的加解密功能
"""

import socket
import threading
import logging
from dtls_client_fixed import DTLSRecordLayer, DTLSConstants

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DTLSTestServer:
    def __init__(self, host='127.0.0.1', port=4433):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.record_layer = DTLSRecordLayer()
        
    def start(self):
        """启动服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info(f"DTLS测试服务器启动在 {self.host}:{self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    logger.info(f"收到来自 {addr} 的数据，长度: {len(data)}")
                    
                    # 解析DTLS记录
                    try:
                        content_type, payload = self.record_layer.parse_record(data)
                        logger.info(f"记录类型: {content_type}, 载荷长度: {len(payload)}")
                        
                        if content_type == DTLSConstants.HANDSHAKE:
                            logger.info("收到握手消息")
                            # 可以在这里发送握手响应
                            
                        elif content_type == DTLSConstants.CHANGE_CIPHER_SPEC:
                            logger.info("收到Change Cipher Spec")
                            
                        elif content_type == DTLSConstants.APPLICATION_DATA:
                            logger.info("收到应用数据")
                            if self.record_layer.encryption_enabled:
                                logger.info("数据已加密")
                            else:
                                try:
                                    message = payload.decode('utf-8')
                                    logger.info(f"应用消息: {message}")
                                except:
                                    logger.info(f"应用数据: {payload.hex()}")
                        
                    except Exception as e:
                        logger.warning(f"解析记录失败: {e}")
                        logger.info(f"原始数据: {data.hex()[:100]}...")
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"接收数据失败: {e}")
                    
        except Exception as e:
            logger.error(f"服务器启动失败: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """停止服务器"""
        self.running = False
        if self.socket:
            self.socket.close()
        logger.info("服务器已停止")

def main():
    server = DTLSTestServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("用户中断")
        server.stop()

if __name__ == "__main__":
    main()

