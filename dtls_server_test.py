#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS测试服务器
用于测试DTLS客户端连接
支持TCP和UDP两种模式

作者: Codegen
"""

import socket
import ssl
import threading
import time
import logging
import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DTLSTestServer:
    def __init__(self, host='localhost', port=4433, mode='tcp'):
        self.host = host
        self.port = port
        self.mode = mode.lower()  # 'tcp' 或 'udp'
        self.running = False
        self.socket = None
        self.ssl_context = None
        self.cert_file = "server_cert.pem"
        self.key_file = "server_key.pem"
        
    def generate_server_cert(self):
        """生成服务器证书"""
        if os.path.exists(self.cert_file) and os.path.exists(self.key_file):
            logger.info("使用现有服务器证书")
            return
            
        logger.info("生成服务器证书...")
        
        # 生成私钥
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # 创建证书
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DTLS Test Server"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())
        
        # 保存证书和私钥
        with open(self.cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        with open(self.key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        logger.info(f"服务器证书生成完成: {self.cert_file}, {self.key_file}")
    
    def setup_ssl_context(self):
        """设置SSL上下文"""
        self.generate_server_cert()
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.cert_file, self.key_file)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        return context
        
    def start(self):
        """启动测试服务器"""
        try:
            if self.mode == 'tcp':
                self.start_tcp_server()
            else:
                self.start_udp_server()
        except Exception as e:
            logger.error(f"服务器启动失败: {e}")
            
    def start_tcp_server(self):
        """启动TCP服务器（支持TLS）"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            logger.info(f"TCP测试服务器启动在 {self.host}:{self.port}")
            
            # 设置SSL上下文
            self.ssl_context = self.setup_ssl_context()
            
            while self.running:
                try:
                    client_socket, addr = self.socket.accept()
                    logger.info(f"新连接来自: {addr}")
                    
                    # 包装为SSL套接字
                    ssl_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    
                    # 在新线程中处理客户端
                    threading.Thread(
                        target=self.handle_tcp_client, 
                        args=(ssl_socket, addr),
                        daemon=True
                    ).start()
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"接受连接失败: {e}")
                        
        except Exception as e:
            logger.error(f"TCP服务器错误: {e}")
        finally:
            self.cleanup()
            
    def start_udp_server(self):
        """启动UDP服务器"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info(f"UDP测试服务器启动在 {self.host}:{self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    threading.Thread(
                        target=self.handle_udp_client, 
                        args=(data, addr),
                        daemon=True
                    ).start()
                except Exception as e:
                    if self.running:
                        logger.error(f"UDP服务器错误: {e}")
                        
        except Exception as e:
            logger.error(f"UDP服务器错误: {e}")
        finally:
            self.cleanup()
            
    def handle_tcp_client(self, ssl_socket, addr):
        """处理TCP客户端连接"""
        try:
            logger.info(f"处理TCP客户端: {addr}")
            
            while True:
                data = ssl_socket.recv(4096)
                if not data:
                    break
                    
                message = data.decode('utf-8')
                logger.info(f"收到来自 {addr} 的TCP消息: {message}")
                
                # 处理特殊消息
                if message.startswith("PING"):
                    response = f"PONG {message.split(' ', 1)[1] if ' ' in message else ''}"
                elif message.startswith("FILE_TRANSFER"):
                    response = "FILE_TRANSFER_OK"
                else:
                    response = f"Echo: {message}"
                
                ssl_socket.send(response.encode('utf-8'))
                logger.info(f"发送给 {addr}: {response}")
                
        except Exception as e:
            logger.error(f"处理TCP客户端 {addr} 失败: {e}")
        finally:
            try:
                ssl_socket.close()
            except:
                pass
            logger.info(f"TCP客户端 {addr} 连接关闭")
            
    def handle_udp_client(self, data, addr):
        """处理UDP客户端消息"""
        try:
            message = data.decode('utf-8')
            logger.info(f"收到来自 {addr} 的UDP消息: {message}")
            
            # 处理特殊消息
            if message.startswith("DTLS_CLIENT_HELLO"):
                response = "DTLS_SERVER_HELLO"
            elif message.startswith("DTLS_PING"):
                response = f"DTLS_PONG {message.split('_', 2)[2] if '_' in message else ''}"
            elif message.startswith("FILE_TRANSFER"):
                response = "FILE_TRANSFER_OK"
            else:
                response = f"Echo: {message}"
            
            self.socket.sendto(response.encode('utf-8'), addr)
            logger.info(f"发送给 {addr}: {response}")
            
        except Exception as e:
            logger.error(f"处理UDP客户端消息失败: {e}")
            
    def stop(self):
        """停止服务器"""
        logger.info("正在停止服务器...")
        self.running = False
        self.cleanup()
        
    def cleanup(self):
        """清理资源"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        logger.info("服务器资源清理完成")

def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='DTLS测试服务器')
    parser.add_argument('--host', default='localhost', help='服务器主机地址')
    parser.add_argument('--port', type=int, default=4433, help='服务器端口')
    parser.add_argument('--mode', choices=['tcp', 'udp'], default='tcp', 
                       help='服务器模式: tcp (支持TLS) 或 udp')
    
    args = parser.parse_args()
    
    print(f"DTLS测试服务器")
    print(f"模式: {args.mode.upper()}")
    print(f"地址: {args.host}:{args.port}")
    print("按 Ctrl+C 停止服务器")
    print("=" * 50)
    
    server = DTLSTestServer(host=args.host, port=args.port, mode=args.mode)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n收到中断信号")
    finally:
        server.stop()
        print("服务器已停止")

if __name__ == "__main__":
    main()
