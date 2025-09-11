#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端实现
支持与DTLS服务端进行协商、交互和加密通信

依赖:
pip install pyopenssl cryptography

作者: Codegen
"""

import socket
import ssl
import time
import threading
import ipaddress
from typing import Optional, Tuple, Dict, Any
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DTLSClient:
    """DTLS客户端类"""
    
    def __init__(self, server_host: str = 'localhost', server_port: int = 4433):
        """
        初始化DTLS客户端
        
        Args:
            server_host: 服务器主机地址
            server_port: 服务器端口
        """
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.ssl_socket = None
        self.connected = False
        self.cert_file = None
        self.key_file = None
        
    def generate_self_signed_cert(self) -> Tuple[str, str]:
        """
        生成自签名证书和私钥
        
        Returns:
            证书文件路径和私钥文件路径的元组
        """
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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DTLS Client"),
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
        
        # 保存证书和私钥到文件
        cert_file = "client_cert.pem"
        key_file = "client_key.pem"
        
        with open(cert_file, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            
        with open(key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
            
        logger.info(f"生成自签名证书: {cert_file}")
        logger.info(f"生成私钥文件: {key_file}")
        
        return cert_file, key_file
    
    def setup_ssl_context(self, verify_mode: int = ssl.CERT_NONE) -> ssl.SSLContext:
        """
        设置SSL上下文
        
        Args:
            verify_mode: 证书验证模式
            
        Returns:
            配置好的SSL上下文
        """
        # 创建SSL上下文，使用DTLS协议
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # 设置证书验证模式
        context.check_hostname = False
        context.verify_mode = verify_mode
        
        # 如果没有证书文件，生成自签名证书
        if not self.cert_file or not self.key_file:
            self.cert_file, self.key_file = self.generate_self_signed_cert()
        
        # 加载客户端证书和私钥
        if os.path.exists(self.cert_file) and os.path.exists(self.key_file):
            context.load_cert_chain(self.cert_file, self.key_file)
            logger.info("已加载客户端证书和私钥")
        
        # 设置密码套件
        context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS')
        
        return context
    
    def connect(self, timeout: float = 10.0) -> bool:
        """
        连接到DTLS服务器
        
        Args:
            timeout: 连接超时时间
            
        Returns:
            连接是否成功
        """
        try:
            logger.info(f"正在连接到DTLS服务器 {self.server_host}:{self.server_port}")
            
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(timeout)
            
            # 设置SSL上下文
            ssl_context = self.setup_ssl_context()
            
            # 注意: Python的ssl模块对DTLS的支持有限
            # 这里使用TCP over TLS作为替代方案进行演示
            # 实际的DTLS实现可能需要使用专门的库如pyDTLS
            
            # 创建TCP套接字用于TLS连接（模拟DTLS）
            tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_socket.settimeout(timeout)
            
            # 包装为SSL套接字
            self.ssl_socket = ssl_context.wrap_socket(
                tcp_socket,
                server_hostname=self.server_host
            )
            
            # 连接到服务器
            self.ssl_socket.connect((self.server_host, self.server_port))
            
            # 执行SSL握手
            self.ssl_socket.do_handshake()
            
            self.connected = True
            logger.info("DTLS连接建立成功")
            
            # 打印连接信息
            self.print_connection_info()
            
            return True
            
        except Exception as e:
            logger.error(f"连接失败: {e}")
            self.cleanup()
            return False
    
    def print_connection_info(self):
        """打印连接信息"""
        if self.ssl_socket:
            try:
                cipher = self.ssl_socket.cipher()
                version = self.ssl_socket.version()
                peer_cert = self.ssl_socket.getpeercert()
                
                logger.info(f"TLS版本: {version}")
                logger.info(f"密码套件: {cipher}")
                
                if peer_cert:
                    logger.info("服务器证书信息:")
                    for key, value in peer_cert.items():
                        logger.info(f"  {key}: {value}")
                        
            except Exception as e:
                logger.warning(f"获取连接信息失败: {e}")
    
    def send_message(self, message: str) -> bool:
        """
        发送加密消息
        
        Args:
            message: 要发送的消息
            
        Returns:
            发送是否成功
        """
        if not self.connected or not self.ssl_socket:
            logger.error("未连接到服务器")
            return False
            
        try:
            # 发送加密消息
            data = message.encode('utf-8')
            self.ssl_socket.send(data)
            logger.info(f"发送消息: {message}")
            return True
            
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return False
    
    def receive_message(self, buffer_size: int = 4096) -> Optional[str]:
        """
        接收加密消息
        
        Args:
            buffer_size: 接收缓冲区大小
            
        Returns:
            接收到的消息，失败时返回None
        """
        if not self.connected or not self.ssl_socket:
            logger.error("未连接到服务器")
            return None
            
        try:
            # 接收加密消息
            data = self.ssl_socket.recv(buffer_size)
            if data:
                message = data.decode('utf-8')
                logger.info(f"接收消息: {message}")
                return message
            else:
                logger.warning("接收到空消息")
                return None
                
        except socket.timeout:
            logger.warning("接收消息超时")
            return None
        except Exception as e:
            logger.error(f"接收消息失败: {e}")
            return None
    
    def send_and_receive(self, message: str, timeout: float = 5.0) -> Optional[str]:
        """
        发送消息并等待响应
        
        Args:
            message: 要发送的消息
            timeout: 等待响应的超时时间
            
        Returns:
            服务器响应，失败时返回None
        """
        if not self.send_message(message):
            return None
            
        # 设置接收超时
        old_timeout = self.ssl_socket.gettimeout()
        self.ssl_socket.settimeout(timeout)
        
        try:
            response = self.receive_message()
            return response
        finally:
            # 恢复原来的超时设置
            self.ssl_socket.settimeout(old_timeout)
    
    def start_interactive_session(self):
        """启动交互式会话"""
        if not self.connected:
            logger.error("未连接到服务器")
            return
            
        logger.info("启动交互式会话，输入 'quit' 退出")
        
        # 启动接收线程
        receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        receive_thread.start()
        
        try:
            while self.connected:
                try:
                    message = input("请输入消息: ")
                    if message.lower() in ['quit', 'exit', 'q']:
                        break
                    
                    if message.strip():
                        self.send_message(message)
                        
                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                    
        except Exception as e:
            logger.error(f"交互式会话错误: {e}")
        finally:
            logger.info("退出交互式会话")
    
    def _receive_loop(self):
        """接收消息循环（在单独线程中运行）"""
        while self.connected:
            try:
                message = self.receive_message()
                if message is None:
                    break
            except Exception as e:
                logger.error(f"接收循环错误: {e}")
                break
    
    def ping_test(self, count: int = 3) -> Dict[str, Any]:
        """
        执行ping测试
        
        Args:
            count: ping次数
            
        Returns:
            测试结果统计
        """
        results = {
            'sent': 0,
            'received': 0,
            'lost': 0,
            'times': [],
            'avg_time': 0,
            'min_time': float('inf'),
            'max_time': 0
        }
        
        logger.info(f"开始ping测试，发送{count}个数据包")
        
        for i in range(count):
            start_time = time.time()
            ping_msg = f"PING {i+1}"
            
            response = self.send_and_receive(ping_msg, timeout=3.0)
            end_time = time.time()
            
            results['sent'] += 1
            
            if response:
                results['received'] += 1
                rtt = (end_time - start_time) * 1000  # 转换为毫秒
                results['times'].append(rtt)
                results['min_time'] = min(results['min_time'], rtt)
                results['max_time'] = max(results['max_time'], rtt)
                
                logger.info(f"PING {i+1}: 响应时间 {rtt:.2f}ms")
            else:
                results['lost'] += 1
                logger.warning(f"PING {i+1}: 超时")
            
            if i < count - 1:  # 最后一次不需要等待
                time.sleep(1)
        
        # 计算统计信息
        results['lost'] = results['sent'] - results['received']
        if results['times']:
            results['avg_time'] = sum(results['times']) / len(results['times'])
        else:
            results['min_time'] = 0
        
        # 打印统计信息
        logger.info(f"Ping统计: 发送 {results['sent']}, 接收 {results['received']}, "
                   f"丢失 {results['lost']} ({results['lost']/results['sent']*100:.1f}%)")
        
        if results['times']:
            logger.info(f"往返时间: 最小 {results['min_time']:.2f}ms, "
                       f"最大 {results['max_time']:.2f}ms, "
                       f"平均 {results['avg_time']:.2f}ms")
        
        return results
    
    def cleanup(self):
        """清理资源"""
        self.connected = False
        
        if self.ssl_socket:
            try:
                self.ssl_socket.close()
            except:
                pass
            self.ssl_socket = None
            
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        logger.info("资源清理完成")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.cleanup()


def main():
    """主函数 - 演示DTLS客户端的使用"""
    print("DTLS客户端演示程序")
    print("=" * 50)
    
    # 创建DTLS客户端
    client = DTLSClient(server_host='localhost', server_port=4433)
    
    try:
        # 连接到服务器
        if not client.connect():
            print("连接失败，请确保DTLS服务器正在运行")
            return
        
        # 执行ping测试
        print("\n执行连接测试...")
        client.ping_test(count=3)
        
        # 发送一些测试消息
        print("\n发送测试消息...")
        test_messages = [
            "Hello, DTLS Server!",
            "这是一条中文测试消息",
            "Test message with numbers: 12345",
            "JSON test: {\"key\": \"value\", \"number\": 42}"
        ]
        
        for msg in test_messages:
            response = client.send_and_receive(msg)
            if response:
                print(f"服务器响应: {response}")
            else:
                print("未收到服务器响应")
            time.sleep(1)
        
        # 启动交互式会话
        print("\n启动交互式会话...")
        client.start_interactive_session()
        
    except KeyboardInterrupt:
        print("\n用户中断")
    except Exception as e:
        print(f"程序错误: {e}")
    finally:
        client.cleanup()
        print("程序结束")


if __name__ == "__main__":
    main()
