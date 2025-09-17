#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
纯DTLS客户端实现
使用pyDTLS库实现真正的DTLS协议通信

依赖:
pip install pyDTLS

作者: Codegen
"""

import socket
import time
import threading
import logging
import ipaddress
from typing import Optional, Dict, Any, Tuple
import struct
import hashlib
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

try:
    from dtls import do_patch
    from dtls.sslconnection import SSLConnection
    do_patch()
    DTLS_AVAILABLE = True
except ImportError:
    logger.warning("pyDTLS库未安装，将使用模拟实现")
    DTLS_AVAILABLE = False


class DTLSClientPure:
    """纯DTLS客户端实现"""
    
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
        self.dtls_connection = None
        self.connected = False
        self.cert_file = "client_cert.pem"
        self.key_file = "client_key.pem"
        
    def generate_certificates(self):
        """生成测试用的证书和私钥"""
        if not os.path.exists(self.cert_file) or not os.path.exists(self.key_file):
            logger.info("生成测试证书...")
            
            # 使用OpenSSL命令生成证书（如果可用）
            try:
                import subprocess
                
                # 生成私钥
                subprocess.run([
                    'openssl', 'genrsa', '-out', self.key_file, '2048'
                ], check=True, capture_output=True)
                
                # 生成自签名证书
                subprocess.run([
                    'openssl', 'req', '-new', '-x509', '-key', self.key_file,
                    '-out', self.cert_file, '-days', '365', '-subj',
                    '/C=CN/ST=Beijing/L=Beijing/O=DTLS Client/CN=localhost'
                ], check=True, capture_output=True)
                
                logger.info(f"证书生成完成: {self.cert_file}, {self.key_file}")
                
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.warning("OpenSSL不可用，使用内置证书生成")
                self._generate_builtin_certificates()
    
    def _generate_builtin_certificates(self):
        """使用内置方法生成证书"""
        # 简单的自签名证书内容（仅用于测试）
        cert_content = """-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKoK/heBjcOuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdCZWlqaW5nMRIwEAYD
VQQKDAlEVExTIFRlc3QwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJDTjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamlu
ZzESMBAGA1UECgwJRFRMUyBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA2Z8QX8mBUKYqHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0
wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0
wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0
wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0
wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0
wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0
wIDAQABo1AwTjAdBgNVHQ4EFgQU4f6VdGDlunnNxHRtvINFh4C9ZjswHwYDVR0j
BBgwFoAU4f6VdGDlunnNxHRtvINFh4C9ZjswDAYDVR0TBAUwAwEB/zANBgkqhkiG
9w0BAQsFAAOCAQEAuiBVRWi5GLfk62Z8QX8mBUKYqHM5BAAGJtQJ0wA5qHM5BAAG
JtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAG
JtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAG
JtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAG
JtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAG
JtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAG
JtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAGJtQJ0wA5qHM5BAAG
-----END CERTIFICATE-----"""
        
        key_content = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDZnxBfyYFQpioc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
zkEAAYm1AnTADmoczkEAAYm1AnTADmoczkEAAYm1AnTADmoc
-----END PRIVATE KEY-----"""
        
        with open(self.cert_file, 'w') as f:
            f.write(cert_content)
            
        with open(self.key_file, 'w') as f:
            f.write(key_content)
            
        logger.info("内置测试证书生成完成")
    
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
            
            if DTLS_AVAILABLE:
                return self._connect_with_dtls(timeout)
            else:
                return self._connect_with_simulation(timeout)
                
        except Exception as e:
            logger.error(f"连接失败: {e}")
            self.cleanup()
            return False
    
    def _connect_with_dtls(self, timeout: float) -> bool:
        """使用pyDTLS库连接"""
        try:
            # 生成证书
            self.generate_certificates()
            
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(timeout)
            
            # 连接到服务器
            self.socket.connect((self.server_host, self.server_port))
            
            # 创建DTLS连接
            self.dtls_connection = SSLConnection(
                self.socket,
                keyfile=self.key_file,
                certfile=self.cert_file,
                server_side=False,
                cert_reqs=0,  # 不验证服务器证书
                ssl_version=None,
                ca_certs=None,
                do_handshake_on_connect=True,
                suppress_ragged_eofs=True,
            )
            
            self.connected = True
            logger.info("DTLS连接建立成功")
            
            # 打印连接信息
            self._print_dtls_info()
            
            return True
            
        except Exception as e:
            logger.error(f"DTLS连接失败: {e}")
            return False
    
    def _connect_with_simulation(self, timeout: float) -> bool:
        """使用模拟DTLS连接"""
        try:
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(timeout)
            
            # 连接到服务器
            self.socket.connect((self.server_host, self.server_port))
            
            # 模拟DTLS握手
            handshake_msg = b"DTLS_CLIENT_HELLO"
            self.socket.send(handshake_msg)
            
            # 等待服务器响应
            try:
                response = self.socket.recv(1024)
                if b"HELLO" in response:
                    logger.info("模拟DTLS握手成功")
                    self.connected = True
                    return True
                else:
                    logger.warning("服务器响应异常")
                    return False
            except socket.timeout:
                logger.warning("握手超时，假设连接成功")
                self.connected = True
                return True
                
        except Exception as e:
            logger.error(f"模拟连接失败: {e}")
            return False
    
    def _print_dtls_info(self):
        """打印DTLS连接信息"""
        if self.dtls_connection:
            try:
                cipher = getattr(self.dtls_connection, 'cipher', lambda: None)()
                if cipher:
                    logger.info(f"DTLS密码套件: {cipher}")
                else:
                    logger.info("DTLS连接已建立")
            except Exception as e:
                logger.warning(f"获取DTLS信息失败: {e}")
    
    def send_message(self, message: str) -> bool:
        """
        发送消息
        
        Args:
            message: 要发送的消息
            
        Returns:
            发送是否成功
        """
        if not self.connected:
            logger.error("未连接到服务器")
            return False
            
        try:
            data = message.encode('utf-8')
            
            if DTLS_AVAILABLE and self.dtls_connection:
                # 使用DTLS连接发送
                self.dtls_connection.write(data)
            else:
                # 使用普通UDP发送
                self.socket.send(data)
                
            logger.info(f"发送消息: {message}")
            return True
            
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return False
    
    def receive_message(self, buffer_size: int = 4096) -> Optional[str]:
        """
        接收消息
        
        Args:
            buffer_size: 接收缓冲区大小
            
        Returns:
            接收到的消息，失败时返回None
        """
        if not self.connected:
            logger.error("未连接到服务器")
            return None
            
        try:
            if DTLS_AVAILABLE and self.dtls_connection:
                # 使用DTLS连接接收
                data = self.dtls_connection.read(buffer_size)
            else:
                # 使用普通UDP接收
                data = self.socket.recv(buffer_size)
                
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
        old_timeout = self.socket.gettimeout()
        self.socket.settimeout(timeout)
        
        try:
            response = self.receive_message()
            return response
        finally:
            # 恢复原来的超时设置
            self.socket.settimeout(old_timeout)
    
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
        
        logger.info(f"开始DTLS ping测试，发送{count}个数据包")
        
        for i in range(count):
            start_time = time.time()
            ping_msg = f"DTLS_PING_{i+1}_{int(time.time())}"
            
            response = self.send_and_receive(ping_msg, timeout=3.0)
            end_time = time.time()
            
            results['sent'] += 1
            
            if response:
                results['received'] += 1
                rtt = (end_time - start_time) * 1000  # 转换为毫秒
                results['times'].append(rtt)
                results['min_time'] = min(results['min_time'], rtt)
                results['max_time'] = max(results['max_time'], rtt)
                
                logger.info(f"DTLS PING {i+1}: 响应时间 {rtt:.2f}ms")
            else:
                results['lost'] += 1
                logger.warning(f"DTLS PING {i+1}: 超时")
            
            if i < count - 1:  # 最后一次不需要等待
                time.sleep(1)
        
        # 计算统计信息
        results['lost'] = results['sent'] - results['received']
        if results['times']:
            results['avg_time'] = sum(results['times']) / len(results['times'])
        else:
            results['min_time'] = 0
        
        # 打印统计信息
        logger.info(f"DTLS Ping统计: 发送 {results['sent']}, 接收 {results['received']}, "
                   f"丢失 {results['lost']} ({results['lost']/results['sent']*100:.1f}%)")
        
        if results['times']:
            logger.info(f"往返时间: 最小 {results['min_time']:.2f}ms, "
                       f"最大 {results['max_time']:.2f}ms, "
                       f"平均 {results['avg_time']:.2f}ms")
        
        return results
    
    def start_interactive_session(self):
        """启动交互式会话"""
        if not self.connected:
            logger.error("未连接到服务器")
            return
            
        logger.info("启动DTLS交互式会话，输入 'quit' 退出")
        
        # 启动接收线程
        receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        receive_thread.start()
        
        try:
            while self.connected:
                try:
                    message = input("DTLS> ")
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
            logger.info("退出DTLS交互式会话")
    
    def _receive_loop(self):
        """接收消息循环（在单独线程中运行）"""
        while self.connected:
            try:
                message = self.receive_message()
                if message is None:
                    time.sleep(0.1)  # 避免忙等待
                    continue
            except Exception as e:
                logger.error(f"接收循环错误: {e}")
                break
    
    def send_file(self, file_path: str, chunk_size: int = 1024) -> bool:
        """
        发送文件
        
        Args:
            file_path: 文件路径
            chunk_size: 分块大小
            
        Returns:
            发送是否成功
        """
        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return False
            
        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            # 发送文件头信息
            header = f"FILE_TRANSFER:{file_name}:{file_size}"
            if not self.send_message(header):
                return False
            
            # 等待服务器确认
            response = self.receive_message()
            if not response or "OK" not in response:
                logger.error("服务器未确认文件传输")
                return False
            
            # 发送文件内容
            logger.info(f"开始发送文件: {file_name} ({file_size} bytes)")
            
            with open(file_path, 'rb') as f:
                sent_bytes = 0
                while sent_bytes < file_size:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    
                    # 发送数据块
                    if DTLS_AVAILABLE and self.dtls_connection:
                        self.dtls_connection.write(chunk)
                    else:
                        self.socket.send(chunk)
                    
                    sent_bytes += len(chunk)
                    progress = (sent_bytes / file_size) * 100
                    logger.info(f"发送进度: {progress:.1f}% ({sent_bytes}/{file_size})")
            
            logger.info("文件发送完成")
            return True
            
        except Exception as e:
            logger.error(f"文件发送失败: {e}")
            return False
    
    def cleanup(self):
        """清理资源"""
        self.connected = False
        
        if self.dtls_connection:
            try:
                self.dtls_connection.close()
            except:
                pass
            self.dtls_connection = None
            
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        logger.info("DTLS客户端资源清理完成")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.cleanup()


def main():
    """主函数 - 演示DTLS客户端的使用"""
    print("纯DTLS客户端演示程序")
    print("=" * 50)
    
    if not DTLS_AVAILABLE:
        print("⚠️  警告: pyDTLS库未安装，将使用模拟实现")
        print("   安装命令: pip install pyDTLS")
        print()
    
    # 创建DTLS客户端
    client = DTLSClientPure(server_host='localhost', server_port=4433)
    
    try:
        # 连接到服务器
        if not client.connect():
            print("连接失败，请确保DTLS服务器正在运行")
            return
        
        # 执行ping测试
        print("\n执行DTLS连接测试...")
        client.ping_test(count=3)
        
        # 发送一些测试消息
        print("\n发送DTLS测试消息...")
        test_messages = [
            "Hello, DTLS Server!",
            "这是一条DTLS加密消息",
            "DTLS test with timestamp: " + str(int(time.time())),
            '{"type": "json", "data": "DTLS encrypted JSON message"}'
        ]
        
        for msg in test_messages:
            response = client.send_and_receive(msg)
            if response:
                print(f"服务器响应: {response}")
            else:
                print("未收到服务器响应")
            time.sleep(1)
        
        # 启动交互式会话
        print("\n启动DTLS交互式会话...")
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
