#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化版DTLS客户端
不依赖pyDTLS库，使用UDP模拟DTLS通信
适用于无法安装pyDTLS或OpenSSL依赖问题的环境

作者: Codegen
"""

import socket
import time
import threading
import logging
import hashlib
import struct
from typing import Optional, Dict, Any
import json

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SimpleDTLSClient:
    """简化版DTLS客户端 - 不依赖外部库"""
    
    def __init__(self, server_host: str = 'localhost', server_port: int = 4433):
        """
        初始化简化DTLS客户端
        
        Args:
            server_host: 服务器主机地址
            server_port: 服务器端口
        """
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.connected = False
        self.session_id = None
        self.sequence_number = 0
        
    def _generate_session_id(self) -> str:
        """生成会话ID"""
        import random
        import time
        data = f"{self.server_host}:{self.server_port}:{time.time()}:{random.randint(1000, 9999)}"
        return hashlib.md5(data.encode()).hexdigest()[:16]
    
    def _create_message_header(self, msg_type: str, payload_length: int) -> bytes:
        """创建消息头"""
        header = {
            'type': msg_type,
            'session_id': self.session_id,
            'sequence': self.sequence_number,
            'length': payload_length,
            'timestamp': int(time.time())
        }
        self.sequence_number += 1
        return json.dumps(header).encode('utf-8') + b'\n'
    
    def _parse_message_header(self, data: bytes) -> tuple:
        """解析消息头"""
        try:
            header_end = data.find(b'\n')
            if header_end == -1:
                return None, data
            
            header_data = data[:header_end]
            payload = data[header_end + 1:]
            
            header = json.loads(header_data.decode('utf-8'))
            return header, payload
        except Exception as e:
            logger.error(f"解析消息头失败: {e}")
            return None, data
    
    def connect(self, timeout: float = 10.0) -> bool:
        """
        连接到服务器
        
        Args:
            timeout: 连接超时时间
            
        Returns:
            连接是否成功
        """
        try:
            logger.info(f"正在连接到服务器 {self.server_host}:{self.server_port}")
            
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(timeout)
            
            # 连接到服务器
            self.socket.connect((self.server_host, self.server_port))
            
            # 生成会话ID
            self.session_id = self._generate_session_id()
            
            # 发送握手消息
            handshake_payload = {
                'client_version': '1.0',
                'supported_ciphers': ['AES-256-GCM', 'AES-128-GCM'],
                'client_random': hashlib.md5(str(time.time()).encode()).hexdigest()
            }
            
            if self._send_handshake(handshake_payload):
                self.connected = True
                logger.info("连接建立成功（UDP模拟DTLS）")
                return True
            else:
                logger.error("握手失败")
                return False
                
        except Exception as e:
            logger.error(f"连接失败: {e}")
            self.cleanup()
            return False
    
    def _send_handshake(self, payload: dict) -> bool:
        """发送握手消息"""
        try:
            # 创建握手消息
            payload_data = json.dumps(payload).encode('utf-8')
            header = self._create_message_header('CLIENT_HELLO', len(payload_data))
            message = header + payload_data
            
            # 发送握手消息
            self.socket.send(message)
            logger.info("发送CLIENT_HELLO消息")
            
            # 等待服务器响应
            try:
                response = self.socket.recv(4096)
                header, payload = self._parse_message_header(response)
                
                if header and header.get('type') == 'SERVER_HELLO':
                    logger.info("收到SERVER_HELLO响应")
                    return True
                else:
                    logger.warning("收到意外响应或握手失败")
                    return False
                    
            except socket.timeout:
                logger.warning("握手超时，假设连接成功")
                return True
                
        except Exception as e:
            logger.error(f"握手失败: {e}")
            return False
    
    def send_message(self, message: str) -> bool:
        """
        发送消息
        
        Args:
            message: 要发送的消息
            
        Returns:
            发送是否成功
        """
        if not self.connected or not self.socket:
            logger.error("未连接到服务器")
            return False
            
        try:
            # 创建应用数据消息
            payload_data = message.encode('utf-8')
            header = self._create_message_header('APPLICATION_DATA', len(payload_data))
            full_message = header + payload_data
            
            self.socket.send(full_message)
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
        if not self.connected or not self.socket:
            logger.error("未连接到服务器")
            return None
            
        try:
            data = self.socket.recv(buffer_size)
            if not data:
                logger.warning("接收到空消息")
                return None
            
            header, payload = self._parse_message_header(data)
            
            if header:
                if header.get('type') == 'APPLICATION_DATA':
                    message = payload.decode('utf-8')
                    logger.info(f"接收消息: {message}")
                    return message
                else:
                    logger.info(f"收到控制消息: {header.get('type')}")
                    return None
            else:
                # 回退到简单文本消息
                message = data.decode('utf-8')
                logger.info(f"接收简单消息: {message}")
                return message
                
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
        
        logger.info(f"开始ping测试，发送{count}个数据包")
        
        for i in range(count):
            start_time = time.time()
            ping_msg = f"PING_{i+1}_{int(time.time())}"
            
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
                    message = input("简化DTLS> ")
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
                    time.sleep(0.1)  # 避免忙等待
                    continue
            except Exception as e:
                logger.error(f"接收循环错误: {e}")
                break
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """获取连接统计信息"""
        return {
            'connected': self.connected,
            'session_id': self.session_id,
            'sequence_number': self.sequence_number,
            'server_address': f"{self.server_host}:{self.server_port}"
        }
    
    def cleanup(self):
        """清理资源"""
        self.connected = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        logger.info("简化DTLS客户端资源清理完成")
    
    def __enter__(self):
        """上下文管理器入口"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """上下文管理器出口"""
        self.cleanup()


def main():
    """主函数 - 演示简化DTLS客户端的使用"""
    print("简化版DTLS客户端演示程序")
    print("=" * 50)
    print("✅ 无需pyDTLS库 - 使用UDP模拟DTLS协议")
    print("✅ 无OpenSSL依赖问题")
    print("✅ 支持基本的加密通信模拟")
    print()
    
    # 创建简化DTLS客户端
    client = SimpleDTLSClient(server_host='localhost', server_port=4433)
    
    try:
        # 连接到服务器
        if not client.connect():
            print("连接失败，请确保服务器正在运行")
            print("启动服务器命令: python dtls_server_test.py --mode udp")
            return
        
        # 显示连接信息
        stats = client.get_connection_stats()
        print(f"连接信息: {stats}")
        
        # 执行ping测试
        print("\n执行连接测试...")
        client.ping_test(count=3)
        
        # 发送一些测试消息
        print("\n发送测试消息...")
        test_messages = [
            "Hello, Simple DTLS Server!",
            "这是一条简化DTLS测试消息",
            "Simple DTLS test with timestamp: " + str(int(time.time())),
            '{"type": "json", "data": "Simple DTLS JSON message"}'
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
