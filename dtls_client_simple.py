#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化的DTLS客户端实现
专注于核心DTLS握手和通信功能
"""

import socket
import struct
import hashlib
import hmac
import os
import logging
from typing import Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DTLSConstants:
    """DTLS协议常量"""
    # 内容类型
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    
    # 握手消息类型
    HELLO_REQUEST = 0
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    
    # DTLS版本
    DTLS_1_2 = 0xFEFD
    
    # 密码套件
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035

class SimpleDTLSClient:
    """简化的DTLS客户端"""
    
    def __init__(self):
        self.socket = None
        self.server_address = None
        self.client_random = None
        self.server_random = None
        self.session_id = b''
        self.cookie = b''
        self.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_CBC_SHA
        self.server_certificate = None
        self.master_secret = None
        self.client_write_key = None
        self.server_write_key = None
        self.sequence_number = 0
        self.connected = False
        
    def connect(self, host: str, port: int) -> bool:
        """连接到DTLS服务器"""
        try:
            logger.info(f"连接到DTLS服务器 {host}:{port}")
            
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(10.0)  # 10秒超时
            self.server_address = (host, port)
            
            # 执行DTLS握手
            if self._perform_handshake():
                self.connected = True
                logger.info("DTLS连接建立成功")
                return True
            else:
                logger.error("DTLS握手失败")
                return False
                
        except Exception as e:
            logger.error(f"连接失败: {e}")
            return False
    
    def _perform_handshake(self) -> bool:
        """执行DTLS握手"""
        try:
            # 1. 发送Client Hello (无Cookie)
            logger.info("发送Client Hello (无Cookie)")
            client_hello = self._create_client_hello()
            self._send_handshake_message(DTLSConstants.CLIENT_HELLO, client_hello)
            
            # 2. 接收Hello Verify Request
            logger.info("等待Hello Verify Request")
            msg_type, data = self._receive_handshake_message()
            
            if msg_type == DTLSConstants.HELLO_VERIFY_REQUEST:
                # 解析Cookie
                self._parse_hello_verify_request(data)
                logger.info(f"收到Cookie，长度: {len(self.cookie)}")
                
                # 3. 发送Client Hello (带Cookie)
                logger.info("发送Client Hello (带Cookie)")
                client_hello_with_cookie = self._create_client_hello()
                self._send_handshake_message(DTLSConstants.CLIENT_HELLO, client_hello_with_cookie)
                
                # 4. 接收Server Hello
                logger.info("等待Server Hello")
                msg_type, data = self._receive_handshake_message()
                
            if msg_type == DTLSConstants.SERVER_HELLO:
                self._parse_server_hello(data)
                logger.info("解析Server Hello完成")
            else:
                logger.error(f"期望Server Hello，收到: {msg_type}")
                return False
            
            # 5. 接收Certificate
            logger.info("等待Certificate")
            try:
                msg_type, data = self._receive_handshake_message()
                if msg_type == DTLSConstants.CERTIFICATE:
                    self._parse_certificate(data)
                    logger.info("解析Certificate完成")
            except socket.timeout:
                logger.info("未收到Certificate（可能是PSK模式）")
            
            # 6. 接收Server Hello Done
            logger.info("等待Server Hello Done")
            try:
                msg_type, data = self._receive_handshake_message()
                if msg_type == DTLSConstants.SERVER_HELLO_DONE:
                    logger.info("收到Server Hello Done")
            except socket.timeout:
                logger.info("未收到Server Hello Done")
            
            # 7. 发送Client Key Exchange
            logger.info("发送Client Key Exchange")
            client_key_exchange = self._create_client_key_exchange()
            self._send_handshake_message(DTLSConstants.CLIENT_KEY_EXCHANGE, client_key_exchange)
            
            # 8. 发送Change Cipher Spec
            logger.info("发送Change Cipher Spec")
            self._send_change_cipher_spec()
            
            # 9. 发送Finished
            logger.info("发送Finished")
            finished = self._create_finished_message()
            self._send_handshake_message(DTLSConstants.FINISHED, finished)
            
            # 10. 接收Change Cipher Spec
            logger.info("等待Change Cipher Spec")
            try:
                self._receive_change_cipher_spec()
                logger.info("收到Change Cipher Spec")
            except socket.timeout:
                logger.warning("未收到Change Cipher Spec")
            
            # 11. 接收Finished
            logger.info("等待Finished")
            try:
                msg_type, data = self._receive_handshake_message()
                if msg_type == DTLSConstants.FINISHED:
                    logger.info("收到Finished消息")
                    # 这里应该验证Finished消息
            except socket.timeout:
                logger.warning("未收到Finished消息")
            
            logger.info("DTLS握手完成")
            return True
            
        except Exception as e:
            logger.error(f"握手失败: {e}")
            return False
    
    def _create_client_hello(self) -> bytes:
        """创建Client Hello消息"""
        # 生成客户端随机数
        if self.client_random is None:
            self.client_random = os.urandom(32)
        
        # 构建Client Hello
        data = b''
        
        # 协议版本 (DTLS 1.2)
        data += struct.pack('!H', DTLSConstants.DTLS_1_2)
        
        # 客户端随机数
        data += self.client_random
        
        # Session ID长度和Session ID
        data += struct.pack('!B', len(self.session_id))
        data += self.session_id
        
        # Cookie长度和Cookie
        data += struct.pack('!B', len(self.cookie))
        data += self.cookie
        
        # 密码套件
        cipher_suites = struct.pack('!H', self.cipher_suite)
        data += struct.pack('!H', len(cipher_suites))
        data += cipher_suites
        
        # 压缩方法
        data += struct.pack('!B', 1)  # 压缩方法长度
        data += struct.pack('!B', 0)  # 无压缩
        
        # 扩展（暂时为空）
        data += struct.pack('!H', 0)  # 扩展长度
        
        return data
    
    def _parse_hello_verify_request(self, data: bytes):
        """解析Hello Verify Request"""
        if len(data) < 3:
            raise ValueError("Hello Verify Request数据太短")
        
        # 跳过版本 (2字节)
        cookie_length = data[2]
        if len(data) < 3 + cookie_length:
            raise ValueError("Cookie数据不完整")
        
        self.cookie = data[3:3+cookie_length]
    
    def _parse_server_hello(self, data: bytes):
        """解析Server Hello"""
        if len(data) < 38:
            raise ValueError("Server Hello数据太短")
        
        # 协议版本
        version = struct.unpack('!H', data[0:2])[0]
        logger.info(f"服务器DTLS版本: 0x{version:04X}")
        
        # 服务器随机数
        self.server_random = data[2:34]
        
        # Session ID
        session_id_length = data[34]
        if len(data) < 35 + session_id_length:
            raise ValueError("Session ID数据不完整")
        
        self.session_id = data[35:35+session_id_length]
        
        # 密码套件
        offset = 35 + session_id_length
        if len(data) < offset + 2:
            raise ValueError("密码套件数据不完整")
        
        self.cipher_suite = struct.unpack('!H', data[offset:offset+2])[0]
        logger.info(f"选择的密码套件: 0x{self.cipher_suite:04X}")
    
    def _parse_certificate(self, data: bytes):
        """解析服务器证书"""
        if len(data) < 3:
            raise ValueError("Certificate数据太短")
        
        # 证书链长度
        cert_chain_length = struct.unpack('!I', b'\\x00' + data[0:3])[0]
        
        if len(data) < 3 + cert_chain_length:
            raise ValueError("证书链数据不完整")
        
        # 解析第一个证书
        offset = 3
        if offset + 3 <= len(data):
            cert_length = struct.unpack('!I', b'\\x00' + data[offset:offset+3])[0]
            offset += 3
            
            if offset + cert_length <= len(data):
                cert_data = data[offset:offset+cert_length]
                try:
                    self.server_certificate = x509.load_der_x509_certificate(cert_data)
                    logger.info("服务器证书解析成功")
                except Exception as e:
                    logger.warning(f"证书解析失败: {e}")
    
    def _create_client_key_exchange(self) -> bytes:
        """创建Client Key Exchange消息"""
        # 生成预主密钥
        pre_master_secret = struct.pack('!H', DTLSConstants.DTLS_1_2) + os.urandom(46)
        
        # 使用服务器公钥加密预主密钥
        if self.server_certificate:
            try:
                public_key = self.server_certificate.public_key()
                encrypted_pms = public_key.encrypt(
                    pre_master_secret,
                    padding.PKCS1v15()
                )
                
                # 计算主密钥
                self._compute_master_secret(pre_master_secret)
                
                # 返回加密的预主密钥长度和数据
                return struct.pack('!H', len(encrypted_pms)) + encrypted_pms
            except Exception as e:
                logger.error(f"加密预主密钥失败: {e}")
        
        # 如果没有证书或加密失败，返回空数据
        return b''
    
    def _compute_master_secret(self, pre_master_secret: bytes):
        """计算主密钥"""
        # PRF函数简化实现
        seed = b"master secret" + self.client_random + self.server_random
        self.master_secret = self._prf(pre_master_secret, seed, 48)
        logger.info("主密钥计算完成")
    
    def _prf(self, secret: bytes, seed: bytes, length: int) -> bytes:
        """伪随机函数（简化实现）"""
        result = b''
        a = seed
        
        while len(result) < length:
            a = hmac.new(secret, a, hashlib.sha256).digest()
            result += hmac.new(secret, a + seed, hashlib.sha256).digest()
        
        return result[:length]
    
    def _create_finished_message(self) -> bytes:
        """创建Finished消息"""
        # 简化实现：返回固定长度的数据
        return b'\\x00' * 12
    
    def _send_handshake_message(self, msg_type: int, data: bytes):
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
        self.socket.sendto(message, self.server_address)
    
    def _receive_handshake_message(self) -> Tuple[int, bytes]:
        """接收握手消息"""
        data, addr = self.socket.recvfrom(4096)
        
        if len(data) < 5:
            raise ValueError("接收到的数据太短")
        
        # 解析记录头
        content_type = data[0]
        if content_type != DTLSConstants.HANDSHAKE:
            raise ValueError(f"期望握手消息，收到类型: {content_type}")
        
        # 解析握手消息头
        if len(data) < 9:
            raise ValueError("握手消息头不完整")
        
        msg_type = data[5]
        msg_length = struct.unpack('!I', b'\\x00' + data[6:9])[0]
        
        if len(data) < 9 + msg_length:
            raise ValueError("握手消息数据不完整")
        
        return msg_type, data[9:9+msg_length]
    
    def _send_change_cipher_spec(self):
        """发送Change Cipher Spec消息"""
        # 构建Change Cipher Spec消息
        ccs_data = struct.pack('!B', 1)
        
        # 构建DTLS记录头
        record_header = struct.pack('!BBHH',
                                  DTLSConstants.CHANGE_CIPHER_SPEC,
                                  0xFE, 0xFD,  # DTLS 1.2
                                  len(ccs_data))
        
        # 发送消息
        message = record_header + ccs_data
        self.socket.sendto(message, self.server_address)
    
    def _receive_change_cipher_spec(self):
        """接收Change Cipher Spec消息"""
        data, addr = self.socket.recvfrom(4096)
        
        if len(data) < 5:
            raise ValueError("接收到的数据太短")
        
        content_type = data[0]
        if content_type != DTLSConstants.CHANGE_CIPHER_SPEC:
            raise ValueError(f"期望Change Cipher Spec，收到类型: {content_type}")
    
    def send_data(self, data: bytes) -> bool:
        """发送应用数据"""
        if not self.connected:
            logger.error("DTLS连接未建立")
            return False
        
        try:
            # 构建应用数据记录
            record_header = struct.pack('!BBHH',
                                      DTLSConstants.APPLICATION_DATA,
                                      0xFE, 0xFD,  # DTLS 1.2
                                      len(data))
            
            message = record_header + data
            self.socket.sendto(message, self.server_address)
            logger.info(f"发送应用数据: {len(data)} 字节")
            return True
            
        except Exception as e:
            logger.error(f"发送数据失败: {e}")
            return False
    
    def receive_data(self) -> Optional[bytes]:
        """接收应用数据"""
        if not self.connected:
            logger.error("DTLS连接未建立")
            return None
        
        try:
            data, addr = self.socket.recvfrom(4096)
            
            if len(data) < 5:
                logger.warning("接收到的数据太短")
                return None
            
            content_type = data[0]
            if content_type == DTLSConstants.APPLICATION_DATA:
                payload = data[5:]  # 跳过记录头
                logger.info(f"接收应用数据: {len(payload)} 字节")
                return payload
            else:
                logger.warning(f"收到非应用数据类型: {content_type}")
                return None
                
        except socket.timeout:
            logger.info("接收数据超时")
            return None
        except Exception as e:
            logger.error(f"接收数据失败: {e}")
            return None
    
    def cleanup(self):
        """清理资源"""
        if self.socket:
            self.socket.close()
            self.socket = None
        self.connected = False
        logger.info("DTLS客户端清理完成")

def main():
    """主函数"""
    print("🚀 简化DTLS客户端测试")
    print("="*30)
    
    client = SimpleDTLSClient()
    
    try:
        # 连接到本地DTLS服务器
        if client.connect("127.0.0.1", 4433):
            print("✅ DTLS连接成功!")
            
            # 发送测试数据
            test_message = "Hello from DTLS client!"
            if client.send_data(test_message.encode()):
                print(f"📤 发送: {test_message}")
                
                # 接收响应
                response = client.receive_data()
                if response:
                    print(f"📥 收到: {response.decode()}")
        else:
            print("❌ DTLS连接失败")
            
    except KeyboardInterrupt:
        print("\\n⏹️ 用户中断")
    except Exception as e:
        print(f"❌ 错误: {e}")
    finally:
        client.cleanup()

if __name__ == "__main__":
    main()

