#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS服务器实现 - 支持Hello Verify Request
实现正确的DTLS握手流程：
1. Client Hello (无Cookie) → Hello Verify Request (带Cookie)
2. Client Hello (带Cookie) → Server Hello + Certificate + ...

作者: Codegen
"""

import socket
import struct
import time
import hashlib
import hmac
import os
import logging
import secrets
from typing import Optional, Dict, Any, Tuple, List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import datetime
import ipaddress

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# DTLS常量定义
class DTLSConstants:
    # 内容类型
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    
    # DTLS版本
    DTLS_1_0 = 0xFEFF  # DTLS 1.0版本
    
    # 握手消息类型
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    HELLO_VERIFY_REQUEST = 3  # DTLS特有
    CERTIFICATE = 11
    SERVER_KEY_EXCHANGE = 12
    CERTIFICATE_REQUEST = 13
    SERVER_HELLO_DONE = 14
    CERTIFICATE_VERIFY = 15
    CLIENT_KEY_EXCHANGE = 16
    FINISHED = 20
    
    # 密码套件
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
    
    # 压缩方法
    COMPRESSION_NULL = 0
    
    # TLS扩展类型
    EXTENSION_SERVER_NAME = 0x0000  # SNI扩展
    
    # SNI名称类型
    SNI_NAME_TYPE_HOSTNAME = 0x00


class DTLSRecord:
    """DTLS记录层"""
    
    def __init__(self):
        self.sequence_number = 0
        self.epoch = 0
    
    def create_record(self, content_type: int, data: bytes) -> bytes:
        """创建DTLS记录"""
        version = DTLSConstants.DTLS_1_0
        epoch = struct.pack('!H', self.epoch)
        sequence_number = struct.pack('!Q', self.sequence_number)[2:]  # 6字节
        length = len(data)
        
        record = struct.pack('!BHH', content_type, version, self.epoch)
        record += sequence_number
        record += struct.pack('!H', length)
        record += data
        
        self.sequence_number += 1
        return record
    
    def parse_record(self, data: bytes) -> Tuple[int, bytes]:
        """解析DTLS记录"""
        if len(data) < 13:  # DTLS记录头最小长度
            raise ValueError("记录太短")
        
        content_type = data[0]
        version = struct.unpack('!H', data[1:3])[0]
        epoch = struct.unpack('!H', data[3:5])[0]
        sequence_number = struct.unpack('!Q', b'\x00\x00' + data[5:11])[0]
        length = struct.unpack('!H', data[11:13])[0]
        
        if len(data) < 13 + length:
            raise ValueError("记录数据不完整")
        
        payload = data[13:13+length]
        return content_type, payload


class DTLSHandshake:
    """DTLS握手层"""
    
    def __init__(self):
        self.message_seq = 0
    
    def create_handshake_message(self, msg_type: int, data: bytes) -> bytes:
        """创建握手消息"""
        length = len(data)
        message_seq = struct.pack('!H', self.message_seq)
        fragment_offset = struct.pack('!I', 0)[1:]  # 3字节
        fragment_length = struct.pack('!I', length)[1:]  # 3字节
        
        handshake_header = struct.pack('!B', msg_type)
        handshake_header += struct.pack('!I', length)[1:]  # 3字节长度
        handshake_header += message_seq
        handshake_header += fragment_offset
        handshake_header += fragment_length
        
        self.message_seq += 1
        return handshake_header + data
    
    def parse_handshake_message(self, data: bytes) -> Tuple[int, bytes]:
        """解析握手消息"""
        if len(data) < 12:  # 握手消息头最小长度
            raise ValueError("握手消息太短")
        
        msg_type = data[0]
        length = struct.unpack('!I', b'\x00' + data[1:4])[0]
        message_seq = struct.unpack('!H', data[4:6])[0]
        fragment_offset = struct.unpack('!I', b'\x00' + data[6:9])[0]
        fragment_length = struct.unpack('!I', b'\x00' + data[9:12])[0]
        
        if len(data) < 12 + fragment_length:
            raise ValueError("握手消息数据不完整")
        
        payload = data[12:12+fragment_length]
        return msg_type, payload


class DTLSServer:
    """DTLS服务器实现 - 支持Hello Verify Request"""
    
    def __init__(self, host: str = 'localhost', port: int = 4433):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # DTLS组件
        self.record_layer = DTLSRecord()
        self.handshake_layer = DTLSHandshake()
        
        # 服务器证书和私钥
        self.server_certificate = None
        self.server_private_key = None
        
        # 客户端状态管理 (IP:Port -> 状态)
        self.client_states = {}
        
        # Cookie密钥 (用于生成和验证Cookie)
        self.cookie_secret = secrets.token_bytes(32)
        
    def generate_server_certificate(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """生成服务器证书和私钥"""
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
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DTLS Server"),
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
        
        return cert, private_key
    
    def generate_cookie(self, client_addr: Tuple[str, int], client_random: bytes) -> bytes:
        """生成Cookie用于Hello Verify Request"""
        # 使用客户端地址、随机数和服务器密钥生成Cookie
        data = f"{client_addr[0]}:{client_addr[1]}".encode() + client_random
        cookie = hmac.new(self.cookie_secret, data, hashlib.sha256).digest()[:20]  # 取前20字节
        logger.debug(f"为客户端 {client_addr} 生成Cookie: {cookie.hex()}")
        return cookie
    
    def verify_cookie(self, client_addr: Tuple[str, int], client_random: bytes, cookie: bytes) -> bool:
        """验证Cookie"""
        expected_cookie = self.generate_cookie(client_addr, client_random)
        is_valid = hmac.compare_digest(expected_cookie, cookie)
        logger.debug(f"Cookie验证结果: {is_valid}, 期望: {expected_cookie.hex()}, 收到: {cookie.hex()}")
        return is_valid
    
    def create_hello_verify_request(self, client_addr: Tuple[str, int], client_random: bytes) -> bytes:
        """创建Hello Verify Request消息"""
        # 协议版本
        version = struct.pack('!H', DTLSConstants.DTLS_1_0)
        
        # 生成Cookie
        cookie = self.generate_cookie(client_addr, client_random)
        cookie_length = struct.pack('!B', len(cookie))
        
        # 组装Hello Verify Request
        hvr_data = version + cookie_length + cookie
        
        logger.info(f"创建Hello Verify Request，Cookie长度: {len(cookie)}")
        logger.debug(f"Hello Verify Request数据: {hvr_data.hex()}")
        
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.HELLO_VERIFY_REQUEST, hvr_data)
    
    def parse_client_hello(self, data: bytes) -> Dict[str, Any]:
        """解析Client Hello消息"""
        try:
            if len(data) < 38:  # 最小Client Hello长度
                logger.error("Client Hello太短")
                return None
            
            offset = 0
            result = {}
            
            # 协议版本 (2 bytes)
            version = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            result['version'] = version
            
            # 客户端随机数 (32 bytes)
            client_random = data[offset:offset+32]
            offset += 32
            result['client_random'] = client_random
            
            # Session ID
            session_id_length = data[offset]
            offset += 1
            if offset + session_id_length > len(data):
                logger.error("Client Hello Session ID数据不足")
                return None
            session_id = data[offset:offset+session_id_length]
            offset += session_id_length
            result['session_id'] = session_id
            
            # Cookie (DTLS特有)
            if offset >= len(data):
                logger.error("Client Hello缺少Cookie字段")
                return None
            cookie_length = data[offset]
            offset += 1
            if offset + cookie_length > len(data):
                logger.error("Client Hello Cookie数据不足")
                return None
            cookie = data[offset:offset+cookie_length]
            offset += cookie_length
            result['cookie'] = cookie
            
            # 密码套件
            if offset + 2 > len(data):
                logger.error("Client Hello缺少密码套件长度")
                return None
            cipher_suites_length = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            if offset + cipher_suites_length > len(data):
                logger.error("Client Hello密码套件数据不足")
                return None
            cipher_suites_data = data[offset:offset+cipher_suites_length]
            offset += cipher_suites_length
            
            # 解析密码套件列表
            cipher_suites = []
            for i in range(0, len(cipher_suites_data), 2):
                if i + 2 <= len(cipher_suites_data):
                    suite = struct.unpack('!H', cipher_suites_data[i:i+2])[0]
                    cipher_suites.append(suite)
            result['cipher_suites'] = cipher_suites
            
            # 压缩方法
            if offset >= len(data):
                logger.error("Client Hello缺少压缩方法")
                return None
            compression_methods_length = data[offset]
            offset += 1
            if offset + compression_methods_length > len(data):
                logger.error("Client Hello压缩方法数据不足")
                return None
            compression_methods = data[offset:offset+compression_methods_length]
            offset += compression_methods_length
            result['compression_methods'] = list(compression_methods)
            
            # 解析扩展（如果存在）
            extensions = {}
            if offset < len(data):
                # 扩展长度
                if offset + 2 <= len(data):
                    extensions_length = struct.unpack('!H', data[offset:offset+2])[0]
                    offset += 2
                    
                    if offset + extensions_length <= len(data):
                        extensions_data = data[offset:offset+extensions_length]
                        extensions = self.parse_extensions(extensions_data)
                        logger.info(f"解析到扩展: {list(extensions.keys())}")
            
            result['extensions'] = extensions
            
            logger.info(f"解析Client Hello成功:")
            logger.info(f"  版本: 0x{version:04x}")
            logger.info(f"  Cookie长度: {len(cookie)}")
            logger.info(f"  密码套件: {[hex(s) for s in cipher_suites]}")
            if 'server_name' in extensions:
                logger.info(f"  SNI服务器名称: {extensions['server_name']}")
            
            return result
            
        except Exception as e:
            logger.error(f"解析Client Hello失败: {e}")
            return None
    
    def parse_extensions(self, extensions_data: bytes) -> Dict[str, Any]:
        """解析TLS扩展"""
        extensions = {}
        offset = 0
        
        while offset < len(extensions_data):
            if offset + 4 > len(extensions_data):
                break
                
            # 扩展类型和长度
            ext_type = struct.unpack('!H', extensions_data[offset:offset+2])[0]
            ext_length = struct.unpack('!H', extensions_data[offset+2:offset+4])[0]
            offset += 4
            
            if offset + ext_length > len(extensions_data):
                break
                
            ext_data = extensions_data[offset:offset+ext_length]
            offset += ext_length
            
            # 解析SNI扩展
            if ext_type == DTLSConstants.EXTENSION_SERVER_NAME:
                server_name = self.parse_sni_extension(ext_data)
                if server_name:
                    extensions['server_name'] = server_name
                    logger.info(f"解析SNI扩展: {server_name}")
        
        return extensions
    
    def parse_sni_extension(self, ext_data: bytes) -> str:
        """解析SNI扩展数据"""
        try:
            if len(ext_data) < 2:
                return None
                
            # 服务器名称列表长度
            name_list_length = struct.unpack('!H', ext_data[0:2])[0]
            offset = 2
            
            if offset + name_list_length > len(ext_data):
                return None
                
            # 解析第一个服务器名称
            if offset + 3 <= len(ext_data):
                name_type = ext_data[offset]
                name_length = struct.unpack('!H', ext_data[offset+1:offset+3])[0]
                offset += 3
                
                if name_type == DTLSConstants.SNI_NAME_TYPE_HOSTNAME and offset + name_length <= len(ext_data):
                    server_name = ext_data[offset:offset+name_length].decode('utf-8')
                    return server_name
                    
        except Exception as e:
            logger.error(f"解析SNI扩展失败: {e}")
            
        return None
    
    def create_server_hello(self, client_hello: Dict[str, Any]) -> bytes:
        """创建Server Hello消息"""
        # 协议版本
        version = struct.pack('!H', DTLSConstants.DTLS_1_0)
        
        # 服务器随机数
        server_random = secrets.token_bytes(32)
        
        # Session ID (使用客户端的Session ID)
        session_id = client_hello['session_id']
        session_id_length = struct.pack('!B', len(session_id))
        
        # 选择密码套件 (选择第一个支持的)
        selected_cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
        cipher_suite = struct.pack('!H', selected_cipher_suite)
        
        # 压缩方法
        compression_method = struct.pack('!B', DTLSConstants.COMPRESSION_NULL)
        
        # 扩展（暂时为空）
        extensions_length = struct.pack('!H', 0)
        extensions = b''
        
        # 组装Server Hello
        server_hello_data = (version + server_random + session_id_length + session_id +
                           cipher_suite + compression_method + extensions_length + extensions)
        
        logger.info(f"创建Server Hello，选择密码套件: 0x{selected_cipher_suite:04x}")
        
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.SERVER_HELLO, server_hello_data)
    
    def create_certificate_message(self) -> bytes:
        """创建Certificate消息"""
        cert_der = self.server_certificate.public_bytes(serialization.Encoding.DER)
        cert_length = struct.pack('!I', len(cert_der))[1:]  # 3字节长度
        certificates_length = struct.pack('!I', len(cert_der) + 3)[1:]  # 3字节总长度
        
        cert_data = certificates_length + cert_length + cert_der
        
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.CERTIFICATE, cert_data)
    
    def create_server_hello_done(self) -> bytes:
        """创建Server Hello Done消息"""
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.SERVER_HELLO_DONE, b'')
    
    def handle_client(self, data: bytes, client_addr: Tuple[str, int]):
        """处理客户端消息"""
        try:
            # 解析DTLS记录
            content_type, payload = self.record_layer.parse_record(data)
            
            if content_type == DTLSConstants.HANDSHAKE:
                # 解析握手消息
                msg_type, message_data = self.handshake_layer.parse_handshake_message(payload)
                
                if msg_type == DTLSConstants.CLIENT_HELLO:
                    logger.info(f"收到来自 {client_addr} 的Client Hello")
                    
                    # 解析Client Hello
                    client_hello = self.parse_client_hello(message_data)
                    if not client_hello:
                        logger.error("解析Client Hello失败")
                        return
                    
                    # 检查是否有Cookie
                    if len(client_hello['cookie']) == 0:
                        # 第一次Client Hello，发送Hello Verify Request
                        logger.info("第一次Client Hello (无Cookie)，发送Hello Verify Request")
                        hvr = self.create_hello_verify_request(client_addr, client_hello['client_random'])
                        hvr_record = self.record_layer.create_record(DTLSConstants.HANDSHAKE, hvr)
                        self.socket.sendto(hvr_record, client_addr)
                        
                        # 保存客户端状态
                        self.client_states[client_addr] = {
                            'client_random': client_hello['client_random'],
                            'state': 'hello_verify_sent'
                        }
                        
                    else:
                        # 第二次Client Hello，验证Cookie
                        logger.info("第二次Client Hello (带Cookie)，验证Cookie")
                        
                        if client_addr not in self.client_states:
                            logger.error("未找到客户端状态")
                            return
                        
                        client_state = self.client_states[client_addr]
                        if not self.verify_cookie(client_addr, client_state['client_random'], client_hello['cookie']):
                            logger.error("Cookie验证失败")
                            return
                        
                        logger.info("Cookie验证成功，继续握手")
                        
                        # 发送Server Hello
                        server_hello = self.create_server_hello(client_hello)
                        server_hello_record = self.record_layer.create_record(DTLSConstants.HANDSHAKE, server_hello)
                        self.socket.sendto(server_hello_record, client_addr)
                        
                        # 发送Certificate
                        certificate = self.create_certificate_message()
                        certificate_record = self.record_layer.create_record(DTLSConstants.HANDSHAKE, certificate)
                        self.socket.sendto(certificate_record, client_addr)
                        
                        # 发送Server Hello Done
                        server_hello_done = self.create_server_hello_done()
                        server_hello_done_record = self.record_layer.create_record(DTLSConstants.HANDSHAKE, server_hello_done)
                        self.socket.sendto(server_hello_done_record, client_addr)
                        
                        # 更新客户端状态
                        client_state['state'] = 'server_hello_done_sent'
                        
                else:
                    logger.info(f"收到其他握手消息类型: {msg_type}")
                    
            elif content_type == DTLSConstants.APPLICATION_DATA:
                logger.info(f"收到来自 {client_addr} 的应用数据")
                # 这里可以处理应用数据
                
        except Exception as e:
            logger.error(f"处理客户端消息时出错: {e}")
    
    def start(self):
        """启动DTLS服务器"""
        try:
            logger.info(f"启动DTLS服务器，监听 {self.host}:{self.port}")
            
            # 生成服务器证书
            self.server_certificate, self.server_private_key = self.generate_server_certificate()
            logger.info("服务器证书生成完成")
            
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info("DTLS服务器启动成功，等待客户端连接...")
            
            while self.running:
                try:
                    # 接收数据
                    data, client_addr = self.socket.recvfrom(4096)
                    logger.debug(f"收到来自 {client_addr} 的数据，长度: {len(data)}")
                    
                    # 处理客户端消息
                    self.handle_client(data, client_addr)
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"处理客户端连接时出错: {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"服务器启动失败: {e}")
        finally:
            self.cleanup()
    
    def stop(self):
        """停止服务器"""
        self.running = False
        logger.info("正在停止DTLS服务器...")
    
    def cleanup(self):
        """清理资源"""
        if self.socket:
            self.socket.close()
            self.socket = None
        logger.info("DTLS服务器已停止")


def main():
    """主函数"""
    server = DTLSServer()
    
    try:
        server.start()
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在停止服务器...")
        server.stop()


if __name__ == "__main__":
    main()
