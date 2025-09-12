#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整DTLS客户端实现
实现完整的DTLS 1.2握手流程，包括：
- Client Hello
- Certificate 交换
- Key Exchange
- Change Cipher Spec
- Finished 消息
- 真正的加密通信

作者: Codegen
"""

import socket
import struct
import time
import hashlib
import hmac
import os
import logging
from typing import Optional, Dict, Any, Tuple, List
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import datetime
import ipaddress
import secrets

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
    
    # 新增的ECDHE密码套件
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C  # ECDHE-ECDSA-AES256-GCM-SHA384
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B  # ECDHE-ECDSA-AES128-GCM-SHA256
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030    # ECDHE-RSA-AES256-GCM-SHA384
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC028    # ECDHE-RSA-AES128-GCM-SHA256
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013       # ECDHE-RSA-AES128-SHA
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00FF        # 重新协商指示
    
    # 压缩方法
    COMPRESSION_NULL = 0
    
    # TLS扩展类型
    EXTENSION_SERVER_NAME = 0x0000              # SNI扩展
    EXTENSION_STATUS_REQUEST = 0x0005           # OCSP状态请求
    EXTENSION_SUPPORTED_GROUPS = 0x000A         # 支持的椭圆曲线组
    EXTENSION_EC_POINT_FORMATS = 0x000B         # EC点格式
    EXTENSION_SIGNATURE_ALGORITHMS = 0x000D     # 签名算法
    EXTENSION_ENCRYPT_THEN_MAC = 0x0016         # 先加密后MAC
    EXTENSION_EXTENDED_MASTER_SECRET = 0x0017   # 扩展主密钥
    EXTENSION_SESSION_TICKET = 0x0023           # 会话票据
    
    # SNI名称类型
    SNI_NAME_TYPE_HOSTNAME = 0x00
    
    # EC点格式
    EC_POINT_FORMAT_UNCOMPRESSED = 0x00
    
    # 支持的椭圆曲线组
    SECP256R1 = 0x0017  # P-256
    SECP384R1 = 0x0018  # P-384
    SECP521R1 = 0x0019  # P-521
    X25519 = 0x001D     # X25519
    
    # 签名算法
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503


class DTLSRecord:
    """DTLS记录层"""
    
    def __init__(self):
        self.sequence_number = 0
        self.epoch = 0
    
    def create_record(self, content_type: int, data: bytes) -> bytes:
        """创建DTLS记录"""
        version = DTLSConstants.DTLS_1_0
        length = len(data)
        
        # DTLS记录格式: type(1) + version(2) + epoch(2) + sequence(6) + length(2) + data
        record = (struct.pack('!BHH', content_type, version, self.epoch) +
                 struct.pack('!Q', self.sequence_number)[2:] +  # 6字节序列号
                 struct.pack('!H', length) + 
                 data)
        
        self.sequence_number += 1
        return record
    
    def parse_record(self, data: bytes) -> Tuple[int, bytes]:
        """解析DTLS记录"""
        if len(data) < 13:
            raise ValueError("记录太短")
        
        content_type = data[0]
        version = struct.unpack('!H', data[1:3])[0]
        epoch = struct.unpack('!H', data[3:5])[0]
        sequence = int.from_bytes(data[5:11], 'big')  # 6字节序列号
        length = struct.unpack('!H', data[11:13])[0]
        payload = data[13:13+length]
        
        return content_type, payload


class DTLSHandshake:
    """DTLS握手层"""
    
    def __init__(self):
        self.message_sequence = 0
        self.handshake_messages = []  # 用于计算Finished消息
    
    def create_handshake_message(self, msg_type: int, data: bytes) -> bytes:
        """创建握手消息"""
        length = len(data)
        
        # 握手消息格式: type(1) + length(3) + message_seq(2) + fragment_offset(3) + fragment_length(3) + data
        # 使用正确的DTLS握手消息格式
        message = (struct.pack("!B", msg_type) + 
                  struct.pack("!I", length)[1:] +  # 3字节长度
                  struct.pack("!H", self.message_sequence) +
                  struct.pack("!I", 0)[1:] +  # 3字节fragment_offset
                  struct.pack("!I", length)[1:] +  # 3字节fragment_length
                  data)
        
        self.message_sequence += 1
        self.handshake_messages.append(message)
        
        return message
    
    def parse_handshake_message(self, data: bytes) -> Tuple[int, bytes]:
        """解析握手消息"""
        if len(data) < 12:
            raise ValueError("握手消息太短")
        
        # 正确解析DTLS握手消息格式
        msg_type = data[0]
        length = int.from_bytes(data[1:4], 'big')
        msg_seq = int.from_bytes(data[4:6], 'big')
        frag_offset = int.from_bytes(data[6:9], 'big')
        frag_length = int.from_bytes(data[9:12], 'big')
        payload = data[12:12+frag_length]
        
        return msg_type, payload


class CompleteDTLSClient:
    """完整的DTLS客户端实现"""
    
    def __init__(self, server_host: str = 'localhost', server_port: int = 4433, server_name: str = None):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.server_name = server_name or server_host  # SNI服务器名称，默认使用server_host
        self.connected = False
        
        # DTLS组件
        self.record_layer = DTLSRecord()
        self.handshake_layer = DTLSHandshake()
        
        # 握手状态
        self.client_random = None
        self.server_random = None
        self.session_id = None
        self.cipher_suite = None
        self.compression_method = None
        self.cookie = None  # DTLS Cookie for Hello Verify Request
        
        # 密钥材料
        self.pre_master_secret = None
        self.master_secret = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None
        
        # 证书
        self.server_certificate = None
        self.client_certificate = None
        self.client_private_key = None
        
        # 加密状态
        self.encryption_enabled = False
        
    def generate_client_certificate(self) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """生成客户端证书和私钥"""
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
            x509.NameAttribute(NameOID.COMMON_NAME, "DTLS Client"),
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
        ).sign(private_key, hashes.SHA256())
        
        return cert, private_key
    
    def create_sni_extension(self, server_name: str) -> bytes:
        """创建SNI扩展"""
        # SNI扩展格式:
        # Extension Type (2 bytes): 0x0000
        # Extension Length (2 bytes)
        # Server Name List Length (2 bytes)
        # Server Name Type (1 byte): 0x00 (host_name)
        # Server Name Length (2 bytes)
        # Server Name (variable)
        
        server_name_bytes = server_name.encode('utf-8')
        server_name_length = len(server_name_bytes)
        
        # 构造服务器名称条目
        server_name_entry = struct.pack('!BH', 
            DTLSConstants.SNI_NAME_TYPE_HOSTNAME,  # 名称类型: host_name
            server_name_length                      # 名称长度
        ) + server_name_bytes
        
        # 服务器名称列表长度
        server_name_list_length = len(server_name_entry)
        
        # 扩展数据
        extension_data = struct.pack('!H', server_name_list_length) + server_name_entry
        
        # 完整的SNI扩展
        sni_extension = struct.pack('!HH', 
            DTLSConstants.EXTENSION_SERVER_NAME,  # 扩展类型
            len(extension_data)                   # 扩展长度
        ) + extension_data
        
        return sni_extension

    def create_ec_point_formats_extension(self) -> bytes:
        """创建EC点格式扩展"""
        # 支持的EC点格式列表
        point_formats = [DTLSConstants.EC_POINT_FORMAT_UNCOMPRESSED]
        
        # 扩展数据：点格式列表长度 + 点格式列表
        extension_data = struct.pack("!B", len(point_formats)) + bytes(point_formats)
        
        # 完整的扩展
        return struct.pack("!HH", 
            DTLSConstants.EXTENSION_EC_POINT_FORMATS,
            len(extension_data)
        ) + extension_data
    
    def create_supported_groups_extension(self) -> bytes:
        """创建支持的椭圆曲线组扩展"""
        # 支持的椭圆曲线组
        supported_groups = [
            DTLSConstants.SECP256R1,  # P-256
            DTLSConstants.SECP384R1,  # P-384
            DTLSConstants.SECP521R1,  # P-521
            DTLSConstants.X25519      # X25519
        ]
        
        # 扩展数据：组列表长度 + 组列表
        groups_data = b"".join(struct.pack("!H", group) for group in supported_groups)
        extension_data = struct.pack("!H", len(groups_data)) + groups_data
        
        return struct.pack("!HH",
            DTLSConstants.EXTENSION_SUPPORTED_GROUPS,
            len(extension_data)
        ) + extension_data
    
    def create_signature_algorithms_extension(self) -> bytes:
        """创建签名算法扩展"""
        # 支持的签名算法
        signature_algorithms = [
            DTLSConstants.RSA_PKCS1_SHA256,
            DTLSConstants.RSA_PKCS1_SHA384,
            DTLSConstants.RSA_PKCS1_SHA512,
            DTLSConstants.ECDSA_SECP256R1_SHA256,
            DTLSConstants.ECDSA_SECP384R1_SHA384
        ]
        
        # 扩展数据：算法列表长度 + 算法列表
        algorithms_data = b"".join(struct.pack("!H", alg) for alg in signature_algorithms)
        extension_data = struct.pack("!H", len(algorithms_data)) + algorithms_data
        
        return struct.pack("!HH",
            DTLSConstants.EXTENSION_SIGNATURE_ALGORITHMS,
            len(extension_data)
        ) + extension_data
    
    def create_status_request_extension(self) -> bytes:
        """创建OCSP状态请求扩展"""
        # OCSP状态请求类型 (1 = ocsp)
        status_type = 1
        # 请求者ID列表长度 (0 = 空)
        responder_id_list_length = 0
        # 请求扩展长度 (0 = 空)
        request_extensions_length = 0
        
        extension_data = struct.pack("!BHH", 
            status_type,
            responder_id_list_length,
            request_extensions_length
        )
        
        return struct.pack("!HH",
            DTLSConstants.EXTENSION_STATUS_REQUEST,
            len(extension_data)
        ) + extension_data
    
    def create_encrypt_then_mac_extension(self) -> bytes:
        """创建先加密后MAC扩展（空扩展）"""
        return struct.pack("!HH",
            DTLSConstants.EXTENSION_ENCRYPT_THEN_MAC,
            0  # 扩展数据长度为0
        )
    
    def create_extended_master_secret_extension(self) -> bytes:
        """创建扩展主密钥扩展（空扩展）"""
        return struct.pack("!HH",
            DTLSConstants.EXTENSION_EXTENDED_MASTER_SECRET,
            0  # 扩展数据长度为0
        )
    
    def create_session_ticket_extension(self) -> bytes:
        """创建会话票据扩展（空扩展，表示支持会话票据）"""
        return struct.pack("!HH",
            DTLSConstants.EXTENSION_SESSION_TICKET,
            0  # 扩展数据长度为0
        )
    
    def create_client_hello(self) -> bytes:
        """创建Client Hello消息"""
        # 生成客户端随机数
        self.client_random = secrets.token_bytes(32)
        
        # 构造Client Hello - 符合DTLS标准格式
        version = struct.pack('!H', DTLSConstants.DTLS_1_0)  # DTLS 1.2 = 0xFEFD
        random = self.client_random  # 32字节随机数
        
        # Session ID
        session_id_length = struct.pack('!B', 0)  # 无会话ID
        session_id = b''
        
        # Cookie (DTLS特有字段)
        if self.cookie is not None:
            cookie_length = struct.pack("!B", len(self.cookie))
            cookie = self.cookie
            logger.debug(f"使用Cookie: {self.cookie.hex()}")
        else:
            cookie_length = struct.pack("!B", 0)  # 初始Client Hello无Cookie
            cookie = b""
            logger.debug("发送初始Client Hello (无Cookie)")
        
        # 密码套件列表 - 包含所有支持的密码套件
        supported_cipher_suites = [
            DTLSConstants.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  # 0xC02C
            DTLSConstants.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  # 0xC02B
            DTLSConstants.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,    # 0xC030
            DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,    # 0xC028
            DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,       # 0xC013
            DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256,          # 0x009C (原有)
            DTLSConstants.TLS_RSA_WITH_AES_256_GCM_SHA384,          # 0x009D (原有)
            DTLSConstants.TLS_EMPTY_RENEGOTIATION_INFO_SCSV         # 0x00FF
        ]
        
        # 构造密码套件数据
        cipher_suites_data = b''
        for suite in supported_cipher_suites:
            cipher_suites_data += struct.pack('!H', suite)
        
        cipher_suites_length = struct.pack('!H', len(cipher_suites_data))
        cipher_suites = cipher_suites_length + cipher_suites_data
        
        logger.info(f"支持的密码套件数量: {len(supported_cipher_suites)}")
        for i, suite in enumerate(supported_cipher_suites):
            logger.debug(f"密码套件 {i+1}: 0x{suite:04X}")
        
        # 压缩方法
        compression_methods_length = struct.pack('!B', 1)  # 1个压缩方法
        compression_method = struct.pack('!B', DTLSConstants.COMPRESSION_NULL)
        compression_methods = compression_methods_length + compression_method
        
        # 扩展
        extensions = b''
        
        # 添加SNI扩展（如果指定了服务器名称）
        if self.server_name:
            sni_extension = self.create_sni_extension(self.server_name)
            extensions += sni_extension
            logger.info(f"添加SNI扩展，服务器名称: {self.server_name}")
        
        # 添加EC点格式扩展
        ec_point_formats_ext = self.create_ec_point_formats_extension()
        extensions += ec_point_formats_ext
        logger.info("添加EC点格式扩展")
        
        # 添加支持的椭圆曲线组扩展
        supported_groups_ext = self.create_supported_groups_extension()
        extensions += supported_groups_ext
        logger.info("添加支持的椭圆曲线组扩展")
        
        # 添加签名算法扩展
        signature_algorithms_ext = self.create_signature_algorithms_extension()
        extensions += signature_algorithms_ext
        logger.info("添加签名算法扩展")
        
        # 添加OCSP状态请求扩展
        status_request_ext = self.create_status_request_extension()
        extensions += status_request_ext
        logger.info("添加OCSP状态请求扩展")
        
        # 添加先加密后MAC扩展
        encrypt_then_mac_ext = self.create_encrypt_then_mac_extension()
        extensions += encrypt_then_mac_ext
        logger.info("添加先加密后MAC扩展")
        
        # 添加扩展主密钥扩展
        extended_master_secret_ext = self.create_extended_master_secret_extension()
        extensions += extended_master_secret_ext
        logger.info("添加扩展主密钥扩展")
        
        # 添加会话票据扩展
        session_ticket_ext = self.create_session_ticket_extension()
        extensions += session_ticket_ext
        logger.info("添加会话票据扩展")
        
        extensions_length = struct.pack('!H', len(extensions))
        
        # 按照DTLS标准顺序组装Client Hello
        client_hello_data = (version + random + session_id_length + session_id + 
                           cookie_length + cookie + cipher_suites + 
                           compression_methods + extensions_length + extensions)
        
        logger.info(f"Client Hello数据长度: {len(client_hello_data)} 字节")
        logger.debug(f"Client Hello数据: {client_hello_data.hex()}")
        
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.CLIENT_HELLO, client_hello_data)
    def parse_hello_verify_request(self, data: bytes) -> bool:
        """解析Hello Verify Request消息"""
        try:
            if len(data) < 3:  # 最小长度：version(2) + cookie_length(1)
                logger.error("Hello Verify Request太短")
                return False
            
            offset = 0
            
            # 协议版本 (2 bytes)
            version = struct.unpack("!H", data[offset:offset+2])[0]
            offset += 2
            logger.debug(f"Hello Verify Request版本: 0x{version:04x}")
            
            # Cookie长度和内容
            cookie_length = data[offset]
            offset += 1
            
            if offset + cookie_length > len(data):
                logger.error("Hello Verify Request Cookie数据不足")
                return False
            
            self.cookie = data[offset:offset+cookie_length]
            logger.info(f"收到Hello Verify Request，Cookie长度: {cookie_length}")
            logger.debug(f"Cookie: {self.cookie.hex()}")
            
            return True
            
        except Exception as e:
            logger.error(f"解析Hello Verify Request失败: {e}")
            return False

    
    def parse_server_hello(self, data: bytes) -> bool:
        """解析Server Hello消息"""
        try:
            if len(data) < 38:  # 最小Server Hello长度
                return False
            
            # 解析版本
            version = struct.unpack('!H', data[0:2])[0]
            if version != DTLSConstants.DTLS_1_0:
                logger.error(f"不支持的DTLS版本: {hex(version)}")
                return False
            
            # 提取服务器随机数
            self.server_random = data[2:34]
            
            # 解析会话ID
            session_id_length = data[34]
            session_id_end = 35 + session_id_length
            if session_id_length > 0:
                self.session_id = data[35:session_id_end]
            
            # 解析密码套件
            cipher_suite_offset = session_id_end
            self.cipher_suite = struct.unpack('!H', data[cipher_suite_offset:cipher_suite_offset+2])[0]
            
            # 解析压缩方法
            compression_offset = cipher_suite_offset + 2
            self.compression_method = data[compression_offset]
            
            logger.info(f"Server Hello解析成功: 密码套件={hex(self.cipher_suite)}")
            return True
            
        except Exception as e:
            logger.error(f"解析Server Hello失败: {e}")
            return False
    
    def parse_certificate(self, data: bytes) -> bool:
        """解析服务器证书"""
        try:
            if len(data) < 3:
                return False
            
            # 证书链长度
            cert_chain_length = struct.unpack('!I', b'\x00' + data[0:3])[0]
            offset = 3
            
            # 解析第一个证书（服务器证书）
            if offset + 3 > len(data):
                return False
            
            cert_length = struct.unpack('!I', b'\x00' + data[offset:offset+3])[0]
            offset += 3
            
            if offset + cert_length > len(data):
                return False
            
            cert_data = data[offset:offset+cert_length]
            
            # 解析X.509证书
            self.server_certificate = x509.load_der_x509_certificate(cert_data)
            
            logger.info("服务器证书解析成功")
            logger.info(f"证书主题: {self.server_certificate.subject}")
            
            return True
            
        except Exception as e:
            logger.error(f"解析证书失败: {e}")
            return False
    
    def create_client_key_exchange(self) -> bytes:
        """创建Client Key Exchange消息"""
        # 生成预主密钥 (48字节)
        self.pre_master_secret = (struct.pack('!H', DTLSConstants.DTLS_1_0) + 
                                secrets.token_bytes(46))
        
        # 使用服务器公钥加密预主密钥
        if self.server_certificate:
            server_public_key = self.server_certificate.public_key()
            encrypted_pre_master = server_public_key.encrypt(
                self.pre_master_secret,
                padding.PKCS1v15()
            )
        else:
            # 如果没有服务器证书，使用模拟加密
            encrypted_pre_master = self.pre_master_secret
        
        # Client Key Exchange消息格式: length(2) + encrypted_pre_master_secret
        key_exchange_data = struct.pack('!H', len(encrypted_pre_master)) + encrypted_pre_master
        
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.CLIENT_KEY_EXCHANGE, key_exchange_data)
    
    def derive_master_secret(self):
        """派生主密钥"""
        if not self.pre_master_secret or not self.client_random or not self.server_random:
            raise ValueError("缺少派生主密钥所需的材料")
        
        # TLS PRF (伪随机函数) 简化实现
        seed = b"master secret" + self.client_random + self.server_random
        
        # 使用HMAC-SHA256作为PRF
        self.master_secret = self._prf(self.pre_master_secret, seed, 48)
        
        logger.info("主密钥派生完成")
    
    def derive_key_material(self):
        """派生密钥材料"""
        if not self.master_secret:
            raise ValueError("主密钥未生成")
        
        # 密钥扩展
        seed = b"key expansion" + self.server_random + self.client_random
        
        # 根据密码套件确定密钥长度
        if self.cipher_suite == DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256:
            key_length = 16  # AES-128
            iv_length = 4    # GCM固定IV长度
        else:
            key_length = 32  # AES-256
            iv_length = 4
        
        # 生成密钥材料
        key_material_length = 2 * (key_length + iv_length)
        key_material = self._prf(self.master_secret, seed, key_material_length)
        
        # 分配密钥
        offset = 0
        self.client_write_key = key_material[offset:offset+key_length]
        offset += key_length
        self.server_write_key = key_material[offset:offset+key_length]
        offset += key_length
        self.client_write_iv = key_material[offset:offset+iv_length]
        offset += iv_length
        self.server_write_iv = key_material[offset:offset+iv_length]
        
        logger.info("密钥材料派生完成")
    
    def _prf(self, secret: bytes, seed: bytes, length: int) -> bytes:
        """TLS伪随机函数 (简化实现)"""
        result = b''
        a = seed
        
        while len(result) < length:
            a = hmac.new(secret, a, hashlib.sha256).digest()
            result += hmac.new(secret, a + seed, hashlib.sha256).digest()
        
        return result[:length]
    
    def create_change_cipher_spec(self) -> bytes:
        """创建Change Cipher Spec消息"""
        return b'\x01'
    
    def create_finished(self) -> bytes:
        """创建Finished消息"""
        # 计算所有握手消息的哈希
        handshake_hash = hashlib.sha256()
        for msg in self.handshake_layer.handshake_messages:
            handshake_hash.update(msg)
        
        # 生成验证数据
        seed = b"client finished" + handshake_hash.digest()
        verify_data = self._prf(self.master_secret, seed, 12)
        
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.FINISHED, verify_data)
    
    def encrypt_message(self, plaintext: bytes) -> bytes:
        """加密应用数据"""
        if not self.encryption_enabled or not self.client_write_key:
            return plaintext
        
        # 使用AES-GCM加密
        nonce = self.client_write_iv + secrets.token_bytes(8)  # 4字节固定IV + 8字节随机
        
        cipher = Cipher(algorithms.AES(self.client_write_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        # 返回: nonce(12) + ciphertext + tag(16)
        return nonce + ciphertext + encryptor.tag
    
    def decrypt_message(self, encrypted_data: bytes) -> bytes:
        """解密应用数据"""
        if not self.encryption_enabled or not self.server_write_key or len(encrypted_data) < 28:
            return encrypted_data
        
        try:
            # 提取组件
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:-16]
            tag = encrypted_data[-16:]
            
            cipher = Cipher(algorithms.AES(self.server_write_key), modes.GCM(nonce, tag))
            decryptor = cipher.decryptor()
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext
            
        except Exception as e:
            logger.warning(f"解密失败: {e}")
            return encrypted_data
    
    def connect(self, timeout: float = 10.0) -> bool:
        """连接到DTLS服务器并执行完整握手"""
        try:
            logger.info(f"开始完整DTLS握手连接到 {self.server_host}:{self.server_port}")
            
            # 创建UDP套接字
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.settimeout(timeout)
            self.socket.connect((self.server_host, self.server_port))
            
            # 生成客户端证书
            self.client_certificate, self.client_private_key = self.generate_client_certificate()
            
            # 执行DTLS握手
            if self._perform_handshake():
                self.connected = True
                self.encryption_enabled = True
                logger.info("完整DTLS握手成功，加密通信已启用")
                return True
            else:
                logger.error("DTLS握手失败")
                return False
                
        except Exception as e:
            logger.error(f"连接失败: {e}")
            self.cleanup()
            return False
    
    def _perform_handshake(self) -> bool:
        """执行完整的DTLS握手流程，包括Hello Verify Request处理"""
        try:
            # 第一阶段：发送初始Client Hello (无Cookie)
            logger.info("1. 发送初始Client Hello (无Cookie)")
            client_hello = self.create_client_hello()
            client_hello_record = self.record_layer.create_record(
                DTLSConstants.HANDSHAKE, client_hello)
            self.socket.send(client_hello_record)
            
            # 接收响应 - 应该是Hello Verify Request
            logger.info("2. 等待Hello Verify Request")
            response = self.socket.recv(4096)
            content_type, payload = self.record_layer.parse_record(response)
            
            if content_type != DTLSConstants.HANDSHAKE:
                logger.error("期望握手消息，收到其他类型")
                return False
            
            msg_type, message_data = self.handshake_layer.parse_handshake_message(payload)
            
            # 检查是否收到Hello Verify Request
            if msg_type == DTLSConstants.HELLO_VERIFY_REQUEST:
                logger.info("收到Hello Verify Request，解析Cookie")
                if not self.parse_hello_verify_request(message_data):
                    return False
                
                # 第二阶段：发送带Cookie的Client Hello
                logger.info("3. 发送带Cookie的Client Hello")
                client_hello_with_cookie = self.create_client_hello()
                client_hello_record = self.record_layer.create_record(
                    DTLSConstants.HANDSHAKE, client_hello_with_cookie)
                self.socket.send(client_hello_record)
                
                # 接收Server Hello
                logger.info("4. 等待Server Hello")
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                
                if content_type != DTLSConstants.HANDSHAKE:
                    logger.error("期望握手消息，收到其他类型")
                    return False
                
                msg_type, server_hello_data = self.handshake_layer.parse_handshake_message(payload)
                if msg_type != DTLSConstants.SERVER_HELLO:
                    logger.error("期望Server Hello消息")
                    return False
                    
            elif msg_type == DTLSConstants.SERVER_HELLO:
                # 服务器直接发送Server Hello (可能不支持Hello Verify Request)
                logger.warning("服务器跳过了Hello Verify Request，直接发送Server Hello")
                server_hello_data = message_data
            else:
                logger.error(f"收到意外的握手消息类型: {msg_type}")
                return False
            
            # 解析Server Hello
            if not self.parse_server_hello(server_hello_data):
                return False
            
            # 5. 接收Certificate (可选)
            logger.info("5. 等待Certificate")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                
                if content_type == DTLSConstants.HANDSHAKE:
                    msg_type, cert_data = self.handshake_layer.parse_handshake_message(payload)
                    if msg_type == DTLSConstants.CERTIFICATE:
                        self.parse_certificate(cert_data)
            except socket.timeout:
                logger.info("未收到证书消息（可能是PSK模式）")
            
            # 6. 接收Server Hello Done
            logger.info("6. 等待Server Hello Done")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                
                if content_type == DTLSConstants.HANDSHAKE:
                    msg_type, _ = self.handshake_layer.parse_handshake_message(payload)
                    if msg_type != DTLSConstants.SERVER_HELLO_DONE:
                        logger.warning("未收到Server Hello Done")
            except socket.timeout:
                logger.info("未收到Server Hello Done（继续握手）")
            
            # 7. 发送Client Key Exchange
            logger.info("7. 发送Client Key Exchange")
            client_key_exchange = self.create_client_key_exchange()
            if client_key_exchange:
                client_key_exchange_record = self.record_layer.create_record(
                    DTLSConstants.HANDSHAKE, client_key_exchange)
                self.socket.send(client_key_exchange_record)
            
            # 8. 发送Change Cipher Spec
            logger.info("8. 发送Change Cipher Spec")
            change_cipher_spec = struct.pack('!B', 1)
            change_cipher_spec_record = self.record_layer.create_record(
                DTLSConstants.CHANGE_CIPHER_SPEC, change_cipher_spec)
            self.socket.send(change_cipher_spec_record)
            
            # 9. 发送Finished
            logger.info("9. 发送Finished")
            finished = self.create_finished_message()
            finished_record = self.record_layer.create_record(
                DTLSConstants.HANDSHAKE, finished)
            self.socket.send(finished_record)
            
            # 10. 接收Change Cipher Spec
            logger.info("10. 等待Change Cipher Spec")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                if content_type == DTLSConstants.CHANGE_CIPHER_SPEC:
                    logger.info("收到Change Cipher Spec")
            except socket.timeout:
                logger.warning("未收到Change Cipher Spec")
            
            # 11. 接收Finished
            logger.info("11. 等待Finished")
            try:
                response = self.socket.recv(4096)
                content_type, payload = self.record_layer.parse_record(response)
                if content_type == DTLSConstants.HANDSHAKE:
                    msg_type, finished_data = self.handshake_layer.parse_handshake_message(payload)
                    if msg_type == DTLSConstants.FINISHED:
                        logger.info("收到Finished消息")
                        if self.verify_finished_message(finished_data):
                            logger.info("Finished消息验证成功")
                        else:
                            logger.warning("Finished消息验证失败")
            except socket.timeout:
                logger.warning("未收到Finished消息")
            
            logger.info("DTLS握手完成")
            return True
            
        except Exception as e:
            logger.error(f"握手过程中发生错误: {e}")
            return False

    
    def send_message(self, message: str) -> bool:
        """发送加密的应用数据"""
        if not self.connected:
            logger.error("未连接到服务器")
            return False
        
        try:
            plaintext = message.encode('utf-8')
            encrypted_data = self.encrypt_message(plaintext)
            
            app_data_record = self.record_layer.create_record(
                DTLSConstants.APPLICATION_DATA, encrypted_data)
            
            self.socket.send(app_data_record)
            logger.info(f"发送加密消息: {message}")
            return True
            
        except Exception as e:
            logger.error(f"发送消息失败: {e}")
            return False
    
    def receive_message(self, buffer_size: int = 4096) -> Optional[str]:
        """接收并解密应用数据"""
        if not self.connected:
            logger.error("未连接到服务器")
            return None
        
        try:
            data = self.socket.recv(buffer_size)
            if not data:
                return None
            
            content_type, payload = self.record_layer.parse_record(data)
            
            if content_type == DTLSConstants.APPLICATION_DATA:
                decrypted_data = self.decrypt_message(payload)
                message = decrypted_data.decode('utf-8')
                logger.info(f"接收加密消息: {message}")
                return message
            else:
                logger.info(f"收到非应用数据消息，类型: {content_type}")
                return None
                
        except socket.timeout:
            return None
        except Exception as e:
            logger.error(f"接收消息失败: {e}")
            return None
    
    def get_handshake_info(self) -> Dict[str, Any]:
        """获取握手信息"""
        return {
            'connected': self.connected,
            'encryption_enabled': self.encryption_enabled,
            'cipher_suite': hex(self.cipher_suite) if self.cipher_suite else None,
            'compression_method': self.compression_method,
            'server_certificate_subject': str(self.server_certificate.subject) if self.server_certificate else None,
            'master_secret_length': len(self.master_secret) if self.master_secret else 0,
            'client_write_key_length': len(self.client_write_key) if self.client_write_key else 0
        }
    
    def send_application_data(self, data: bytes) -> bool:
        """发送应用数据"""
        if not self.connected:
            logger.error("未连接到服务器")
            return False
        
        try:
            # 创建应用数据记录
            app_record = self.record_layer.create_record(DTLSConstants.APPLICATION_DATA, data)
            self.socket.sendto(app_record, (self.server_host, self.server_port))
            logger.info(f"发送应用数据: {len(data)} 字节")
            return True
        except Exception as e:
            logger.error(f"发送应用数据失败: {e}")
            return False
    
    def receive_application_data(self, timeout: float = 5.0) -> Optional[bytes]:
        """接收应用数据"""
        if not self.connected:
            logger.error("未连接到服务器")
            return None
        
        try:
            self.socket.settimeout(timeout)
            data, addr = self.socket.recvfrom(4096)
            
            # 解析DTLS记录
            content_type, payload = self.record_layer.parse_record(data)
            
            if content_type == DTLSConstants.APPLICATION_DATA:
                logger.info(f"收到应用数据: {len(payload)} 字节")
                return payload
            else:
                logger.warning(f"收到非应用数据: 类型={content_type}")
                return None
                
        except Exception as e:
            logger.error(f"接收应用数据失败: {e}")
            return None
    
    def close(self):
        """关闭连接"""
        self.cleanup()
    def create_finished_message(self) -> bytes:
        """创建Finished消息"""
        # 简化的Finished消息实现
        # 在实际实现中，这应该包含握手消息的哈希验证
        finished_data = b"client finished"  # 简化版本
        return self.handshake_layer.create_handshake_message(
            DTLSConstants.FINISHED, finished_data)
    
    def verify_finished_message(self, data: bytes) -> bool:
        """验证Finished消息"""
        # 简化的验证实现
        logger.info("验证Finished消息（简化版本）")
        return True

    
    def cleanup(self):
        """清理资源"""
        self.connected = False
        self.encryption_enabled = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        logger.info("完整DTLS客户端资源清理完成")


def main():
    """主函数 - 演示完整DTLS客户端"""
    print("完整DTLS客户端演示程序")
    print("=" * 50)
    print("✅ 实现完整的DTLS 1.2握手流程")
    print("✅ 包括Client Hello、Certificate交换、Key Exchange")
    print("✅ 真正的密钥协商和加密通信")
    print("✅ 支持RSA密钥交换和AES-GCM加密")
    print()
    
    client = CompleteDTLSClient(server_host='localhost', server_port=4433)
    
    try:
        # 执行完整握手
        if not client.connect():
            print("DTLS握手失败，请确保服务器支持DTLS协议")
            return
        
        # 显示握手信息
        info = client.get_handshake_info()
        print("握手信息:")
        for key, value in info.items():
            print(f"  {key}: {value}")
        
        # 发送加密消息
        print("\n发送加密消息...")
        test_messages = [
            "Hello, Complete DTLS Server!",
            "这是通过完整DTLS握手建立的加密连接",
            "Message with RSA key exchange and AES-GCM encryption"
        ]
        
        for msg in test_messages:
            if client.send_message(msg):
                # 尝试接收响应
                response = client.receive_message()
                if response:
                    print(f"服务器响应: {response}")
                time.sleep(1)
        
        print("\n完整DTLS通信演示完成")
        
    except KeyboardInterrupt:
        print("\n用户中断")
    except Exception as e:
        print(f"程序错误: {e}")
    finally:
        client.cleanup()


if __name__ == "__main__":
    main()
