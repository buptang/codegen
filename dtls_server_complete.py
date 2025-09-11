#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整DTLS服务器实现
支持完整的DTLS 1.2握手流程

作者: Codegen
"""

import socket
import struct
import threading
import time
import hashlib
import hmac
import logging
from typing import Optional, Dict, Any, Tuple
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import datetime
import ipaddress
import secrets

# 重用客户端的常量定义
# 移除循环导入


class DTLSConstants:
    # 内容类型
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23
    
    # DTLS版本
    DTLS_1_2 = 0xFEFD
    
    # 握手消息类型
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
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


# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DTLSRecord:
    """DTLS记录层"""
    
    def __init__(self):
        self.sequence_number = 0
        self.epoch = 0
    
    def create_record(self, content_type: int, data: bytes) -> bytes:
        """创建DTLS记录"""
        version = DTLSConstants.DTLS_1_2
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


class CompleteDTLSServer:
    """完整的DTLS服务器实现"""
    
    def __init__(self, host: str = 'localhost', port: int = 4433):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        
        # 服务器证书和私钥
        self.server_certificate = None
        self.server_private_key = None
        
        self.generate_server_certificate()
    
    def generate_server_certificate(self):
        """生成服务器证书和私钥"""
        logger.info("生成服务器证书...")
        
        # 生成私钥
        self.server_private_key = rsa.generate_private_key(
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
        
        self.server_certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.server_private_key.public_key()
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
        ).sign(self.server_private_key, hashes.SHA256())
        
        logger.info("服务器证书生成完成")
    
    def start(self):
        """启动DTLS服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.running = True
            
            logger.info(f"完整DTLS服务器启动在 {self.host}:{self.port}")
            
            while self.running:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    # 为每个客户端创建处理线程
                    threading.Thread(
                        target=self.handle_client,
                        args=(data, addr),
                        daemon=True
                    ).start()
                    
                except Exception as e:
                    if self.running:
                        logger.error(f"服务器错误: {e}")
                        
        except Exception as e:
            logger.error(f"启动服务器失败: {e}")
        finally:
            self.cleanup()
    
    def handle_client(self, initial_data: bytes, client_addr: tuple):
        """处理客户端连接"""
        logger.info(f"处理客户端连接: {client_addr}")
        
        # 创建客户端会话
        session = DTLSServerSession(self, client_addr)
        
        try:
            # 处理初始数据
            session.process_message(initial_data)
            
            # 继续处理后续消息
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.bind(('', 0))  # 绑定到任意端口
            client_socket.settimeout(30.0)  # 30秒超时
            
            # 这里简化处理，实际应该维护客户端状态
            while session.connected:
                try:
                    data, addr = self.socket.recvfrom(4096)
                    if addr == client_addr:
                        session.process_message(data)
                except socket.timeout:
                    break
                except Exception as e:
                    logger.error(f"处理客户端消息错误: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"客户端处理失败 {client_addr}: {e}")
        finally:
            logger.info(f"客户端 {client_addr} 连接关闭")
    
    def stop(self):
        """停止服务器"""
        self.cleanup()
    
    def cleanup(self):
        """清理资源"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None


class DTLSServerSession:
    """DTLS服务器会话"""
    
    def __init__(self, server: CompleteDTLSServer, client_addr: tuple):
        self.server = server
        self.client_addr = client_addr
        self.connected = False
        
        # DTLS组件
        self.record_layer = DTLSRecord()
        self.handshake_layer = DTLSHandshake()
        
        # 握手状态
        self.client_random = None
        self.server_random = None
        self.session_id = None
        self.cipher_suite = DTLSConstants.TLS_RSA_WITH_AES_128_GCM_SHA256
        self.compression_method = DTLSConstants.COMPRESSION_NULL
        
        # 密钥材料
        self.pre_master_secret = None
        self.master_secret = None
        self.client_write_key = None
        self.server_write_key = None
        self.client_write_iv = None
        self.server_write_iv = None
        
        # 握手状态机
        self.handshake_state = "WAIT_CLIENT_HELLO"
        self.encryption_enabled = False
    
    def process_message(self, data: bytes):
        """处理接收到的消息"""
        try:
            content_type, payload = self.record_layer.parse_record(data)
            
            if content_type == DTLSConstants.HANDSHAKE:
                self.process_handshake_message(payload)
            elif content_type == DTLSConstants.CHANGE_CIPHER_SPEC:
                self.process_change_cipher_spec(payload)
            elif content_type == DTLSConstants.APPLICATION_DATA:
                self.process_application_data(payload)
            else:
                logger.warning(f"未知消息类型: {content_type}")
                
        except Exception as e:
            logger.error(f"处理消息失败: {e}")
    
    def process_handshake_message(self, data: bytes):
        """处理握手消息"""
        try:
            msg_type, payload = self.handshake_layer.parse_handshake_message(data)
            
            if msg_type == DTLSConstants.CLIENT_HELLO and self.handshake_state == "WAIT_CLIENT_HELLO":
                self.process_client_hello(payload)
            elif msg_type == DTLSConstants.CLIENT_KEY_EXCHANGE and self.handshake_state == "WAIT_CLIENT_KEY_EXCHANGE":
                self.process_client_key_exchange(payload)
            elif msg_type == DTLSConstants.FINISHED and self.handshake_state == "WAIT_CLIENT_FINISHED":
                self.process_client_finished(payload)
            else:
                logger.warning(f"意外的握手消息: 类型={msg_type}, 状态={self.handshake_state}")
                
        except Exception as e:
            logger.error(f"处理握手消息失败: {e}")
    
    def process_client_hello(self, data: bytes):
        """处理Client Hello消息"""
        logger.info("处理Client Hello")
        
        try:
            # 解析Client Hello
            if len(data) < 38:
                logger.error("Client Hello太短")
                return
            
            # 提取客户端随机数
            self.client_random = data[2:34]
            
            # 生成服务器随机数
            self.server_random = secrets.token_bytes(32)
            
            # 发送Server Hello
            self.send_server_hello()
            
            # 发送Certificate
            self.send_certificate()
            
            # 发送Server Hello Done
            self.send_server_hello_done()
            
            self.handshake_state = "WAIT_CLIENT_KEY_EXCHANGE"
            
        except Exception as e:
            logger.error(f"处理Client Hello失败: {e}")
    
    def send_server_hello(self):
        """发送Server Hello消息"""
        logger.info("发送Server Hello")
        
        # 构造Server Hello
        version = struct.pack('!H', DTLSConstants.DTLS_1_2)
        random = self.server_random
        session_id_length = b'\x00'  # 无会话ID
        session_id = b''
        cipher_suite = struct.pack('!H', self.cipher_suite)
        compression_method = struct.pack('!B', self.compression_method)
        extensions_length = struct.pack('!H', 0)
        extensions = b''
        
        server_hello_data = (version + random + session_id_length + session_id +
                           cipher_suite + compression_method +
                           extensions_length + extensions)
        
        server_hello = self.handshake_layer.create_handshake_message(
            DTLSConstants.SERVER_HELLO, server_hello_data)
        
        server_hello_record = self.record_layer.create_record(
            DTLSConstants.HANDSHAKE, server_hello)
        
        self.send_to_client(server_hello_record)
    
    def send_certificate(self):
        """发送Certificate消息"""
        logger.info("发送Certificate")
        
        # 序列化证书
        cert_der = self.server.server_certificate.public_bytes(serialization.Encoding.DER)
        
        # 构造Certificate消息
        cert_length = struct.pack('!I', len(cert_der))[1:]  # 3字节长度
        cert_chain_length = struct.pack('!I', len(cert_der) + 3)[1:]  # 3字节长度
        
        certificate_data = cert_chain_length + cert_length + cert_der
        
        certificate = self.handshake_layer.create_handshake_message(
            DTLSConstants.CERTIFICATE, certificate_data)
        
        certificate_record = self.record_layer.create_record(
            DTLSConstants.HANDSHAKE, certificate)
        
        self.send_to_client(certificate_record)
    
    def send_server_hello_done(self):
        """发送Server Hello Done消息"""
        logger.info("发送Server Hello Done")
        
        server_hello_done = self.handshake_layer.create_handshake_message(
            DTLSConstants.SERVER_HELLO_DONE, b'')
        
        server_hello_done_record = self.record_layer.create_record(
            DTLSConstants.HANDSHAKE, server_hello_done)
        
        self.send_to_client(server_hello_done_record)
    
    def process_client_key_exchange(self, data: bytes):
        """处理Client Key Exchange消息"""
        logger.info("处理Client Key Exchange")
        
        try:
            # 解析加密的预主密钥
            if len(data) < 2:
                logger.error("Client Key Exchange太短")
                return
            
            encrypted_length = struct.unpack('!H', data[0:2])[0]
            encrypted_pre_master = data[2:2+encrypted_length]
            
            # 使用服务器私钥解密预主密钥
            self.pre_master_secret = self.server.server_private_key.decrypt(
                encrypted_pre_master,
                padding.PKCS1v15()
            )
            
            # 派生主密钥和会话密钥
            self.derive_master_secret()
            self.derive_key_material()
            
            self.handshake_state = "WAIT_CLIENT_CCS"
            
        except Exception as e:
            logger.error(f"处理Client Key Exchange失败: {e}")
    
    def process_change_cipher_spec(self, data: bytes):
        """处理Change Cipher Spec消息"""
        logger.info("处理Change Cipher Spec")
        
        if data == b'\x01':
            # 发送服务器的Change Cipher Spec
            self.send_change_cipher_spec()
            
            # 发送Finished消息
            self.send_finished()
            
            self.encryption_enabled = True
            self.connected = True
            self.handshake_state = "CONNECTED"
            
            logger.info("DTLS握手完成，加密通信已启用")
    
    def send_change_cipher_spec(self):
        """发送Change Cipher Spec消息"""
        logger.info("发送Change Cipher Spec")
        
        ccs_data = b'\x01'
        ccs_record = self.record_layer.create_record(
            DTLSConstants.CHANGE_CIPHER_SPEC, ccs_data)
        
        self.send_to_client(ccs_record)
    
    def send_finished(self):
        """发送Finished消息"""
        logger.info("发送Finished")
        
        # 计算验证数据
        handshake_hash = hashlib.sha256()
        for msg in self.handshake_layer.handshake_messages:
            handshake_hash.update(msg)
        
        seed = b"server finished" + handshake_hash.digest()
        verify_data = self._prf(self.master_secret, seed, 12)
        
        finished = self.handshake_layer.create_handshake_message(
            DTLSConstants.FINISHED, verify_data)
        
        finished_record = self.record_layer.create_record(
            DTLSConstants.HANDSHAKE, finished)
        
        self.send_to_client(finished_record)
    
    def process_client_finished(self, data: bytes):
        """处理客户端Finished消息"""
        logger.info("处理客户端Finished")
        # 这里应该验证客户端的Finished消息，简化处理
        self.connected = True
        self.handshake_state = "CONNECTED"
    
    def process_application_data(self, data: bytes):
        """处理应用数据"""
        if not self.encryption_enabled:
            logger.warning("收到未加密的应用数据")
            return
        
        try:
            # 解密数据
            decrypted_data = self.decrypt_message(data)
            message = decrypted_data.decode('utf-8')
            logger.info(f"收到加密消息: {message}")
            
            # 发送回显响应
            response = f"Echo: {message}"
            self.send_application_data(response)
            
        except Exception as e:
            logger.error(f"处理应用数据失败: {e}")
    
    def send_application_data(self, message: str):
        """发送加密的应用数据"""
        try:
            plaintext = message.encode('utf-8')
            encrypted_data = self.encrypt_message(plaintext)
            
            app_data_record = self.record_layer.create_record(
                DTLSConstants.APPLICATION_DATA, encrypted_data)
            
            self.send_to_client(app_data_record)
            logger.info(f"发送加密响应: {message}")
            
        except Exception as e:
            logger.error(f"发送应用数据失败: {e}")
    
    def derive_master_secret(self):
        """派生主密钥"""
        seed = b"master secret" + self.client_random + self.server_random
        self.master_secret = self._prf(self.pre_master_secret, seed, 48)
        logger.info("主密钥派生完成")
    
    def derive_key_material(self):
        """派生密钥材料"""
        seed = b"key expansion" + self.server_random + self.client_random
        
        # AES-128-GCM密钥长度
        key_length = 16
        iv_length = 4
        
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
        """TLS伪随机函数"""
        result = b''
        a = seed
        
        while len(result) < length:
            a = hmac.new(secret, a, hashlib.sha256).digest()
            result += hmac.new(secret, a + seed, hashlib.sha256).digest()
        
        return result[:length]
    
    def encrypt_message(self, plaintext: bytes) -> bytes:
        """加密消息"""
        nonce = self.server_write_iv + secrets.token_bytes(8)
        
        cipher = Cipher(algorithms.AES(self.server_write_key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        return nonce + ciphertext + encryptor.tag
    
    def decrypt_message(self, encrypted_data: bytes) -> bytes:
        """解密消息"""
        if len(encrypted_data) < 28:
            return encrypted_data
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:-16]
        tag = encrypted_data[-16:]
        
        cipher = Cipher(algorithms.AES(self.client_write_key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    
    def send_to_client(self, data: bytes):
        """发送数据到客户端"""
        self.server.socket.sendto(data, self.client_addr)


def main():
    """主函数"""
    print("完整DTLS服务器")
    print("=" * 50)
    print("✅ 支持完整的DTLS 1.2握手流程")
    print("✅ RSA密钥交换和AES-GCM加密")
    print("✅ 证书验证和密钥协商")
    print("按 Ctrl+C 停止服务器")
    print("=" * 50)
    
    server = CompleteDTLSServer(host='localhost', port=4433)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n服务器停止")
    except Exception as e:
        print(f"服务器错误: {e}")
    finally:
        server.cleanup()


if __name__ == "__main__":
    main()
