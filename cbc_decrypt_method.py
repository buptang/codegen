def _decrypt_data_cbc(self, content_type: int, encrypted_data: bytes) -> bytes:
    """使用AES-128-CBC + HMAC-SHA1解密数据"""
    if not hasattr(self, 'cipher_algorithm') or not self.cipher_algorithm:
        return encrypted_data
    
    from cryptography.hazmat.primitives import hashes, hmac, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    import struct
    
    if len(encrypted_data) < 16:
        raise ValueError("加密数据太短，无法包含IV")
    
    # 提取IV和密文
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # 解密（使用server_write_key解密来自服务端的数据）
    decrypt_key = self.server_write_key if hasattr(self, 'server_write_key') and self.server_write_key else self.client_write_key
    mac_key = self.server_write_mac_key if hasattr(self, 'server_write_mac_key') and self.server_write_mac_key else self.client_write_mac_key
    
    cipher = Cipher(algorithms.AES(decrypt_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    # 移除填充
    unpadder = padding.PKCS7(128).unpadder()
    try:
        data_with_mac = unpadder.update(padded_data) + unpadder.finalize()
    except Exception as e:
        logger.error(f"填充移除失败: {e}")
        raise ValueError("填充验证失败")
    
    # 分离数据和MAC
    if len(data_with_mac) < 20:
        raise ValueError("解密数据太短，无法包含MAC")
    
    data = data_with_mac[:-20]
    received_mac = data_with_mac[-20:]
    
    # 验证MAC
    seq_num_8bytes = struct.pack("!Q", self.sequence_number)
    mac_data = (seq_num_8bytes +
               struct.pack("!BHH", content_type, DTLSConstants.DTLS_1_0, len(data)) +
               data)
    
    if mac_key:
        h = hmac.HMAC(mac_key, hashes.SHA1())
        h.update(mac_data)
        computed_mac = h.finalize()
        
        if received_mac != computed_mac:
            logger.error(f"MAC验证失败")
            raise ValueError("MAC验证失败")
    
    logger.debug(f"AES-CBC解密成功，数据长度: {len(data)}")
    return data

