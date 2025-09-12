# DTLS客户端实现

这是一个用Python3实现的DTLS（Datagram Transport Layer Security）客户端，支持与DTLS服务端进行协商、交互和加密通信。

## 功能特性

### 🔐 支持的加密模式

1. **AES-128-CBC + HMAC-SHA1** (TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA)
   - 密码套件ID: `0xc013`
   - 使用AES-128-CBC进行对称加密
   - 使用HMAC-SHA1进行消息认证
   - 支持PKCS#7填充

2. **AES-128-GCM** (TLS_RSA_WITH_AES_128_GCM_SHA256)
   - 密码套件ID: `0x9c`
   - 使用AES-128-GCM进行认证加密
   - 内置消息认证，无需额外MAC

3. **AES-256-GCM** (默认)
   - 使用AES-256-GCM进行认证加密
   - 更高的安全强度

### 🚀 核心功能

- ✅ DTLS握手协议实现
- ✅ 多种密码套件支持
- ✅ 密钥派生和管理
- ✅ 记录层加密/解密
- ✅ 应用数据传输
- ✅ 错误处理和日志记录

## 文件结构

```
├── dtls_client_complete.py    # 完整的DTLS客户端实现
├── dtls_client_example.py     # 使用示例和测试
├── test_dtls_cbc.py          # CBC模式专项测试
└── README_DTLS.md            # 本文档
```

## 快速开始

### 1. 安装依赖

```bash
pip install cryptography
```

### 2. 运行示例

```bash
# 运行加密模式测试
python3 dtls_client_example.py

# 运行CBC模式专项测试
python3 test_dtls_cbc.py
```

### 3. 基本使用

```python
from dtls_client_complete import CompleteDTLSClient

# 创建DTLS客户端
client = CompleteDTLSClient()

# 连接到DTLS服务器
success = client.connect("127.0.0.1", 4433)

if success:
    # 发送应用数据
    client.send_application_data(b"Hello, DTLS Server!")
    
    # 关闭连接
    client.close()
```

## 技术实现

### 密钥派生

实现了标准的TLS密钥派生过程：

```python
def derive_key_material(self):
    """派生密钥材料"""
    seed = b"key expansion" + self.server_random + self.client_random
    
    if self.cipher_suite == DTLSConstants.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
        # CBC模式需要MAC密钥
        key_material_length = 2 * (mac_length + key_length + iv_length)
    else:
        # GCM模式不需要MAC密钥
        key_material_length = 2 * (key_length + iv_length)
```

### CBC模式加密

```python
def _encrypt_data_cbc(self, content_type: int, data: bytes) -> bytes:
    """AES-128-CBC + HMAC-SHA1加密"""
    # 1. 计算HMAC-SHA1
    mac = hmac.HMAC(self.client_write_mac_key, hashes.SHA1())
    
    # 2. 添加PKCS#7填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data + mac) + padder.finalize()
    
    # 3. AES-CBC加密
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encrypted = cipher.encryptor().update(padded_data)
    
    return iv + encrypted
```

### GCM模式加密

```python
def _encrypt_data_gcm(self, content_type: int, data: bytes) -> bytes:
    """AES-GCM认证加密"""
    nonce = self.client_write_iv + struct.pack("!Q", self.sequence_number)
    aad = struct.pack("!Q", self.sequence_number)[2:] + ...
    
    encrypted_data = self.cipher.encrypt(nonce, data, aad)
    return encrypted_data
```

## 性能对比

根据测试结果，不同加密模式的性能对比：

| 加密模式 | 原始数据 | 加密后大小 | 开销 | 特点 |
|---------|---------|-----------|------|------|
| AES-128-CBC + HMAC-SHA1 | 38字节 | 80字节 | 42字节 | 需要填充，开销较大 |
| AES-128-GCM | 38字节 | 54字节 | 16字节 | 认证加密，开销较小 |

## 支持的密码套件

| 密码套件ID | 名称 | 描述 |
|-----------|------|------|
| `0xc013` | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA | ECDHE密钥交换 + RSA签名 + AES-128-CBC + HMAC-SHA1 |
| `0x9c` | TLS_RSA_WITH_AES_128_GCM_SHA256 | RSA密钥交换 + AES-128-GCM |

## 日志输出

程序提供详细的日志输出，包括：

- 🔑 密钥派生过程
- 🔒 加密模式选择
- 📊 加密性能统计
- ⚠️ 错误和警告信息

```
2025-09-12 08:25:26,516 - INFO - CBC密钥材料派生完成 - MAC密钥: 20字节, 加密密钥: 16字节, IV: 16字节
2025-09-12 08:25:26,520 - INFO - 记录层加密已启用 (AES-128-CBC + HMAC-SHA1)
```

## 安全注意事项

1. **密钥管理**: 实现了标准的TLS密钥派生过程
2. **随机数生成**: 使用`os.urandom()`生成安全的随机数
3. **填充攻击防护**: 正确实现PKCS#7填充
4. **重放攻击防护**: 使用序列号防止重放攻击

## 扩展性

代码设计具有良好的扩展性：

- 🔧 易于添加新的密码套件
- 🔧 支持自定义加密算法
- 🔧 模块化的记录层设计
- 🔧 完整的错误处理机制

## 测试

运行测试以验证功能：

```bash
# 基本功能测试
python3 dtls_client_example.py

# CBC模式详细测试
python3 test_dtls_cbc.py
```

## 依赖项

- Python 3.6+
- cryptography >= 3.0

## 许可证

本项目采用MIT许可证。

## 贡献

欢迎提交Issue和Pull Request来改进这个DTLS客户端实现。

---

*这个DTLS客户端实现提供了完整的加密通信功能，支持多种加密模式，适用于需要安全UDP通信的应用场景。*

