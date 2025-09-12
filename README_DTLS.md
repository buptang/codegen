# Python DTLS 客户端实现

这是一个使用Python 3实现的完整DTLS (Datagram Transport Layer Security) 1.2客户端，支持与DTLS服务端进行安全的握手协商和加密通信。

## 🚀 功能特性

### ✅ 完整的DTLS 1.2协议支持
- **标准握手流程**: Client Hello → Hello Verify Request → Client Hello (with Cookie) → Server Hello → Certificate → Server Key Exchange → Server Hello Done → Client Key Exchange + Change Cipher Spec + Finished → Change Cipher Spec + Finished
- **Cookie验证**: 支持DTLS特有的Hello Verify Request和Cookie机制
- **消息重传**: 实现DTLS的可靠性保证机制

### 🔐 密码学功能
- **多种密码套件**: 支持RSA、ECDHE密钥交换
- **加密算法**: AES-128-GCM, AES-256-GCM, AES-128-CBC, AES-256-CBC
- **哈希算法**: SHA-256, SHA-384
- **椭圆曲线**: secp256r1, secp384r1, secp521r1

### 🛡️ 安全特性
- **证书验证**: X.509证书链验证
- **Server Key Exchange**: 支持ECDHE临时密钥交换
- **完美前向保密**: 通过ECDHE实现
- **消息认证**: HMAC和AEAD模式

### 🔧 实现亮点
- **模块化设计**: 分离记录层、握手层和应用层
- **错误处理**: 完善的异常处理和日志记录
- **扩展支持**: SNI、椭圆曲线、签名算法等扩展
- **优化握手**: 合并客户端消息发送以提高效率

## 📁 文件结构

```
├── dtls_client_complete.py    # 完整DTLS客户端实现
├── test_dtls_client.py        # 测试脚本
└── README_DTLS.md            # 本文档
```

## 🏗️ 架构设计

### 核心类结构

```python
class DTLSConstants:
    """DTLS协议常量定义"""
    
class DTLSRecord:
    """DTLS记录层实现"""
    
class DTLSHandshake:
    """DTLS握手层实现"""
    
class DTLSClient:
    """DTLS客户端主类"""
```

### 关键方法

#### 握手流程
- `handshake()`: 执行完整DTLS握手
- `parse_server_hello()`: 解析服务器Hello消息
- `parse_certificate()`: 解析服务器证书
- `parse_server_key_exchange()`: 解析服务器密钥交换消息

#### 密钥管理
- `generate_keys()`: 生成主密钥和会话密钥
- `create_client_key_exchange()`: 创建客户端密钥交换消息
- `create_finished_message()`: 创建Finished消息

#### 数据传输
- `send_application_data()`: 发送加密应用数据
- `receive_application_data()`: 接收解密应用数据

## 🚀 使用方法

### 基本使用

```python
from dtls_client_complete import DTLSClient

# 创建DTLS客户端
client = DTLSClient(
    server_host='localhost',
    server_port=4433,
    server_name='example.com'
)

try:
    # 执行握手
    if client.handshake():
        print("握手成功！")
        
        # 发送数据
        message = "Hello, DTLS Server!"
        client.send_application_data(message.encode())
        
        # 接收响应
        response = client.receive_application_data()
        print(f"收到响应: {response.decode()}")
        
finally:
    client.close()
```

### 运行测试

```bash
# 运行测试脚本
python3 test_dtls_client.py

# 查看帮助
python3 test_dtls_client.py --help
```

## 🧪 测试环境

### 使用OpenSSL测试服务器

```bash
# 1. 生成测试证书
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj "/CN=localhost"

# 2. 启动DTLS服务器
openssl s_server -dtls1_2 -accept 4433 -cert server.crt -key server.key

# 3. 在另一个终端运行客户端
python3 test_dtls_client.py
```

### 支持的测试场景

1. **基本连接测试**: 验证握手流程
2. **证书验证测试**: 测试X.509证书处理
3. **密钥交换测试**: 验证ECDHE密钥协商
4. **加密通信测试**: 测试应用数据加密传输
5. **错误处理测试**: 验证异常情况处理

## 🔍 协议实现细节

### DTLS握手流程

```
客户端                    服务器
   |                        |
   |--- Client Hello ------>|
   |<-- Hello Verify Req ---|
   |--- Client Hello ------>|  (with Cookie)
   |<----- Server Hello ----|
   |<----- Certificate -----|
   |<-- Server Key Exch. ---|  (ECDHE)
   |<-- Server Hello Done --|
   |                        |
   |-- Client Key Exch. --->|
   |-- Change Cipher Spec ->|
   |------ Finished ------->|
   |<- Change Cipher Spec --|
   |<------ Finished -------|
   |                        |
   |<==== 加密通信 ========>|
```

### 新增功能说明

#### Server Key Exchange处理
- 解析椭圆曲线参数
- 提取服务器临时公钥
- 验证数字签名
- 支持多种椭圆曲线

#### 优化的消息发送
- 将Client Key Exchange、Change Cipher Spec、Finished消息合并发送
- 减少网络往返次数
- 提高握手效率

## 📋 依赖要求

```python
# 标准库
import socket
import struct
import hashlib
import hmac
import secrets
import logging
import datetime

# 第三方库
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
```

## 🔧 配置选项

### 支持的密码套件
- `TLS_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- `TLS_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_RSA_WITH_AES_256_CBC_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`
- `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384`

### 支持的扩展
- Server Name Indication (SNI)
- EC Point Formats
- Supported Elliptic Curves
- Signature Algorithms
- OCSP Status Request
- Encrypt-then-MAC
- Extended Master Secret
- Session Ticket

## 🐛 故障排除

### 常见问题

1. **连接被拒绝**
   - 确保DTLS服务器正在运行
   - 检查端口号是否正确
   - 验证防火墙设置

2. **握手失败**
   - 检查密码套件兼容性
   - 验证证书有效性
   - 确认协议版本支持

3. **证书验证错误**
   - 检查证书链完整性
   - 验证证书有效期
   - 确认主机名匹配

### 调试技巧

```python
# 启用详细日志
logging.basicConfig(level=logging.DEBUG)

# 查看握手消息
client = DTLSClient(server_host='localhost', server_port=4433)
client.handshake()  # 查看日志输出
```

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进这个DTLS客户端实现！

### 开发环境设置

```bash
# 克隆仓库
git clone <repository-url>
cd dtls-client

# 安装依赖
pip3 install cryptography

# 运行测试
python3 test_dtls_client.py
```

## 📄 许可证

本项目采用MIT许可证，详见LICENSE文件。

## 🙏 致谢

感谢所有为DTLS协议标准化和Python密码学库开发做出贡献的开发者们！

---

**注意**: 这是一个教育和测试用途的DTLS客户端实现。在生产环境中使用前，请进行充分的安全审计和测试。

