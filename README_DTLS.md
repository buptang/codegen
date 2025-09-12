# Python DTLS 客户端实现

这是一个完整的 Python3 DTLS (Datagram Transport Layer Security) 客户端实现，支持与 DTLS 服务端进行安全协商、交互和加密通信。

## 🚀 功能特性

### 核心功能
- ✅ 完整的 DTLS 1.0 握手流程
- ✅ 客户端证书验证
- ✅ 密钥交换和协商
- ✅ 加密数据传输
- ✅ 会话管理

### TLS/DTLS 扩展支持
- ✅ **SNI (Server Name Indication)** - 服务器名称指示
- ✅ **EC Point Formats** - 椭圆曲线点格式
- ✅ **Supported Groups** - 支持的椭圆曲线组
- ✅ **Signature Algorithms** - 签名算法协商
- ✅ **OCSP Status Request** - 在线证书状态协议
- ✅ **Encrypt-then-MAC** - 先加密后MAC
- ✅ **Extended Master Secret** - 扩展主密钥
- ✅ **Session Ticket** - 会话票据

### 安全特性
- 🔐 支持多种密码套件
- 🔐 RSA 和 ECDSA 签名算法
- 🔐 AES-GCM 加密
- 🔐 完整性验证

## 📁 文件结构

```
├── dtls_client_complete.py    # 完整的DTLS客户端实现
├── dtls_server_complete.py    # 配套的DTLS服务端实现
├── test_dtls_client.py        # 测试脚本
└── README_DTLS.md            # 本文档
```

## 🛠️ 安装要求

```bash
# Python 3.7+
pip install cryptography
```

## 📖 使用方法

### 基本用法

```python
from dtls_client_complete import DTLSClient

# 创建客户端
client = DTLSClient()

# 设置服务器名称（可选，用于SNI扩展）
client.server_name = "example.com"

# 连接到DTLS服务器
success = client.connect('127.0.0.1', 4433)

if success:
    # 发送加密数据
    message = "Hello, DTLS Server!"
    client.send_data(message.encode('utf-8'))
    
    # 接收响应
    response = client.receive_data()
    if response:
        print(f"收到响应: {response.decode('utf-8')}")
    
    # 清理资源
    client.cleanup()
```

### 高级配置

```python
from dtls_client_complete import DTLSClient

client = DTLSClient()

# 配置连接参数
client.server_name = "secure.example.com"  # SNI扩展
client.timeout = 10.0                      # 超时时间

# 连接并处理
try:
    if client.connect('secure.example.com', 4433):
        # 执行安全通信
        data = client.send_and_receive(b"GET /api/data HTTP/1.1\r\n\r\n")
        print(f"API响应: {data}")
except Exception as e:
    print(f"连接失败: {e}")
finally:
    client.cleanup()
```

## 🧪 运行测试

```bash
# 运行完整测试套件
python test_dtls_client.py

# 单独测试扩展功能
python -c "from test_dtls_client import test_extensions; test_extensions()"
```

## 🔧 支持的扩展详解

### 1. SNI (Server Name Indication)
允许客户端指定要连接的服务器名称，支持虚拟主机。

```python
client.server_name = "api.example.com"
```

### 2. EC Point Formats
指定支持的椭圆曲线点格式：
- Uncompressed (0x00)

### 3. Supported Groups
支持的椭圆曲线组：
- P-256 (secp256r1)
- P-384 (secp384r1) 
- P-521 (secp521r1)
- X25519

### 4. Signature Algorithms
支持的签名算法：
- RSA-PKCS1-SHA256
- RSA-PKCS1-SHA384
- RSA-PKCS1-SHA512
- ECDSA-secp256r1-SHA256
- ECDSA-secp384r1-SHA384

### 5. 其他扩展
- **OCSP Status Request**: 在线证书状态检查
- **Encrypt-then-MAC**: 提高安全性的MAC计算方式
- **Extended Master Secret**: 增强的主密钥派生
- **Session Ticket**: 支持会话恢复

## 🏗️ 架构设计

### 类结构
```
DTLSConstants          # 协议常量定义
├── 内容类型
├── DTLS版本
├── 握手消息类型
├── 密码套件
└── 扩展类型

DTLSRecord            # DTLS记录层
├── create_record()   # 创建DTLS记录
└── parse_record()    # 解析DTLS记录

DTLSClient           # DTLS客户端主类
├── connect()        # 建立连接
├── send_data()      # 发送数据
├── receive_data()   # 接收数据
├── create_*_extension()  # 各种扩展创建方法
└── cleanup()        # 清理资源
```

### 握手流程
```
客户端                    服务端
   |                        |
   |--- Client Hello ------>|  (包含所有扩展)
   |                        |
   |<--- Server Hello ------|  (选择密码套件)
   |<--- Certificate ------|  (服务器证书)
   |<-- Server Hello Done --|
   |                        |
   |-- Client Key Exchange->|  (密钥交换)
   |-- Change Cipher Spec ->|  (切换到加密模式)
   |------ Finished ------>|  (握手完成)
   |                        |
   |<- Change Cipher Spec --|
   |<------ Finished ------|
   |                        |
   |<==== 加密通信 ====>|
```

## 🐛 故障排除

### 常见问题

1. **连接超时**
   ```python
   client.timeout = 30.0  # 增加超时时间
   ```

2. **证书验证失败**
   ```python
   # 检查服务器证书是否有效
   # 确保时间同步正确
   ```

3. **握手失败**
   ```python
   # 检查支持的密码套件
   # 验证扩展兼容性
   ```

### 调试模式

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# 现在会显示详细的握手过程
client = DTLSClient()
client.connect('127.0.0.1', 4433)
```

## 🔒 安全注意事项

1. **证书验证**: 在生产环境中务必验证服务器证书
2. **密码套件**: 使用强加密算法，避免弱密码套件
3. **随机数**: 确保随机数生成器的安全性
4. **会话管理**: 适当管理会话生命周期
5. **错误处理**: 妥善处理各种异常情况

## 📝 许可证

本项目采用 MIT 许可证。

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📞 联系方式

如有问题或建议，请通过以下方式联系：
- GitHub Issues
- Email: [您的邮箱]

---

**注意**: 这是一个教育和测试用途的实现。在生产环境中使用前，请进行充分的安全审计和测试。

