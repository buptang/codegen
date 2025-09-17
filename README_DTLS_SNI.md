# DTLS 1.0 + SNI 实现

这是一个完整的 DTLS 1.0 客户端和服务器实现，支持 SNI (Server Name Indication) 扩展。

## 🚀 主要特性

### DTLS 1.0 协议支持
- ✅ 完整的 DTLS 1.0 握手流程
- ✅ Hello Verify Request 防重放攻击
- ✅ RSA 密钥交换
- ✅ AES-128-GCM 加密套件
- ✅ 数据完整性验证

### SNI 扩展支持
- ✅ 客户端 SNI 扩展生成
- ✅ 服务器 SNI 扩展解析
- ✅ 支持 hostname 类型的服务器名称
- ✅ 灵活的服务器名称配置

## 📁 文件结构

```
├── dtls_client_complete.py    # DTLS 1.0 客户端实现
├── dtls_server_with_hvr.py    # DTLS 1.0 服务器实现
├── test_dtls_sni.py          # SNI 功能测试
├── demo_dtls_sni.py          # 演示脚本
└── README_DTLS_SNI.md        # 本文档
```

## 🔧 使用方法

### 基本客户端使用

```python
from dtls_client_complete import CompleteDTLSClient

# 创建DTLS客户端（使用默认SNI）
client = CompleteDTLSClient(
    server_host='localhost',
    server_port=4433
)

# 建立连接
if client.connect():
    # 发送加密数据
    client.send_data(b"Hello, DTLS Server!")
    
    # 接收响应
    response = client.receive_data()
    print(f"收到: {response}")
    
    # 关闭连接
    client.close()
```

### 带自定义SNI的客户端

```python
from dtls_client_complete import CompleteDTLSClient

# 创建带自定义SNI的DTLS客户端
client = CompleteDTLSClient(
    server_host='192.168.1.100',      # 实际服务器IP
    server_port=4433,
    server_name='secure.example.com'   # SNI服务器名称
)

if client.connect():
    print("DTLS连接建立成功，SNI已发送")
    # ... 进行加密通信
```

### 服务器使用

```python
from dtls_server_with_hvr import DTLSServer

# 创建DTLS服务器
server = DTLSServer(host='localhost', port=4433)

# 启动服务器（会自动解析客户端SNI）
server.start_server()
```

## 🧪 测试和演示

### 运行SNI功能测试

```bash
python test_dtls_sni.py
```

这个测试会验证：
- 默认SNI行为
- 自定义SNI服务器名称
- 不同域名格式的SNI

### 运行演示脚本

```bash
python demo_dtls_sni.py
```

演示脚本展示了完整的DTLS 1.0 + SNI通信流程。

## 🔍 技术细节

### DTLS 1.0 版本

- **版本号**: `0xFEFF`
- **与DTLS 1.2的区别**: 使用不同的版本标识符
- **兼容性**: 支持标准的DTLS 1.0握手流程

### SNI 扩展格式

SNI扩展遵循RFC 6066标准：

```
Extension Type: 0x0000 (server_name)
Extension Length: variable
Server Name List Length: 2 bytes
  Server Name Type: 0x00 (host_name)
  Server Name Length: 2 bytes
  Server Name: variable (UTF-8 encoded)
```

### 实现细节

1. **客户端SNI生成**:
   - `create_sni_extension()` 方法构造SNI扩展
   - 自动编码服务器名称为UTF-8
   - 正确计算所有长度字段

2. **服务器SNI解析**:
   - `parse_extensions()` 方法解析所有扩展
   - `parse_sni_extension()` 专门处理SNI扩展
   - 提取并验证服务器名称

3. **错误处理**:
   - 完整的长度验证
   - 异常捕获和日志记录
   - 优雅的降级处理

## 📊 日志输出示例

```
2024-01-15 10:30:15 - INFO - 创建DTLS客户端 (SNI: demo.example.com)
2024-01-15 10:30:15 - INFO - 添加SNI扩展，服务器名称: demo.example.com
2024-01-15 10:30:16 - INFO - 解析SNI扩展: demo.example.com
2024-01-15 10:30:16 - INFO - SNI服务器名称: demo.example.com
2024-01-15 10:30:16 - INFO - DTLS握手成功! 连接已建立
```

## 🔒 安全特性

- **防重放攻击**: Hello Verify Request机制
- **数据加密**: AES-128-GCM加密套件
- **完整性保护**: AEAD认证加密
- **密钥交换**: RSA公钥加密
- **随机性**: 使用`secrets`模块生成随机数

## 🛠️ 依赖要求

```python
# 标准库
import socket
import struct
import secrets
import hashlib
import hmac
import threading
import time
import logging
from typing import Dict, Any, Optional

# 第三方库
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime
```

## 📝 注意事项

1. **证书验证**: 当前实现使用自签名证书，生产环境需要使用有效的CA证书
2. **错误处理**: 实现了基本的错误处理，可根据需要扩展
3. **性能优化**: 适合测试和学习，生产使用可能需要性能优化
4. **协议完整性**: 实现了核心DTLS功能，某些高级特性可能需要补充

## 🤝 贡献

欢迎提交问题报告和改进建议！

## 📄 许可证

本项目仅供学习和研究使用。

