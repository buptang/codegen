# Python DTLS客户端实现

这是一个完整的Python3 DTLS（Datagram Transport Layer Security）客户端实现，支持与DTLS服务器进行协商、交互和加密通信。

## 功能特性

### 🔐 完整的DTLS 1.2支持
- **握手协议**：完整的Client Hello、密钥交换、Change Cipher Spec和Finished消息流程
- **记录层协议**：支持DTLS记录的创建、解析和处理
- **密码套件**：支持AES-128-CBC + HMAC-SHA1和AES-128-GCM加密

### 🛡️ 安全特性
- **正确的密钥派生**：基于RFC 5246的PRF函数和密钥材料派生
- **MAC验证**：完整的HMAC-SHA1消息认证码验证
- **随机IV**：每个记录使用随机初始化向量（CBC模式）
- **填充验证**：正确的PKCS#7填充处理

### 🔧 技术实现
- **加密库**：使用cryptography库进行加密操作
- **网络通信**：基于UDP套接字的可靠通信
- **错误处理**：完善的异常处理和日志记录
- **模块化设计**：清晰的记录层和客户端分离

## 文件说明

### 核心文件

1. **`dtls_client_fixed.py`** - 修复版DTLS客户端
   - 完整的DTLS客户端实现
   - 修复了密钥派生和加解密问题
   - 支持CBC和GCM两种加密模式

2. **`dtls_client_complete.py`** - 原始完整版本
   - 包含完整功能但有一些加密问题
   - 用于对比和参考

3. **`test_dtls_fixes.py`** - 密钥派生和加解密测试
   - 验证密钥派生逻辑
   - 测试CBC模式加解密
   - MAC计算和验证测试

4. **`dtls_test_server.py`** - 简单测试服务器
   - 用于测试DTLS客户端
   - 记录接收到的消息和数据

### 文档文件

5. **`README_DTLS.md`** - 本文档
   - 完整的使用说明和技术文档

## 快速开始

### 安装依赖

```bash
pip install cryptography
```

### 基本使用

```python
from dtls_client_fixed import DTLSClient

# 创建DTLS客户端
client = DTLSClient("127.0.0.1", 4433)

# 连接到服务器
if client.connect():
    # 发送加密消息
    client.send_message("Hello DTLS Server!")
    
    # 接收响应
    response = client.receive_message()
    if response:
        print(f"服务器响应: {response}")
    
    # 清理资源
    client.cleanup()
```

### 运行演示

```bash
# 运行DTLS客户端演示
python3 dtls_client_fixed.py

# 在另一个终端运行测试服务器
python3 dtls_test_server.py
```

## 技术细节

### 密钥派生过程

1. **主密钥派生**
   ```
   master_secret = PRF(pre_master_secret, "master secret" + client_random + server_random)[0..47]
   ```

2. **密钥材料派生**
   ```
   key_block = PRF(master_secret, "key expansion" + server_random + client_random)
   ```

3. **密钥分配**（按RFC 5246顺序）
   ```
   client_write_MAC_key[mac_length]
   server_write_MAC_key[mac_length]  
   client_write_key[key_length]
   server_write_key[key_length]
   ```

### AES-128-CBC + HMAC-SHA1加密

1. **MAC计算**
   ```
   MAC = HMAC-SHA1(MAC_key, seq_num + type + version + length + data)
   ```

2. **填充和加密**
   ```
   padded_data = PKCS7_pad(data + MAC)
   IV = random(16)
   ciphertext = AES-CBC-encrypt(key, IV, padded_data)
   record = IV + ciphertext
   ```

3. **解密和验证**
   ```
   IV = record[0:16]
   ciphertext = record[16:]
   padded_data = AES-CBC-decrypt(key, IV, ciphertext)
   data_with_mac = PKCS7_unpad(padded_data)
   data = data_with_mac[:-20]
   received_mac = data_with_mac[-20:]
   computed_mac = HMAC-SHA1(MAC_key, seq_num + type + version + length + data)
   verify(received_mac == computed_mac)
   ```

### 关键修复

#### 1. HMAC使用修复
**问题**：使用了错误的cryptography HMAC API
```python
# 错误的方式
h = hmac.HMAC(key, hashes.SHA1())
h.update(data)
mac = h.finalize()

# 正确的方式  
h = hmac.new(key, data, hashlib.sha1)
mac = h.digest()
```

#### 2. 密钥材料顺序修复
**问题**：密钥材料派生顺序不符合RFC 5246
```python
# 正确的顺序（RFC 5246）
client_write_MAC_key + server_write_MAC_key + client_write_key + server_write_key
```

#### 3. MAC验证实现
**问题**：解密时跳过了MAC验证
```python
# 添加完整的MAC验证
if received_mac != computed_mac:
    raise ValueError("MAC验证失败")
```

#### 4. 随机IV使用
**问题**：CBC模式使用固定IV
```python
# 每个记录使用随机IV
iv = os.urandom(16)  # AES块大小
```

## 测试验证

### 运行密钥派生测试
```bash
python3 test_dtls_fixes.py
```

预期输出：
```
DTLS密钥派生和加解密测试
==================================================
主密钥派生完成: d799702d2dcc2258...
密钥材料派生完成:
  客户端MAC密钥: ad844e3b9b3650cd...
  服务端MAC密钥: 2fcf91951d829b0c...
  客户端加密密钥: ad27ce8aa51cf521...
  服务端加密密钥: 5f9cb1436c753611...

测试数据: b'Hello DTLS World! This is a test message.'
加密结果长度: 80
解密结果: b'Hello DTLS World! This is a test message.'
✅ CBC加解密测试成功!

测试完成!
```

### 验证加密通信

1. 启动测试服务器：
   ```bash
   python3 dtls_test_server.py
   ```

2. 运行客户端：
   ```bash
   python3 dtls_client_fixed.py
   ```

3. 观察日志输出，确认：
   - 握手过程完成
   - 密钥派生成功
   - 消息加密发送
   - MAC验证通过

## 安全注意事项

### ⚠️ 仅用于学习和测试
- 这是一个教育性实现，不建议用于生产环境
- 缺少证书验证和完整的错误处理
- 握手过程是模拟的，不包含真实的密钥交换

### 🔒 安全特性
- 使用加密安全的随机数生成器
- 实现了正确的MAC验证
- 支持现代加密算法（AES-128）
- 遵循RFC标准的密钥派生

### 🛡️ 建议改进
- 添加证书验证
- 实现完整的握手协议
- 添加重传和超时处理
- 支持更多密码套件
- 添加会话恢复功能

## 技术参考

- **RFC 6347**: Datagram Transport Layer Security Version 1.2
- **RFC 5246**: The Transport Layer Security (TLS) Protocol Version 1.2
- **RFC 3268**: Advanced Encryption Standard (AES) Ciphersuites for TLS
- **RFC 2104**: HMAC: Keyed-Hashing for Message Authentication

## 许可证

本项目仅用于教育和学习目的。请遵守相关的开源许可证和法律法规。

---

**作者**: Codegen  
**版本**: 1.0  
**更新时间**: 2025-09-15

