# DTLS客户端实现

这是一个用Python3实现的DTLS（Datagram Transport Layer Security）客户端，支持与DTLS服务端进行协商、交互和加密通信。

## 功能特性

### 🔐 真正的DTLS over UDP协议
- ✅ 使用pyDTLS库实现标准DTLS协议
- ✅ 基于UDP传输，支持数据报加密
- ✅ 完整的DTLS握手和会话管理
- ✅ 抓包显示为DTLS协议而非TLS

### 🛡️ 安全特性
- ✅ 自动生成自签名证书
- ✅ 加密消息传输
- ✅ 证书验证选项

### 📡 通信功能
- ✅ 连接测试和ping功能
- ✅ 交互式会话模式
- ✅ 文件传输支持
- ✅ 完整的错误处理和日志记录
- ✅ 上下文管理器支持

### 🔧 协议对比
| 特性 | 真正DTLS | UDP模拟 | TLS over TCP |
|------|----------|---------|--------------|
| 传输协议 | UDP | UDP | TCP |
| 加密方式 | DTLS | 无加密 | TLS |
| 抓包显示 | DTLS | UDP | TLS |
| 可靠性 | 中等 | 低 | 高 |
| 延迟 | 低 | 最低 | 中等 |

## 安装依赖

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install pyopenssl cryptography pyDTLS
```

## 文件说明

- **`dtls_client.py`** - 智能DTLS客户端
  - 优先使用真正的DTLS over UDP（需要pyDTLS库）
  - 自动回退到UDP模拟模式（无需额外依赖）
- **`dtls_client_pure.py`** - 纯DTLS实现
  - 专门使用pyDTLS库实现真正的DTLS协议
  - 提供文件传输等高级功能
- **`dtls_client_simple.py`** - 简化版DTLS客户端
  - 无需pyDTLS库，避免OpenSSL依赖问题
  - 使用UDP模拟DTLS协议
  - 适用于有依赖问题的环境
- **`dtls_server_test.py`** - 增强测试服务器
  - 支持TCP/UDP双模式
  - UDP模式支持真正的DTLS协议
- **`run_test.py`** - 自动化测试脚本
- **`requirements.txt`** - 依赖包列表

## 使用方法

### 1. 启动测试服务器

```bash
python dtls_server_test.py
```

### 2. 运行DTLS客户端

#### 使用基础版本（推荐）：
```bash
python dtls_client.py
```

#### 使用纯DTLS版本：
```bash
python dtls_client_pure.py
```

### 3. 编程接口使用

```python
from dtls_client import DTLSClient

# 创建客户端
with DTLSClient(server_host='localhost', server_port=4433) as client:
    # 连接到服务器
    if client.connect():
        # 发送消息
        client.send_message("Hello, DTLS Server!")
        
        # 接收响应
        response = client.receive_message()
        print(f"服务器响应: {response}")
        
        # 执行ping测试
        results = client.ping_test(count=5)
        
        # 启动交互式会话
        client.start_interactive_session()
```

## API文档

### DTLSClient类

#### 初始化
```python
DTLSClient(server_host='localhost', server_port=4433)
```

#### 主要方法

- `connect(timeout=10.0)` - 连接到DTLS服务器
- `send_message(message)` - 发送加密消息
- `receive_message(buffer_size=4096)` - 接收加密消息
- `send_and_receive(message, timeout=5.0)` - 发送消息并等待响应
- `ping_test(count=3)` - 执行连接测试
- `start_interactive_session()` - 启动交互式会话
- `cleanup()` - 清理资源

## 配置选项

### 证书配置
客户端会自动生成自签名证书，也可以手动指定：

```python
client.cert_file = "my_cert.pem"
client.key_file = "my_key.pem"
```

### SSL上下文配置
可以自定义SSL上下文设置：

```python
context = client.setup_ssl_context(verify_mode=ssl.CERT_REQUIRED)
```

## 安全注意事项

1. **证书验证**: 生产环境中应启用证书验证
2. **密钥管理**: 妥善保管私钥文件
3. **网络安全**: 确保网络连接的安全性
4. **日志安全**: 避免在日志中记录敏感信息

## 故障排除

### 快速测试

使用自动测试脚本：

```bash
python run_test.py
```

这个脚本会：
- ✅ 自动检查依赖文件
- ✅ 找到可用端口
- ✅ 启动测试服务器
- ✅ 测试客户端连接
- ✅ 提供详细的错误信息

### 常见问题

#### 1. **[Errno 111] Connection refused**

**原因**: 没有DTLS服务器在运行

**解决方案**:
```bash
# 方法1: 使用自动测试
python run_test.py

# 方法2: 手动启动服务器
# 终端1: 启动服务器
python dtls_server_test.py

# 终端2: 运行客户端
python dtls_client.py
```

#### 2. **端口被占用**

**解决方案**:
```bash
# 使用不同端口启动服务器
python dtls_server_test.py --port 5433

# 或者找到占用端口的进程
lsof -i :4433  # Linux/Mac
netstat -ano | findstr :4433  # Windows
```

#### 3. **证书错误**

**解决方案**:
```bash
# 删除旧证书文件
rm *.pem

# 重新运行程序，会自动生成新证书
python dtls_client.py
```

#### 4. **依赖问题**

**解决方案**:
```bash
# 安装所有依赖
pip install -r requirements.txt

# 或者单独安装
pip install pyopenssl cryptography pyDTLS
```

#### 5. **IP地址格式错误**

如果遇到 `value must be an instance of ipaddress.IPv4Address` 错误：

**解决方案**: 已在最新版本中修复，确保使用最新代码。

#### 6. **OpenSSL库缺失错误**

如果遇到 `libcrypto.so.1.1: cannot open shared object file` 错误：

**自动修复**:
```bash
python fix_openssl.py
```

**手动解决方案**:
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install libssl1.1 libssl-dev

# CentOS/RHEL/Fedora
sudo yum install compat-openssl11  # 或 sudo dnf install compat-openssl11

# 或者使用简化版本（无需pyDTLS）
python dtls_client_simple.py
```

### 调试模式

启用详细日志：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 手动测试步骤

1. **启动服务器**:
```bash
# TCP模式（推荐）
python dtls_server_test.py --mode tcp --port 4433

# UDP模式
python dtls_server_test.py --mode udp --port 4433
```

2. **运行客户端**:
```bash
# 基础版本
python dtls_client.py

# 纯DTLS版本
python dtls_client_pure.py
```

3. **验证连接**:
   - 查看服务器日志确认连接建立
   - 在客户端发送测试消息
   - 确认消息正确传输

### 网络诊断

```bash
# 检查端口是否开放
telnet localhost 4433

# 检查进程是否运行
ps aux | grep dtls

# 检查网络连接
netstat -tlnp | grep 4433
```

## 示例场景

### 1. 简单消息通信
```python
client = DTLSClient()
if client.connect():
    client.send_message("Hello World")
    response = client.receive_message()
    print(response)
```

### 2. 批量数据传输
```python
client = DTLSClient()
if client.connect():
    for i in range(100):
        message = f"Message {i}"
        response = client.send_and_receive(message)
        print(f"Sent: {message}, Received: {response}")
```

### 3. 文件传输（纯DTLS版本）
```python
from dtls_client_pure import DTLSClientPure

client = DTLSClientPure()
if client.connect():
    client.send_file("test_file.txt")
```

## 性能优化

- 使用连接池减少握手开销
- 调整缓冲区大小优化传输性能
- 启用数据压缩减少网络流量
- 合理设置超时时间

## 许可证

本项目采用MIT许可证。

## 贡献

欢迎提交Issue和Pull Request来改进这个项目。

## 更新日志

- v1.0.0 - 初始版本，支持基本DTLS通信功能
- 支持自动证书生成
- 支持交互式会话
- 支持连接测试和性能统计
