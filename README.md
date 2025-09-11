# DTLS客户端实现

这是一个用Python3实现的DTLS（Datagram Transport Layer Security）客户端，支持与DTLS服务端进行协商、交互和加密通信。

## 功能特性

- ✅ DTLS协议支持（使用pyDTLS库）
- ✅ 自动生成自签名证书
- ✅ 加密消息传输
- ✅ 连接测试和ping功能
- ✅ 交互式会话模式
- ✅ 文件传输支持
- ✅ 完整的错误处理和日志记录
- ✅ 上下文管理器支持

## 安装依赖

```bash
pip install -r requirements.txt
```

或者手动安装：

```bash
pip install pyopenssl cryptography pyDTLS
```

## 文件说明

- `dtls_client.py` - 基于TLS over TCP的DTLS客户端实现（兼容性更好）
- `dtls_client_pure.py` - 纯DTLS客户端实现（使用pyDTLS库）
- `dtls_server_test.py` - 简单的测试服务器
- `requirements.txt` - 依赖包列表

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

### 常见问题

1. **连接失败**
   - 检查服务器是否运行
   - 确认端口号正确
   - 检查防火墙设置

2. **证书错误**
   - 删除旧的证书文件重新生成
   - 检查证书权限

3. **依赖问题**
   - 确保所有依赖包已正确安装
   - 检查Python版本兼容性

### 调试模式

启用详细日志：

```python
import logging
logging.basicConfig(level=logging.DEBUG)
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
