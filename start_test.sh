#!/bin/bash
# DTLS客户端测试启动脚本

echo "🚀 DTLS客户端测试环境"
echo "====================="

# 检查Python版本
python3 --version

# 检查依赖
echo "检查依赖包..."
python3 -c "import cryptography; print('✅ cryptography 已安装')" 2>/dev/null || {
    echo "❌ cryptography 未安装"
    echo "请运行: pip install cryptography"
    exit 1
}

echo "✅ 依赖检查完成"
echo ""

# 显示选项
echo "请选择测试方式:"
echo "1. 使用内置简单服务器测试"
echo "2. 使用OpenSSL服务器测试"
echo "3. 仅运行客户端演示"
echo ""

read -p "请输入选择 (1-3): " choice

case $choice in
    1)
        echo "启动内置简单服务器..."
        echo "在另一个终端运行客户端测试"
        echo "客户端命令: python3 demo.py"
        echo ""
        python3 simple_dtls_server.py
        ;;
    2)
        echo "OpenSSL服务器测试指南:"
        echo "====================="
        echo "1. 生成证书:"
        echo "   openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes"
        echo ""
        echo "2. 启动服务器:"
        echo "   openssl s_server -dtls1_2 -accept 4433 -cert server.crt -key server.key"
        echo ""
        echo "3. 在另一个终端运行客户端:"
        echo "   python3 demo.py"
        echo ""
        ;;
    3)
        echo "运行客户端演示..."
        python3 demo.py
        ;;
    *)
        echo "无效选择"
        exit 1
        ;;
esac

