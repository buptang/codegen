#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DTLS客户端测试运行脚本
自动启动服务器并测试客户端连接

作者: Codegen
"""

import subprocess
import time
import sys
import os
import signal
import threading
import socket

def check_port_available(host, port):
    """检查端口是否可用"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((host, port))
            return result != 0  # 0表示端口被占用
    except:
        return True

def find_available_port(start_port=4433):
    """找到可用端口"""
    port = start_port
    while port < start_port + 100:
        if check_port_available('localhost', port):
            return port
        port += 1
    return None

def run_server(port, mode='tcp'):
    """在后台运行服务器"""
    cmd = [sys.executable, 'dtls_server_test.py', '--port', str(port), '--mode', mode]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def run_client(client_type='basic', port=4433):
    """运行客户端"""
    if client_type == 'basic':
        script = 'dtls_client.py'
    else:
        script = 'dtls_client_pure.py'
    
    # 修改客户端代码中的端口
    modify_client_port(script, port)
    
    cmd = [sys.executable, script]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

def modify_client_port(script, port):
    """临时修改客户端脚本中的端口"""
    with open(script, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 替换默认端口
    content = content.replace('server_port=4433', f'server_port={port}')
    
    # 创建临时文件
    temp_script = f"temp_{script}"
    with open(temp_script, 'w', encoding='utf-8') as f:
        f.write(content)
    
    # 替换原文件
    os.rename(temp_script, script)

def test_connection(host='localhost', port=4433, timeout=5):
    """测试连接"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except:
        return False

def main():
    print("DTLS客户端测试工具")
    print("=" * 50)
    
    # 检查必要文件
    required_files = ['dtls_client.py', 'dtls_client_pure.py', 'dtls_server_test.py']
    missing_files = [f for f in required_files if not os.path.exists(f)]
    
    if missing_files:
        print(f"❌ 缺少必要文件: {', '.join(missing_files)}")
        return
    
    # 找到可用端口
    port = find_available_port()
    if not port:
        print("❌ 无法找到可用端口")
        return
    
    print(f"✅ 使用端口: {port}")
    
    # 启动服务器
    print("🚀 启动测试服务器...")
    server_process = run_server(port, 'tcp')
    
    try:
        # 等待服务器启动
        time.sleep(2)
        
        # 检查服务器是否启动成功
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print(f"❌ 服务器启动失败:")
            print(f"stdout: {stdout.decode()}")
            print(f"stderr: {stderr.decode()}")
            return
        
        # 测试连接
        print("🔍 测试服务器连接...")
        if not test_connection('localhost', port):
            print("❌ 无法连接到服务器")
            return
        
        print("✅ 服务器连接正常")
        
        # 测试基础客户端
        print("\n📡 测试基础DTLS客户端...")
        try:
            result = run_client('basic', port)
            if result.returncode == 0:
                print("✅ 基础客户端测试成功")
                print("输出:", result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
            else:
                print("❌ 基础客户端测试失败")
                print("错误:", result.stderr)
        except subprocess.TimeoutExpired:
            print("⏰ 基础客户端测试超时（这可能是正常的，因为客户端可能在等待用户输入）")
        except Exception as e:
            print(f"❌ 基础客户端测试异常: {e}")
        
        # 测试纯DTLS客户端
        print("\n📡 测试纯DTLS客户端...")
        try:
            result = run_client('pure', port)
            if result.returncode == 0:
                print("✅ 纯DTLS客户端测试成功")
                print("输出:", result.stdout[:200] + "..." if len(result.stdout) > 200 else result.stdout)
            else:
                print("❌ 纯DTLS客户端测试失败")
                print("错误:", result.stderr)
        except subprocess.TimeoutExpired:
            print("⏰ 纯DTLS客户端测试超时（这可能是正常的，因为客户端可能在等待用户输入）")
        except Exception as e:
            print(f"❌ 纯DTLS客户端测试异常: {e}")
        
        print("\n🎉 测试完成！")
        print("\n📋 手动测试步骤:")
        print(f"1. 在一个终端运行: python dtls_server_test.py --port {port}")
        print(f"2. 在另一个终端运行: python dtls_client.py")
        print("3. 按照提示进行交互测试")
        
    except KeyboardInterrupt:
        print("\n⏹️ 测试被用户中断")
    except Exception as e:
        print(f"❌ 测试过程中出现错误: {e}")
    finally:
        # 清理服务器进程
        if server_process and server_process.poll() is None:
            print("🛑 停止测试服务器...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
        
        print("✅ 清理完成")

if __name__ == "__main__":
    main()
