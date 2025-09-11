#!/usr/bin/env python3
"""
完整DTLS握手测试脚本
"""
import subprocess
import time
import signal
import os
import sys

def run_dtls_test():
    """运行完整的DTLS测试"""
    print("完整DTLS握手测试")
    print("=" * 50)
    
    server_process = None
    try:
        # 启动服务器
        print("🚀 启动DTLS服务器...")
        server_process = subprocess.Popen(
            [sys.executable, "dtls_server_complete.py"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # 等待服务器启动
        time.sleep(3)
        
        # 检查服务器是否还在运行
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print(f"❌ 服务器启动失败:")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return False
        
        print("✅ 服务器启动成功")
        
        # 运行客户端
        print("\n🔗 运行DTLS客户端...")
        client_result = subprocess.run(
            [sys.executable, "dtls_client_complete.py"],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        print("客户端输出:")
        print("-" * 30)
        print(client_result.stdout)
        if client_result.stderr:
            print("客户端错误:")
            print(client_result.stderr)
        
        # 检查结果
        if client_result.returncode == 0:
            if "握手成功" in client_result.stdout or "加密通信建立" in client_result.stdout:
                print("✅ DTLS握手测试成功!")
                return True
            else:
                print("⚠️ 客户端运行完成，但握手可能未完全成功")
                return False
        else:
            print(f"❌ 客户端运行失败，返回码: {client_result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print("❌ 客户端运行超时")
        return False
    except Exception as e:
        print(f"❌ 测试过程中出错: {e}")
        return False
    finally:
        # 清理服务器进程
        if server_process and server_process.poll() is None:
            print("\n🛑 停止服务器...")
            server_process.terminate()
            try:
                server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_process.kill()
                server_process.wait()
            print("✅ 服务器已停止")

if __name__ == "__main__":
    success = run_dtls_test()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 完整DTLS测试成功!")
        print("✅ struct.pack问题已修复")
        print("✅ 握手流程正常工作")
    else:
        print("❌ DTLS测试失败")
        print("请检查服务器和客户端的实现")
    
    sys.exit(0 if success else 1)

