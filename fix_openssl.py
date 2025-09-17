#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenSSL依赖问题修复脚本
解决libcrypto.so.1.1缺失问题

作者: Codegen
"""

import os
import sys
import subprocess
import platform
import shutil

def detect_system():
    """检测操作系统"""
    system = platform.system().lower()
    if system == 'linux':
        # 检测Linux发行版
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                if 'ubuntu' in content or 'debian' in content:
                    return 'debian'
                elif 'centos' in content or 'rhel' in content or 'fedora' in content:
                    return 'redhat'
                elif 'arch' in content:
                    return 'arch'
                else:
                    return 'linux'
        except:
            return 'linux'
    return system

def check_openssl_version():
    """检查OpenSSL版本"""
    try:
        result = subprocess.run(['openssl', 'version'], capture_output=True, text=True)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"✅ OpenSSL版本: {version}")
            return version
        else:
            print("❌ OpenSSL未安装或不可用")
            return None
    except FileNotFoundError:
        print("❌ OpenSSL命令未找到")
        return None

def find_openssl_libs():
    """查找系统中的OpenSSL库"""
    possible_paths = [
        '/usr/lib/x86_64-linux-gnu/',
        '/usr/lib64/',
        '/usr/lib/',
        '/lib/x86_64-linux-gnu/',
        '/lib64/',
        '/lib/',
        '/usr/local/lib/',
        '/opt/openssl/lib/',
    ]
    
    found_libs = {}
    
    for path in possible_paths:
        if os.path.exists(path):
            for file in os.listdir(path):
                if 'libcrypto.so' in file or 'libssl.so' in file:
                    full_path = os.path.join(path, file)
                    if os.path.isfile(full_path) or os.path.islink(full_path):
                        found_libs[file] = full_path
    
    return found_libs

def create_symlinks(found_libs):
    """创建符号链接"""
    created_links = []
    
    # 需要的库文件
    required_libs = {
        'libcrypto.so.1.1': ['libcrypto.so.3', 'libcrypto.so.1.0.0', 'libcrypto.so'],
        'libssl.so.1.1': ['libssl.so.3', 'libssl.so.1.0.0', 'libssl.so']
    }
    
    for target, sources in required_libs.items():
        if target in found_libs:
            print(f"✅ {target} 已存在: {found_libs[target]}")
            continue
            
        # 寻找可用的源文件
        source_file = None
        for source in sources:
            if source in found_libs:
                source_file = found_libs[source]
                break
        
        if source_file:
            # 确定目标路径
            target_dir = os.path.dirname(source_file)
            target_path = os.path.join(target_dir, target)
            
            try:
                # 创建符号链接
                if not os.path.exists(target_path):
                    os.symlink(source_file, target_path)
                    print(f"✅ 创建符号链接: {target_path} -> {source_file}")
                    created_links.append(target_path)
                else:
                    print(f"✅ 符号链接已存在: {target_path}")
            except PermissionError:
                print(f"❌ 权限不足，无法创建符号链接: {target_path}")
                print(f"   请使用sudo运行: sudo ln -s {source_file} {target_path}")
            except Exception as e:
                print(f"❌ 创建符号链接失败: {e}")
        else:
            print(f"❌ 未找到 {target} 的源文件")
    
    return created_links

def install_openssl_debian():
    """在Debian/Ubuntu系统上安装OpenSSL"""
    commands = [
        "sudo apt update",
        "sudo apt install -y libssl1.1 libssl-dev",
        # 如果上面的包不可用，尝试这些
        "sudo apt install -y libssl3 libssl-dev || true",
        "sudo apt install -y openssl libssl-dev || true"
    ]
    
    for cmd in commands:
        print(f"执行: {cmd}")
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ 命令执行成功")
            else:
                print(f"⚠️ 命令执行警告: {result.stderr}")
        except Exception as e:
            print(f"❌ 命令执行失败: {e}")

def install_openssl_redhat():
    """在RedHat/CentOS/Fedora系统上安装OpenSSL"""
    commands = [
        "sudo yum install -y openssl-libs openssl-devel || sudo dnf install -y openssl-libs openssl-devel",
        "sudo yum install -y compat-openssl11 || sudo dnf install -y compat-openssl11 || true"
    ]
    
    for cmd in commands:
        print(f"执行: {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ 命令执行成功")
            else:
                print(f"⚠️ 命令执行警告: {result.stderr}")
        except Exception as e:
            print(f"❌ 命令执行失败: {e}")

def install_openssl_arch():
    """在Arch Linux系统上安装OpenSSL"""
    commands = [
        "sudo pacman -Sy --noconfirm openssl",
        "sudo pacman -Sy --noconfirm openssl-1.1 || true"
    ]
    
    for cmd in commands:
        print(f"执行: {cmd}")
        try:
            result = subprocess.run(cmd.split(), capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ 命令执行成功")
            else:
                print(f"⚠️ 命令执行警告: {result.stderr}")
        except Exception as e:
            print(f"❌ 命令执行失败: {e}")

def test_dtls_import():
    """测试DTLS库导入"""
    try:
        print("测试pyDTLS库导入...")
        import dtls
        print("✅ pyDTLS库导入成功")
        return True
    except ImportError as e:
        print(f"❌ pyDTLS库导入失败: {e}")
        return False
    except Exception as e:
        print(f"❌ pyDTLS库测试失败: {e}")
        return False

def main():
    print("OpenSSL依赖问题修复工具")
    print("=" * 50)
    
    # 检测系统
    system = detect_system()
    print(f"检测到系统: {system}")
    
    # 检查OpenSSL版本
    openssl_version = check_openssl_version()
    
    # 查找现有的OpenSSL库
    print("\n🔍 搜索系统中的OpenSSL库...")
    found_libs = find_openssl_libs()
    
    if found_libs:
        print("找到的OpenSSL库文件:")
        for lib, path in found_libs.items():
            print(f"  {lib}: {path}")
    else:
        print("❌ 未找到OpenSSL库文件")
    
    # 尝试创建符号链接
    print("\n🔗 尝试创建符号链接...")
    created_links = create_symlinks(found_libs)
    
    # 测试DTLS导入
    print("\n🧪 测试DTLS库...")
    if test_dtls_import():
        print("🎉 问题已解决！")
        return
    
    # 如果符号链接不能解决问题，尝试安装OpenSSL
    print("\n📦 尝试安装/更新OpenSSL...")
    
    if system == 'debian':
        install_openssl_debian()
    elif system == 'redhat':
        install_openssl_redhat()
    elif system == 'arch':
        install_openssl_arch()
    else:
        print("❌ 不支持的系统，请手动安装OpenSSL 1.1")
        print("参考命令:")
        print("  Ubuntu/Debian: sudo apt install libssl1.1")
        print("  CentOS/RHEL: sudo yum install compat-openssl11")
        print("  Fedora: sudo dnf install compat-openssl11")
    
    # 重新查找库文件
    print("\n🔍 重新搜索OpenSSL库...")
    found_libs = find_openssl_libs()
    
    # 重新创建符号链接
    if found_libs:
        print("🔗 重新创建符号链接...")
        create_symlinks(found_libs)
    
    # 最终测试
    print("\n🧪 最终测试...")
    if test_dtls_import():
        print("🎉 问题已解决！")
    else:
        print("❌ 问题仍未解决")
        print("\n📋 手动解决步骤:")
        print("1. 确保安装了OpenSSL 1.1:")
        print("   Ubuntu/Debian: sudo apt install libssl1.1")
        print("   CentOS/RHEL: sudo yum install compat-openssl11")
        print("2. 或者使用不需要pyDTLS的版本:")
        print("   python dtls_client.py  # 会自动回退到UDP模拟模式")
        print("3. 或者重新编译pyDTLS:")
        print("   pip uninstall pyDTLS")
        print("   pip install --no-cache-dir pyDTLS")

if __name__ == "__main__":
    main()
