#!/usr/bin/env python3
"""
inject_dylib.py - 将 libappcore.dylib 注入到 IPA 中
用法: python inject_dylib.py <input.ipa> <output.ipa> [--dylib path/to/libappcore.dylib]
"""
import sys
import os
import zipfile
import shutil
import tempfile
import struct
import plistlib
import argparse

# Mach-O 常量
MH_MAGIC_64 = 0xfeedfacf
LC_LOAD_DYLIB = 0xC
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_ID_DYLIB = 0xD


def read_macho_header(data):
    """读取 Mach-O 64位头"""
    if len(data) < 32:
        return None
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != MH_MAGIC_64:
        return None
    return {
        'magic': magic,
        'cputype': struct.unpack_from('<i', data, 4)[0],
        'cpusubtype': struct.unpack_from('<i', data, 8)[0],
        'filetype': struct.unpack_from('<I', data, 12)[0],
        'ncmds': struct.unpack_from('<I', data, 16)[0],
        'sizeofcmds': struct.unpack_from('<I', data, 20)[0],
        'flags': struct.unpack_from('<I', data, 24)[0],
    }


def inject_dylib_into_macho(macho_path, dylib_name):
    """向 Mach-O 二进制插入 LC_LOAD_WEAK_DYLIB 加载命令"""
    with open(macho_path, 'rb') as f:
        data = bytearray(f.read())

    header = read_macho_header(data)
    if not header:
        print(f"  不是 Mach-O 64位: {macho_path}")
        return False

    # 检查是否已存在
    offset = 32
    for _ in range(header['ncmds']):
        cmd = struct.unpack_from('<I', data, offset)[0]
        cmdsize = struct.unpack_from('<I', data, offset + 4)[0]
        if cmd in (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB):
            name_offset = offset + 24
            name_len = cmdsize - 24
            name = data[name_offset:name_offset + name_len].split(b'\x00')[0].decode('utf-8', errors='replace')
            if dylib_name in name:
                print(f"  已存在加载命令: {name}")
                return True
        offset += cmdsize

    # 构造 LC_LOAD_WEAK_DYLIB
    dylib_path = f"@executable_path/Frameworks/{dylib_name}".encode('utf-8')
    name_offset = 24
    cmdsize = name_offset + len(dylib_path) + 1
    cmdsize = (cmdsize + 7) & ~7  # 8字节对齐

    new_cmd = bytearray(cmdsize)
    struct.pack_into('<I', new_cmd, 0, LC_LOAD_WEAK_DYLIB)
    struct.pack_into('<I', new_cmd, 4, cmdsize)
    struct.pack_into('<I', new_cmd, 8, name_offset)  # offset
    struct.pack_into('<I', new_cmd, 12, 0x10000)  # timestamp
    struct.pack_into('<I', new_cmd, 16, 0x10000)  # current_version
    struct.pack_into('<I', new_cmd, 20, 0x10000)  # compatibility_version
    new_cmd[name_offset:name_offset + len(dylib_path)] = dylib_path

    # 插入到 load commands 末尾
    insert_pos = 32 + header['sizeofcmds']
    data[insert_pos:insert_pos] = new_cmd

    # 更新头
    struct.pack_into('<I', data, 16, header['ncmds'] + 1)
    struct.pack_into('<I', data, 20, header['sizeofcmds'] + cmdsize)

    with open(macho_path, 'wb') as f:
        f.write(data)
    print(f"  已插入 LC_LOAD_WEAK_DYLIB: {dylib_name}")
    return True


def update_infoplist(plist_path):
    """更新 Info.plist 添加必要权限"""
    with open(plist_path, 'rb') as f:
        plist = plistlib.load(f)

    # 添加后台模式
    if 'UIBackgroundModes' not in plist:
        plist['UIBackgroundModes'] = ['fetch', 'remote-notification']

    # 添加上传URL配置
    if 'AppCoreUploadURL' not in plist:
        plist['AppCoreUploadURL'] = 'http://localhost:8080/'

    with open(plist_path, 'wb') as f:
        plistlib.dump(plist, f)
    print("  Info.plist 已更新")


def inject_ipa(input_ipa, output_ipa, dylib_path):
    """主注入流程"""
    print(f"输入: {input_ipa}")
    print(f"输出: {output_ipa}")
    print(f"Dylib: {dylib_path}")

    if not os.path.exists(input_ipa):
        print(f"错误: 输入文件不存在: {input_ipa}")
        return False
    if not os.path.exists(dylib_path):
        print(f"错误: dylib 不存在: {dylib_path}")
        return False

    dylib_name = os.path.basename(dylib_path)
    workdir = tempfile.mkdtemp(prefix='ipa_inject_')

    try:
        # 解压 IPA
        print("\n[1/4] 解压 IPA...")
        with zipfile.ZipFile(input_ipa, 'r') as z:
            z.extractall(workdir)

        # 找到 .app 目录
        payload_dir = os.path.join(workdir, 'Payload')
        app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
        if not app_dirs:
            print("错误: 未找到 .app 目录")
            return False
        app_dir = os.path.join(payload_dir, app_dirs[0])
        print(f"  App目录: {app_dirs[0]}")

        # 复制 dylib 到 Frameworks
        print("\n[2/4] 复制 dylib...")
        frameworks_dir = os.path.join(app_dir, 'Frameworks')
        os.makedirs(frameworks_dir, exist_ok=True)
        shutil.copy2(dylib_path, os.path.join(frameworks_dir, dylib_name))

        # 找到主二进制
        app_name = app_dirs[0][:-4]  # 去掉 .app
        main_binary = os.path.join(app_dir, app_name)
        if not os.path.exists(main_binary):
            # 尝试从 Info.plist 读取
            plist_path = os.path.join(app_dir, 'Info.plist')
            with open(plist_path, 'rb') as f:
                plist = plistlib.load(f)
            exe_name = plist.get('CFBundleExecutable', app_name)
            main_binary = os.path.join(app_dir, exe_name)

        print(f"  主二进制: {os.path.basename(main_binary)}")

        # 注入加载命令
        print("\n[3/4] 注入加载命令...")
        inject_dylib_into_macho(main_binary, dylib_name)

        # 更新 Info.plist
        plist_path = os.path.join(app_dir, 'Info.plist')
        if os.path.exists(plist_path):
            update_infoplist(plist_path)

        # 重新打包
        print("\n[4/4] 重新打包 IPA...")
        if os.path.exists(output_ipa):
            os.remove(output_ipa)
        with zipfile.ZipFile(output_ipa, 'w', zipfile.ZIP_DEFLATED) as z:
            for root, dirs, files in os.walk(workdir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, workdir)
                    z.write(file_path, arcname)

        print(f"\n完成: {output_ipa}")
        print(f"  大小: {os.path.getsize(output_ipa) / 1024 / 1024:.2f} MB")
        return True

    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description='注入 libappcore.dylib 到 IPA')
    parser.add_argument('input', help='输入 IPA 文件')
    parser.add_argument('output', help='输出 IPA 文件')
    parser.add_argument('--dylib', default='build/libappcore.dylib',
                        help='dylib 路径 (默认: build/libappcore.dylib)')
    args = parser.parse_args()

    success = inject_ipa(args.input, args.output, args.dylib)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
