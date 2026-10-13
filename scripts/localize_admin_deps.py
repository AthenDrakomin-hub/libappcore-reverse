#!/usr/bin/env python3
"""
localize_admin_deps.py - 将 admin-web 的 CDN 依赖下载到本地
使后台在离线环境也能运行

用法:
  python localize_admin_deps.py [--output admin-web/vendor]

依赖:
  - Vue 3 (global build)
  - Element Plus
  - Element Plus CSS
"""
import os
import sys
import urllib.request
import argparse

DEPENDENCIES = [
    {
        "name": "vue.global.prod.js",
        "url": "https://unpkg.com/vue@3/dist/vue.global.prod.js",
        "description": "Vue 3 全局构建"
    },
    {
        "name": "element-plus.full.min.js",
        "url": "https://unpkg.com/element-plus/dist/index.full.min.js",
        "description": "Element Plus 完整构建"
    },
    {
        "name": "element-plus.css",
        "url": "https://unpkg.com/element-plus/dist/index.css",
        "description": "Element Plus 样式"
    },
    {
        "name": "element-plus-icons.min.js",
        "url": "https://unpkg.com/@element-plus/icons-vue/dist/index.iife.min.js",
        "description": "Element Plus 图标"
    },
]


def download_file(url, dest):
    """下载文件, 带进度显示"""
    print(f"  下载: {url}")
    print(f"  目标: {dest}")
    try:
        urllib.request.urlretrieve(url, dest)
        size = os.path.getsize(dest)
        print(f"  完成: {size / 1024:.1f} KB")
        return True
    except Exception as e:
        print(f"  失败: {e}")
        return False


def update_index_html(index_path, vendor_dir):
    """更新 index.html 中的 CDN 引用为本地路径"""
    with open(index_path, 'r', encoding='utf-8') as f:
        content = f.read()

    replacements = {
        'https://unpkg.com/vue@3/dist/vue.global.prod.js': 'vendor/vue.global.prod.js',
        'https://unpkg.com/element-plus/dist/index.full.min.js': 'vendor/element-plus.full.min.js',
        'https://unpkg.com/element-plus/dist/index.css': 'vendor/element-plus.css',
        'https://unpkg.com/@element-plus/icons-vue/dist/index.iife.min.js': 'vendor/element-plus-icons.min.js',
    }

    changed = False
    for cdn, local in replacements.items():
        if cdn in content:
            content = content.replace(cdn, local)
            changed = True
            print(f"  替换: {cdn} -> {local}")

    if changed:
        with open(index_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print("  index.html 已更新")
    else:
        print("  index.html 无需更新 (已是本地引用或未找到CDN)")

    return changed


def main():
    parser = argparse.ArgumentParser(description='本地化 admin-web 依赖')
    parser.add_argument('--output', default='vendor',
                        help='输出目录 (相对于 admin-web)')
    parser.add_argument('--skip-download', action='store_true',
                        help='跳过下载, 仅更新 index.html 引用')
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    admin_web_dir = os.path.join(script_dir, '..', 'server', 'admin-web')
    vendor_dir = os.path.join(admin_web_dir, args.output)
    index_path = os.path.join(admin_web_dir, 'index.html')

    if not os.path.exists(index_path):
        print(f"错误: 未找到 {index_path}")
        return 1

    print(f"admin-web 目录: {admin_web_dir}")
    print(f"vendor 目录: {vendor_dir}")
    os.makedirs(vendor_dir, exist_ok=True)

    if not args.skip_download:
        print("\n[1/2] 下载依赖...")
        success = 0
        for dep in DEPENDENCIES:
            dest = os.path.join(vendor_dir, dep['name'])
            print(f"\n{dep['description']} ({dep['name']})")
            if download_file(dep['url'], dest):
                success += 1
        print(f"\n下载完成: {success}/{len(DEPENDENCIES)}")
        if success < len(DEPENDENCIES):
            print("警告: 部分依赖下载失败, 可手动下载后放入 vendor 目录")

    print("\n[2/2] 更新 index.html...")
    update_index_html(index_path, vendor_dir)

    print("\n完成! 后台现在可以离线运行。")
    print(f"  依赖目录: {vendor_dir}")
    print("  如需恢复 CDN, 重新运行时将 vendor 路径改回 CDN URL")
    return 0


if __name__ == '__main__':
    sys.exit(main())
