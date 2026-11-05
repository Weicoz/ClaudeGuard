#!/usr/bin/env python3
"""Build a Apple Silicon macOS DMG with offline payload and interactive installer."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def run(*args):
    subprocess.run(args, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?', args.version):
        parser.error('invalid release version')
    repo = Path(__file__).resolve().parents[1]
    output = repo / 'dist'
    output.mkdir(exist_ok=True)
    dmg = output / f'ClaudeGuard-{args.version}-macos-arm64.dmg'
    with tempfile.TemporaryDirectory(prefix='claudeguard-release-') as directory:
        root = Path(directory)
        image = root / 'image'
        payload = image / 'ClaudeGuard'
        payload.mkdir(parents=True)
        for name in ('src', 'bin', 'assets', 'docs', 'native'):
            shutil.copytree(repo / name, payload / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', '.DS_Store'))
        for name in ('install.sh', 'uninstall.sh', 'LICENSE', 'NOTICE', 'README.zh-CN.md'):
            shutil.copy2(repo / name, payload / name)
        prebuilt = payload / 'prebuilt'
        prebuilt.mkdir()
        run('swiftc', '-O', '-target', 'arm64-apple-macosx13.0', str(repo / 'src/main.swift'), '-o', str(prebuilt / 'ClaudeGuardMenuBar'))
        run('clang', '-O2', '-arch', 'arm64', '-mmacosx-version-min=13.0', str(repo / 'src/hosts_helper.c'), '-o', str(prebuilt / 'hosts-helper'))
        for name in ('ClaudeGuardMenuBar', 'hosts-helper'):
            target = prebuilt / name
            run('codesign', '--force', '--sign', '-', str(target))
            run('codesign', '--verify', '--strict', str(target))
            run('lipo', str(target), '-verify_arch', 'arm64')
        (payload / 'VERSION').write_text(args.version + '\n')
        manifest = {str(p.relative_to(payload)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in sorted(payload.rglob('*')) if p.is_file()}
        (payload / 'MANIFEST.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')
        install = image / 'Install ClaudeGuard.command'
        install.write_text('''#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/ClaudeGuard"
/usr/bin/python3 - <<'VERIFY'
import hashlib,json,pathlib
root=pathlib.Path('.')
for name, expected in json.loads((root/'MANIFEST.json').read_text()).items():
    if hashlib.sha256((root/name).read_bytes()).hexdigest() != expected:
        raise SystemExit('Payload verification failed: '+name)
VERIFY
./install.sh
printf '\\n安装完成。后台防护已启动，新装窗口任务默认禁用；已有任务启用状态保留。按回车退出。\\n'
read -r _
''')
        install.chmod(0o755)
        (image / '请先阅读.txt').write_text('''ClaudeGuard 预览版

要求：macOS 13 或更新版本；可用的 /usr/bin/python3（通常来自 Xcode 命令行工具）。
仅支持 Apple Silicon，程序已预编译。无需联网下载项目源码。

双击 Install ClaudeGuard.command 安装。系统网络助手需要管理员密码，由你输入。
这不是拖拽即用的独立 App；安装后通过 ClaudeGuard.app 或 claudeguard settings 打开设置。
Claude-W 功能入口：claudeguard window --help。新安装的自动请求任务默认禁用。
已有历史和计划保留；已有启用的旧任务保持原状态。

本预览版仅使用本地 ad-hoc 签名，没有 Developer ID 签名或 Apple 公证。
macOS 可以阻止下载的安装程序；如系统不允许，请停止安装，不要关闭系统安全保护。
系统助手仅操作专属 pf 锚点；发现旧版全局规则时，安装器停止，保留现有防护。\n设置界面与全新系统安装尚未完成全部手工验收。
''')
        run('hdiutil', 'create', '-volname', 'ClaudeGuard', '-srcfolder', str(image), '-format', 'UDZO', '-ov', str(dmg))
    run('hdiutil', 'verify', str(dmg))
    checksum = hashlib.sha256(dmg.read_bytes()).hexdigest()
    sums = output / 'SHA256SUMS'
    sums.write_text(f'{checksum}  {dmg.name}\n')
    print(dmg)


if __name__ == '__main__':
    main()
