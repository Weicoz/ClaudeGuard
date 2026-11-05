#!/usr/bin/env python3
"""安装本地命令，备份已有文件；不启动任务、不调用 Claude。"""

import argparse
from datetime import datetime
import ipaddress
import os
from pathlib import Path
import plistlib
import re
import shutil
import tempfile
from src.policy import locked
import sys
import subprocess

from src import window_manager as app


def install(expected_ip=None):
    source = Path(__file__).resolve().parents[1] / "bin/claude-w"
    bindir = app.HOME / ".local/bin"
    bindir.mkdir(parents=True, exist_ok=True)
    app.ensure_dirs()
    with locked(app.LOCK):
        backup = app.BASE / "backups" / datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        backup.mkdir(parents=True, mode=0o700)
        for path in (bindir / "claude-w", bindir / "claude-window", bindir / "ckill",
                     app.PLIST, app.STATE, app.CONFIG, app.HISTORY, app.LIVE_CACHE):
            if path.is_symlink():
                (backup / path.name).symlink_to(os.readlink(path))
            elif path.exists():
                shutil.copy2(path, backup / path.name)
        if expected_ip is None and not app.CONFIG.exists():
            old = bindir / "claude-window"
            if old.exists():
                match = re.search(r'^EXPECTED_IP = "([0-9.]+)"$', old.read_text(), re.M)
                if match:
                    expected_ip = ipaddress.IPv4Address(match.group(1))
        if expected_ip is not None:
            app.write_json(app.CONFIG, {"expected_ip": str(expected_ip)})
        manifest = app.BASE / "claudeguard-install.json"
        if not manifest.exists():
            app.write_json(manifest, {"backup": str(backup), "new_plist": not app.PLIST.exists()})
        app.migrate_history()
        source.chmod(0o755)
        with tempfile.TemporaryDirectory(prefix=".claudeguard-", dir=bindir) as staging:
            for name, target in (("claude-w", source), ("claude-window", "claude-w")):
                temp = Path(staging) / name
                temp.symlink_to(target)
                temp.replace(bindir / name)
            temp = Path(staging) / "ckill"
            temp.write_text('#!/bin/sh\n# ClaudeGuard compatibility\nexec "$HOME/.local/bin/claude-w" kill "$@"\n')
            temp.chmod(0o755)
            temp.replace(bindir / "ckill")
        if not app.PLIST.exists():
            config = {
                "Label": app.LABEL,
                "Disabled": True,
                "ProgramArguments": [sys.executable, str(bindir / "claude-w"), "check"],
                "StartInterval": app.INTERVAL,
                "RunAtLoad": True,
                "ProcessType": "Background",
                "Nice": 10,
                "EnvironmentVariables": {"PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"},
                "StandardOutPath": "/dev/null",
                "StandardErrorPath": str(app.ERR),
            }
            with app.PLIST.open("wb") as f:
                plistlib.dump(config, f)
        print(f"已安装 claude-w；ckill 和 claude-window 保留兼容。备份：{backup}")
        print("未启动/重启任务，也未调用 Claude；新安装的任务默认禁用；原已启用的任务保持原状态。")
        if not app.CONFIG.exists():
            print("请先运行 claude-w config --expected-ip <固定出口IPv4>，再运行 claude-w start。")


def uninstall():
    """Restore only owned entrypoints, with the same lock as a running request."""
    manifest = app.BASE / "claudeguard-install.json"
    if not manifest.exists():
        return
    with locked(app.LOCK):
        record = app.read_json(manifest)
        if not record:
            raise ValueError("窗口安装记录无效，未执行卸载")
        backup = Path(record["backup"])
        backup.resolve().relative_to((app.BASE / "backups").resolve())
        if not backup.is_dir():
            raise ValueError("窗口命令备份丢失，未执行卸载")
        source = Path(__file__).resolve().parents[1] / "bin/claude-w"
        bindir = app.HOME / ".local/bin"
        owned = {}
        # Resolve every alias before replacing its target.
        for name in ("claude-w", "claude-window", "ckill"):
            path = bindir / name
            owned[name] = path.is_symlink() and path.resolve() == source.resolve()
            if name == "ckill" and path.is_file() and not path.is_symlink():
                owned[name] = path.read_text() == '#!/bin/sh\n# ClaudeGuard compatibility\nexec "$HOME/.local/bin/claude-w" kill "$@"\n'
        if owned['claude-w']:
            subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{app.LABEL}"], capture_output=True, timeout=10)
        with tempfile.TemporaryDirectory(prefix=".claudeguard-restore-", dir=bindir) as staging:
            for name, ours in owned.items():
                if not ours:
                    continue
                old, path = backup / name, bindir / name
                temporary = Path(staging) / name
                if old.is_symlink():
                    temporary.symlink_to(os.readlink(old))
                    temporary.replace(path)
                elif old.is_file():
                    shutil.copy2(old, temporary)
                    temporary.replace(path)
                else:
                    path.unlink()
        if owned['claude-w'] and record.get("new_plist") and app.PLIST.exists():
            value = plistlib.loads(app.PLIST.read_bytes())
            if value.get('Label') == app.LABEL and str(bindir / 'claude-w') in value.get('ProgramArguments', []):
                app.PLIST.unlink()
        manifest.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-ip", type=ipaddress.IPv4Address)
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    uninstall() if args.uninstall else install(args.expected_ip)
