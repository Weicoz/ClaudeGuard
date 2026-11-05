#!/usr/bin/env python3
"""安装本地命令，备份已有文件；不启动任务、不调用 Claude。"""

import argparse
from datetime import datetime
import fcntl
import ipaddress
import os
from pathlib import Path
import plistlib
import re
import shutil
import sys
import subprocess

from src import window_manager as app


def install(expected_ip=None):
    source = Path(__file__).resolve().parents[1] / "bin/claude-w"
    bindir = app.HOME / ".local/bin"
    bindir.mkdir(parents=True, exist_ok=True)
    app.ensure_dirs()
    with app.LOCK.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
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
        for name, target in (("claude-w", source), ("claude-window", "claude-w")):
            path = bindir / name
            temp = path.with_name(f".{name}.{os.getpid()}.tmp")
            temp.symlink_to(target)
            temp.replace(path)
        path = bindir / "ckill"
        temp = path.with_name(f".ckill.{os.getpid()}.tmp")
        temp.write_text('#!/bin/sh\n# ClaudeGuard compatibility\nexec "$HOME/.local/bin/claude-w" kill "$@"\n')
        temp.chmod(0o755)
        temp.replace(path)
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
    """Restore only compatibility entrypoints owned by this installation."""
    manifest = app.BASE / "claudeguard-install.json"
    record = app.read_json(manifest)
    if not record:
        return
    backup = Path(record["backup"])
    backup.resolve().relative_to((app.BASE / "backups").resolve())
    source = Path(__file__).resolve().parents[1] / "bin/claude-w"
    bindir = app.HOME / ".local/bin"
    current = bindir / "claude-w"
    ours = current.is_symlink() and current.resolve() == source.resolve()
    if ours:
        subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{app.LABEL}"], capture_output=True)
    for name in ("claude-w", "claude-window", "ckill"):
        path = bindir / name
        owned = (path.is_symlink() and path.resolve() == source.resolve())
        if name == "ckill" and path.is_file() and not path.is_symlink():
            owned = "# ClaudeGuard compatibility" in path.read_text()
        if not owned:
            continue
        old = backup / name
        if old.is_symlink():
            temp = path.with_name(f".{name}.restore")
            temp.symlink_to(os.readlink(old))
            temp.replace(path)
        elif old.exists():
            temp = path.with_name(f".{name}.restore")
            shutil.copy2(old, temp)
            temp.replace(path)
        else:
            path.unlink()
    if ours and record.get("new_plist") and app.PLIST.exists():
        app.PLIST.unlink()
    manifest.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-ip", type=ipaddress.IPv4Address)
    parser.add_argument("--uninstall", action="store_true")
    args = parser.parse_args()
    uninstall() if args.uninstall else install(args.expected_ip)
