#!/usr/bin/env bash
set -euo pipefail
INSTALL_DIR="$HOME/.local/share/ClaudeGuard"
PLIST_PATH="$HOME/Library/LaunchAgents/com.claudeguard.daemon.plist"
MENU_PLIST_PATH="$HOME/Library/LaunchAgents/com.claudeguard.menubar.plist"
HELPER_SYS_DIR="/Library/Application Support/ClaudeGuard"
HELPER_PLIST="/Library/LaunchDaemons/com.claudeguard.helper.plist"
SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

# 清理独立直连规则；失败时不停止既有防护或删除安装文件。
if [ -e "/Library/LaunchDaemons/com.claudeguard.direct-firewall.plist" ] || [ -d "$HELPER_SYS_DIR/DirectFirewall" ]; then
    sudo /usr/bin/python3 -I "$SOURCE_DIR/native/macos_direct_firewall.py" uninstall
fi

# Stop both user services before clearing rules; restore them if cleanup fails.
if [ -f "$MENU_PLIST_PATH" ]; then
    launchctl bootout "gui/$(id -u)/com.claudeguard.menubar" 2>/dev/null || true
fi
if [ -f "$PLIST_PATH" ]; then
    launchctl bootout "gui/$(id -u)/com.claudeguard.daemon" 2>/dev/null || true
fi
trap 'for p in "$PLIST_PATH" "$MENU_PLIST_PATH"; do if [ -f "$p" ]; then launchctl load "$p" 2>/dev/null || true; fi; done' ERR
(cd "$SOURCE_DIR" && /usr/bin/python3 - <<'PY'
import os
from src.config import ConfigManager
from src.network_guard import sync_hosts_file
from src.update_guard import apply_auto_update_lock
config = ConfigManager()
ok, message = sync_hosts_file(False, False, config)
if not ok:
    raise SystemExit('网络规则清理失败，保留现有安装：' + message)
ok, message = apply_auto_update_lock(False)
if not ok:
    raise SystemExit(message)
from src.window_install import uninstall
uninstall()
from src.integrity import discover_real_cli
real = discover_real_cli(config)
for path, target in [(os.path.expanduser('~/.local/bin/claudeguard'), os.path.join(os.path.expanduser('~/.local/share/ClaudeGuard'), 'bin/claudeguard'))] + [(p, os.path.join(os.path.expanduser('~/.local/share/ClaudeGuard'), 'src/cli_wrapper.py')) for p in (os.path.expanduser('~/.local/bin/claude'), '/usr/local/bin/claude', '/opt/homebrew/bin/claude')]:
    if os.path.islink(path) and os.path.realpath(path) == os.path.realpath(target):
        os.unlink(path)
        if path.endswith('/claude') and real and not os.path.lexists(path):
            os.symlink(real, path)
app = os.path.expanduser('~/Applications/ClaudeGuard.app')
if os.path.islink(app) and os.path.realpath(app) == os.path.join(os.path.expanduser('~/.local/share/ClaudeGuard'), 'ClaudeGuard.app'):
    os.unlink(app)
PY
)
sudo launchctl bootout system "$HELPER_PLIST" 2>/dev/null || true
sudo rm -f "$HELPER_PLIST" "$HELPER_SYS_DIR/hosts-helper" "$HELPER_SYS_DIR/macos_network_helper.py" \
    "$HELPER_SYS_DIR/status.json" "$HELPER_SYS_DIR/apply.lock" "$HELPER_SYS_DIR/pf-token"
sudo rmdir "$HELPER_SYS_DIR" 2>/dev/null || true
rm -f "$PLIST_PATH" "$MENU_PLIST_PATH"
rm -rf "$INSTALL_DIR"
trap - ERR
printf '%s\n' 'ClaudeGuard 已卸载。配置、窗口历史及备份已保留；仅清理专属网络规则。'
