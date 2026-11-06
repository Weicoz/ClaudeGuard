#!/usr/bin/env bash
#
# ClaudeGuard installer.
#
# Works two ways from the SAME file:
#   • One-liner:   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Weicoz/ClaudeGuard/main/install.sh)"
#   • Local:       ./install.sh   (from a git checkout or unpacked archive)
#
# When run via curl|bash there's no local source tree, so the script first
# fetches the repo, then compiles the Swift menu bar app + C helper NATIVELY on
# this Apple Silicon Mac. Locally-compiled binaries carry no
# quarantine flag, so Gatekeeper never blocks them — no Apple Developer account,
# no code-signing, no notarization required.
set -euo pipefail

# Which repo the one-liner pulls from. Override without editing:
#   CLAUDEGUARD_REPO=you/ClaudeGuard bash -c "$(curl -fsSL .../install.sh)"
REPO="${CLAUDEGUARD_REPO:-Weicoz/ClaudeGuard}"
BRANCH="${CLAUDEGUARD_BRANCH:-main}"

INSTALL_DIR="$HOME/.local/share/ClaudeGuard"
APP_BUNDLE="$INSTALL_DIR/ClaudeGuard.app"
PLIST_PATH="$HOME/Library/LaunchAgents/com.claudeguard.daemon.plist"
MENU_PLIST_PATH="$HOME/Library/LaunchAgents/com.claudeguard.menubar.plist"
CONFIG_DIR="$HOME/.config/claudeguard"
# Root privileged-helper: a LaunchDaemon (no sudoers, no setuid). The binary
# lives in a root-owned dir so it can't be swapped, and it runs only when the
# trigger file below is touched.
HELPER_SYS_DIR="/Library/Application Support/ClaudeGuard"
HELPER_PLIST="/Library/LaunchDaemons/com.claudeguard.helper.plist"
LEGACY_SUDOERS="/etc/sudoers.d/claudeguard"   # removed on upgrade from old versions

# --- Pretty output ----------------------------------------------------------
if [ -t 1 ]; then
    BOLD=$'\033[1m'; DIM=$'\033[2m'; RED=$'\033[31m'; GRN=$'\033[32m'
    YLW=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
else
    BOLD=; DIM=; RED=; GRN=; YLW=; CYN=; RST=
fi
info() { printf '%s %s\n' "${CYN}==>${RST}" "$*"; }
ok()   { printf '%s %s\n' "${GRN}✓${RST}"   "$*"; }
warn() { printf '%s %s\n' "${YLW}⚠${RST}"   "$*"; }
die()  { printf '%s %s\n' "${RED}✗${RST}"   "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

printf '%s\n' "${BOLD}${CYN}"
cat <<'BANNER'
   ____ _                 _        ____                     _
  / ___| | __ _ _   _  __| | ___  / ___|_   _  __ _ _ __ __| |
 | |   | |/ _` | | | |/ _` |/ _ \| |  _| | | |/ _` | '__/ _` |
 | |___| | (_| | |_| | (_| |  __/| |_| | |_| | (_| | | | (_| |
  \____|_|\__,_|\__,_|\__,_|\___| \____|\__,_|\__,_|_|  \__,_|
BANNER
printf '%s\n' "        VPN-whitelist guard for Claude on macOS${RST}"
printf '\n'

[ "$(uname -s)" = "Darwin" ] || die "ClaudeGuard is macOS-only."
[ "$(uname -m)" = "arm64" ] || die "This release supports Apple Silicon only."
/usr/bin/python3 --version >/dev/null 2>&1 || die "A working /usr/bin/python3 is required."

# --- Bootstrap: fetch source when piped from curl (no local tree) -----------
_src="${BASH_SOURCE[0]:-}"
if [ -n "$_src" ] && [ -f "$_src" ]; then
    SOURCE_DIR="$(cd "$(dirname "$_src")" && pwd)"
else
    SOURCE_DIR=""
fi

if [ -z "$SOURCE_DIR" ] || [ ! -f "$SOURCE_DIR/src/main.swift" ]; then
    info "Fetching ClaudeGuard from ${BOLD}github.com/$REPO${RST} (branch $BRANCH)…"
    BOOT_TMP="$(mktemp -d)"
    trap 'rm -rf "$BOOT_TMP"' EXIT
    if have git; then
        git clone --depth 1 --branch "$BRANCH" "https://github.com/$REPO.git" \
            "$BOOT_TMP/ClaudeGuard" >/dev/null 2>&1 || die "git clone failed (is $REPO correct and public?)"
        SOURCE_DIR="$BOOT_TMP/ClaudeGuard"
    else
        curl -fsSL "https://codeload.github.com/$REPO/tar.gz/refs/heads/$BRANCH" \
            | tar -xz -C "$BOOT_TMP" || die "download failed (is $REPO correct and public?)"
        SOURCE_DIR="$BOOT_TMP/${REPO##*/}-$BRANCH"
    fi
    [ -f "$SOURCE_DIR/src/main.swift" ] || die "fetched archive is missing src/main.swift"
    ok "Source ready."
fi

LOGO_PNG="$SOURCE_DIR/assets/AppIcon.png"
APP_VERSION="$(cat "$SOURCE_DIR/VERSION" 2>/dev/null || echo '0.1.0')"
APP_SHORT_VERSION="${APP_VERSION%%-*}"

# --- Prerequisite: Xcode Command Line Tools (clang + swiftc) ----------------
# Required to compile on-device. If missing, launch Apple's installer and wait.
if [ ! -f "$SOURCE_DIR/prebuilt/ClaudeGuardMenuBar" ] && { ! have clang || ! have swiftc; }; then
    warn "Xcode Command Line Tools required (clang + swiftc)."
    info "Launching Apple's installer — click ${BOLD}Install${RST} in the popup."
    xcode-select --install >/dev/null 2>&1 || true
    printf '%s' "${DIM}    waiting for the tools to finish installing"
    while ! (have clang && have swiftc); do printf '.'; sleep 5; done
    printf '%s\n' "${RST}"
    ok "Command Line Tools ready."
fi

# Detect incompatible global rules before changing any installed files.
# No global PF reload is safe to infer on a Mac with other network tools.
if [ "$(id -u)" -eq 0 ]; then
    PF_RULES="$(/sbin/pfctl -sr 2>/dev/null)" || die "Cannot inspect the current PF rules."
else
    PF_RULES="$(sudo /sbin/pfctl -sr 2>/dev/null)" || die "Cannot inspect PF; installation unchanged."
fi
if printf '%s\n' "$PF_RULES" | /usr/bin/grep -Eq 'to[[:space:]]+<claude_guard>'; then
    die "Legacy global ClaudeGuard PF rules detected. Keep the current installation; administrator migration is required. See docs/release-macos.md."
fi
printf '%s\n' "$PF_RULES" | /usr/bin/grep -Eq 'anchor[[:space:]]+"com\.apple/(\*|claudeguard)"' \
    || die "PF has no ClaudeGuard-compatible anchor hook. Ask the administrator to configure one before installing."
# Never turn a user-writable directory and its old symlinks into a root trust boundary.
/usr/bin/python3 - "$SOURCE_DIR" "$HELPER_SYS_DIR" /Library/Logs/ClaudeGuard <<'PYTRUST'
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from native.macos_network_helper import checked_directory
for value in sys.argv[2:]:
    path = Path(value)
    if path.exists() or path.is_symlink():
        fd = checked_directory(path, 0)
        os.close(fd)
PYTRUST

# Build and verify before stopping the installed guard or replacing its source.
BUILD_TMP="$(mktemp -d)"
cleanup_build() { rm -rf "$BUILD_TMP"; }
trap 'cleanup_build; if [ -n "${BOOT_TMP:-}" ]; then rm -rf "$BOOT_TMP"; fi' EXIT
if [ -f "$SOURCE_DIR/prebuilt/ClaudeGuardMenuBar" ] && [ -f "$SOURCE_DIR/prebuilt/hosts-helper" ]; then
    for name in ClaudeGuardMenuBar hosts-helper; do
        /usr/bin/lipo "$SOURCE_DIR/prebuilt/$name" -verify_arch arm64
        /usr/bin/codesign --verify --strict "$SOURCE_DIR/prebuilt/$name"
        cp "$SOURCE_DIR/prebuilt/$name" "$BUILD_TMP/$name"
    done
else
    clang -O2 "$SOURCE_DIR/src/hosts_helper.c" -o "$BUILD_TMP/hosts-helper"
    swiftc -O "$SOURCE_DIR/src/main.swift" -o "$BUILD_TMP/ClaudeGuardMenuBar"
fi
if [ -f "$MENU_PLIST_PATH" ]; then
    launchctl bootout "gui/$(id -u)/com.claudeguard.menubar" 2>/dev/null || true
fi
if [ -f "$PLIST_PATH" ]; then
    launchctl bootout "gui/$(id -u)/com.claudeguard.daemon" 2>/dev/null || true
fi
mkdir -p "$HOME/Library/Logs/ClaudeGuard"
chmod 700 "$HOME/Library/Logs/ClaudeGuard"

# --- 1. Stage source into the install dir -----------------------------------
info "Installing to ${BOLD}$INSTALL_DIR${RST}"
mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/src" "$INSTALL_DIR/native"
cp "$SOURCE_DIR/native/macos_network_helper.py" "$INSTALL_DIR/native/macos_network_helper.py"
cp "$SOURCE_DIR/native/macos_direct_firewall.py" "$INSTALL_DIR/native/macos_direct_firewall.py"
/usr/bin/rsync -a --exclude '__pycache__' --exclude '*.pyc' --exclude '.DS_Store' \
    "$SOURCE_DIR/src/" "$INSTALL_DIR/src/"
(cd "$INSTALL_DIR" && /usr/bin/python3 -c 'from src.config import ConfigManager; ConfigManager().migrate_network_only()')
for f in "$SOURCE_DIR/bin/"*; do
    [ "$(basename "$f")" = "hosts-helper" ] && continue   # compiled below, never shipped
    cp -R "$f" "$INSTALL_DIR/bin/"
done

# --- 2. Install verified native binaries ------------------------------------
cp "$BUILD_TMP/ClaudeGuardMenuBar" "$INSTALL_DIR/bin/.ClaudeGuardMenuBar.new"
mv -f "$INSTALL_DIR/bin/.ClaudeGuardMenuBar.new" "$INSTALL_DIR/bin/ClaudeGuardMenuBar"
rm -f "$INSTALL_DIR/bin/hosts-helper" 2>/dev/null || sudo rm -f "$INSTALL_DIR/bin/hosts-helper"
cp "$BUILD_TMP/hosts-helper" "$INSTALL_DIR/bin/hosts-helper"

chmod +x "$INSTALL_DIR/bin/claudeguard" "$INSTALL_DIR/bin/ClaudeGuardMenuBar" \
         "$INSTALL_DIR/src/cli_wrapper.py" "$INSTALL_DIR/src/app_launcher.py" \
         "$INSTALL_DIR/src/helper.py"

# --- 3. Build the .app bundle (icon + Info.plist) ---------------------------
info "Creating ClaudeGuard.app bundle…"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

if [ -f "$LOGO_PNG" ]; then
    ICON_TMP="$(mktemp -d)"
    ICONSET_DIR="$ICON_TMP/AppIcon.iconset"; mkdir -p "$ICONSET_DIR"
    for pair in "16:icon_16x16" "32:icon_16x16@2x" "32:icon_32x32" "64:icon_32x32@2x" \
                "128:icon_128x128" "256:icon_128x128@2x" "256:icon_256x256" \
                "512:icon_256x256@2x" "512:icon_512x512" "1024:icon_512x512@2x"; do
        sz="${pair%%:*}"; nm="${pair#*:}"   # split without relying on word-splitting (bash+zsh safe)
        sips -z "$sz" "$sz" "$LOGO_PNG" --out "$ICONSET_DIR/$nm.png" >/dev/null 2>&1
    done
    iconutil -c icns "$ICONSET_DIR" -o "$APP_BUNDLE/Contents/Resources/AppIcon.icns"
    rm -rf "$ICON_TMP"
else
    warn "assets/AppIcon.png not found — bundle will use the default icon."
fi

cat > "$APP_BUNDLE/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key><string>ClaudeGuardMenuBar</string>
    <key>CFBundleIconFile</key><string>AppIcon</string>
    <key>CFBundleIdentifier</key><string>com.claudeguard.app</string>
    <key>CFBundleName</key><string>ClaudeGuard</string>
    <key>CFBundleShortVersionString</key><string>$APP_SHORT_VERSION</string>
    <key>CFBundleVersion</key><string>$APP_SHORT_VERSION</string>
    <key>CFBundleGetInfoString</key><string>ClaudeGuard $APP_VERSION</string>
    <key>CFBundlePackageType</key><string>APPL</string>
    <key>LSUIElement</key><true/>
</dict>
</plist>
EOF

cp "$INSTALL_DIR/bin/ClaudeGuardMenuBar" "$APP_BUNDLE/Contents/MacOS/ClaudeGuardMenuBar"
mkdir -p "$HOME/Applications"
ln -sf "$APP_BUNDLE" "$HOME/Applications/ClaudeGuard.app"

# --- 4. Symlink the manager CLI ---------------------------------------------
info "Installing the 'claudeguard' manager…"
mkdir -p "$HOME/.local/bin" "$CONFIG_DIR"
ln -sf "$INSTALL_DIR/bin/claudeguard" "$HOME/.local/bin/claudeguard"
[ -w "/usr/local/bin" ] && ln -sf "$INSTALL_DIR/bin/claudeguard" "/usr/local/bin/claudeguard"

# Window management keeps existing data and schedules; a fresh task stays disabled.
chmod +x "$INSTALL_DIR/bin/claude-w"
(cd "$INSTALL_DIR" && /usr/bin/python3 -m src.window_install)

# --- 5. Hook the `claude` CLI + locate Claude Desktop ------------------------
# Delegated to src/integrity.py, the same code the daemon runs on a timer, so a
# fresh install and a later self-heal can't disagree about where Claude lives.
info "Hooking the 'claude' command…"
REPAIR_OUT="$(cd "$INSTALL_DIR" && python3 -c "
import sys
sys.path.insert(0, '.')
from src.config import ConfigManager
from src.integrity import repair

report = repair(ConfigManager())
print('REAL_CLI=' + (report['real_cli'] or ''))
for change in report['changed']:
    print('CHANGED=' + change)
for note in report['notes']:
    print('NOTE=' + note)
" 2>&1)" || REPAIR_OUT=""

REAL_CLAUDE="$(printf '%s\n' "$REPAIR_OUT" | sed -n 's/^REAL_CLI=//p')"
printf '%s\n' "$REPAIR_OUT" | sed -n 's/^CHANGED=//p' | while IFS= read -r line; do ok "$line"; done
printf '%s\n' "$REPAIR_OUT" | sed -n 's/^NOTE=//p'    | while IFS= read -r line; do warn "$line"; done

if [ -n "$REAL_CLAUDE" ]; then
    ok "Real Claude CLI: $REAL_CLAUDE"
else
    warn "Could not find the real 'claude' CLI. If you use Claude Code, run later:"
    warn "    claudeguard set-cli-path /path/to/real/claude"
fi

# --- 6. LaunchAgent (autostart at login) ------------------------------------
info "Registering login-autostart LaunchAgent…"
mkdir -p "$HOME/Library/LaunchAgents"
/usr/bin/python3 - "$PLIST_PATH" "$INSTALL_DIR" "$MENU_PLIST_PATH" <<'PYPLIST'
import os, plistlib, sys
path, install, menu_path = sys.argv[1:]
with open(path, 'wb') as stream:
    plistlib.dump({'Label': 'com.claudeguard.daemon',
                  'ProgramArguments': [install + '/bin/ClaudeGuardMenuBar', '--daemon'],
                  'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False},
                  'StandardOutPath': os.path.expanduser('~/Library/Logs/ClaudeGuard/daemon.log'),
                  'StandardErrorPath': os.path.expanduser('~/Library/Logs/ClaudeGuard/daemon.err')}, stream)
with open(menu_path, 'wb') as stream:
    plistlib.dump({'Label': 'com.claudeguard.menubar',
                  'ProgramArguments': [install + '/ClaudeGuard.app/Contents/MacOS/ClaudeGuardMenuBar', '--menu-bar'],
                  'RunAtLoad': True, 'KeepAlive': {'SuccessfulExit': False},
                  'ProcessType': 'Interactive',
                  'StandardOutPath': os.path.expanduser('~/Library/Logs/ClaudeGuard/menu.log'),
                  'StandardErrorPath': os.path.expanduser('~/Library/Logs/ClaudeGuard/menu.err')}, stream)
PYPLIST

launchctl unload "$PLIST_PATH" 2>/dev/null || true

# --- 7. Root network helper via a LaunchDaemon (no sudoers) ------------------
# The user-session daemon has no root; it stages the desired /etc/hosts + pf
# rule in ~/.config/claudeguard/pending and touches a trigger file. This root
# LaunchDaemon watches that trigger and applies the vetted files. Needs your
# password ONCE now (to place the root-owned binary + plist); never again.
info "Installing the root network helper (LaunchDaemon — needs your password once)…"

# Private staging dir + trigger file the helper watches (must exist before load).
mkdir -p "$CONFIG_DIR/pending"
chmod 700 "$CONFIG_DIR/pending"
/usr/bin/python3 - "$CONFIG_DIR/pending/request" <<'PYTRIGGER'
import os, stat, sys
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
try:
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise SystemExit('Helper trigger must be a regular file')
finally:
    os.close(fd)
PYTRIGGER

HELPER_PLIST_BODY="$(/usr/bin/python3 - "$HELPER_SYS_DIR" "$CONFIG_DIR" <<'PYPLIST'
import os, plistlib, sys
root, config = sys.argv[1:]
print(plistlib.dumps({'Label': 'com.claudeguard.helper',
                     'ProgramArguments': [root + '/hosts-helper', config, str(os.getuid())],
                     'WatchPaths': [config + '/pending/request'], 'ThrottleInterval': 1,
                     'StandardOutPath': '/Library/Logs/ClaudeGuard/helper.log',
                     'StandardErrorPath': '/Library/Logs/ClaudeGuard/helper.err'}).decode())
PYPLIST
)"

install_root_helper() {   # $1 = sudo prefix ("" when already root)
    local S="$1"
    $S launchctl bootout system "$HELPER_PLIST" 2>/dev/null || true
    if [ -L "$HELPER_SYS_DIR" ]; then die "Refusing symlinked helper directory"; fi
    if [ -L /Library/Logs/ClaudeGuard ]; then die "Refusing symlinked helper log directory"; fi
    $S mkdir -p /Library/Logs/ClaudeGuard
    $S chown root:wheel /Library/Logs/ClaudeGuard
    $S chmod 755 /Library/Logs/ClaudeGuard
    $S mkdir -p "$HELPER_SYS_DIR"
    $S chown root:wheel "$HELPER_SYS_DIR"
    $S chmod 755 "$HELPER_SYS_DIR"
    $S rm -f "$HELPER_SYS_DIR/hosts-helper" "$HELPER_SYS_DIR/macos_network_helper.py"
    $S cp "$INSTALL_DIR/bin/hosts-helper" "$HELPER_SYS_DIR/hosts-helper"
    $S cp "$SOURCE_DIR/native/macos_network_helper.py" "$HELPER_SYS_DIR/macos_network_helper.py"
    $S chown root:wheel "$HELPER_SYS_DIR/hosts-helper" "$HELPER_SYS_DIR/macos_network_helper.py"
    $S chmod 644 "$HELPER_SYS_DIR/macos_network_helper.py"
    $S chmod 755 "$HELPER_SYS_DIR/hosts-helper"     # root-owned, not user-writable
    printf '%s\n' "$HELPER_PLIST_BODY" | $S tee "$HELPER_PLIST" >/dev/null
    $S chown root:wheel "$HELPER_PLIST"
    $S chmod 644 "$HELPER_PLIST"
    $S launchctl bootout system "$HELPER_PLIST" 2>/dev/null || true
    $S launchctl bootstrap system "$HELPER_PLIST" 2>/dev/null \
        || $S launchctl load -w "$HELPER_PLIST"
}

if [ "$(id -u)" -eq 0 ]; then
    rm -f "$LEGACY_SUDOERS" 2>/dev/null || true
    install_root_helper ""
else
    sudo rm -f "$LEGACY_SUDOERS" 2>/dev/null || true   # drop old NOPASSWD entry if upgrading
    install_root_helper "sudo"
fi
# The compiled copy in the user dir is never executed now; drop it.
rm -f "$INSTALL_DIR/bin/hosts-helper" 2>/dev/null || true
launchctl load "$PLIST_PATH"
launchctl load "$MENU_PLIST_PATH"

# --- 8. First-run: offer to whitelist the current public IP -----------------
# Best done while you're connected to your VPN right now.
CUR_IP="$(cd "$INSTALL_DIR" && python3 -c 'import sys; sys.path.insert(0,"."); from src.ip_checker import stun_public_ip; print(stun_public_ip() or "")' 2>/dev/null || true)"
if [ -n "$CUR_IP" ] && [ -r /dev/tty ]; then
    printf '\n%sYour current public IP is %s%s%s.\n' "$BOLD" "$CYN" "$CUR_IP" "$RST"
    printf '%sWhitelist it now? Only say yes if you are on your VPN right now. [y/N] %s' "$BOLD" "$RST"
    read -r ans < /dev/tty || ans=""
    case "$ans" in
        [Yy]*) "$INSTALL_DIR/bin/claudeguard" add-ip "$CUR_IP" >/dev/null 2>&1 && ok "Whitelisted $CUR_IP" ;;
        *)     info "Skipped. Add your VPN IP later: ${BOLD}claudeguard add-ip <IP>${RST}" ;;
    esac
fi

printf '\n%s\n' "${GRN}${BOLD}🎉 ClaudeGuard installed & running.${RST}"
printf '%s\n' "   The menu bar shield stays visible at login; dismissing the menu keeps it running. The guard runs independently."
printf '%s\n' "   ${DIM}Manage it:${RST} ${BOLD}claudeguard status${RST}  ·  ${BOLD}claudeguard add-ip <IP>${RST}"
if ! printf '%s' "$PATH" | tr ':' '\n' | grep -qx "$HOME/.local/bin"; then
    printf '%s\n' "   ${YLW}Note:${RST} add ~/.local/bin to your PATH to use 'claudeguard' directly:"
    printf '%s\n' "         ${DIM}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc${RST}"
fi
