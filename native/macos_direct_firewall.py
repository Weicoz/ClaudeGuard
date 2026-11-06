#!/usr/bin/python3
"""Claude 直连 PF 规则的独立安装、维护和卸载入口；仅使用标准库。"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import fcntl
import ipaddress
import json
import math
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path('/Library/Application Support/ClaudeGuard/DirectFirewall')
PLIST = Path('/Library/LaunchDaemons/com.claudeguard.direct-firewall.plist')
LABEL = 'com.claudeguard.direct-firewall'
PARENT_ANCHOR = 'com.apple/claudeguard'
ANCHOR = PARENT_ANCHOR + '/direct'
TABLE = 'claudeguard_direct'
NETWORKS = ('160.79.104.0/21', '153.61.224.0/22', '2607:6bc0::/32')
# shortcut: 仅维护列明域名的解析 IP；未知子域名零遗漏需域名感知的出站过滤器。
DOMAINS = (
    'servd-anthropic-website.b-cdn.net', 'anthropic.com.cdn.cloudflare.net',
    'anthropic.auth0.com', 'anthropic-com.ghost.io', 'claude.ai', 'anthropic.com',
    'claude.com', 'claudeusercontent.com', 'claudemcpcontent.com', 'clau.de',
    'claudemcpclient.com', 'claude.dev', 'claude.app', 'datadoghq.com',
    'api.anthropic.com', 'http-intake.logs.us5.datadoghq.com',
    'bridge.claudeusercontent.com', 'downloads.claude.ai',
)


def command(*args):
    return subprocess.run(args, capture_output=True, text=True, check=True, timeout=15)


def atomic_text(path, content, mode=0o644):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def trusted_json(path, owner):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd) as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or info.st_size > 1048576:
            raise ValueError('防火墙状态文件不可信')
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError('防火墙状态格式错误')
    return value


def public_addresses(values):
    result = set()
    for value in values:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if address.is_global and not address.is_multicast:
            result.add(str(address))
    return result


def physical_interfaces():
    # 只在实体出口拦截；utun 内的原始目标包仍须交给代理封装。
    return sorted(name for _, name in socket.if_nameindex()
                  if re.fullmatch(r'(?:en|bridge|bond)\d+', name))


def target_networks(addresses):
    networks = [ipaddress.ip_network(value) for value in NETWORKS]
    return list(NETWORKS) + sorted(address for address in public_addresses(addresses)
                                  if not any(ipaddress.ip_address(address) in network for network in networks))


def render_rules(addresses, interfaces):
    if not interfaces or any(not re.fullmatch(r'(?:en|bridge|bond)\d+', name) for name in interfaces):
        raise ValueError('未找到支持的实体网络接口，未加载规则')
    targets = target_networks(addresses)
    return (f'table <{TABLE}> persist {{ ' + ' '.join(targets) + ' }\n'
            + 'block drop out quick on { ' + ' '.join(interfaces) + f' }} to <{TABLE}>\n')


def resolve_domain(domain):
    found = set()
    successful = True
    for kind in ('A', 'AAAA'):
        answered = False
        for resolver in ('1.1.1.1', '8.8.8.8'):
            try:
                result = subprocess.run(['/usr/bin/dig', '@' + resolver, '+noall', '+comments', '+answer', '+tcp',
                                         '+time=1', '+tries=1', kind, domain],
                                        capture_output=True, text=True, timeout=3)
            except subprocess.SubprocessError:
                continue
            if result.returncode == 0 and re.search(r'status: (?:NOERROR|NXDOMAIN),', result.stdout):
                found.update(public_addresses(line.split()[-1] for line in result.stdout.splitlines()
                                              if line.strip() and not line.startswith(';')))
                answered = True
                break
        successful = successful and answered
    return domain, found, successful


def merged_addresses(previous, results, now):
    seen = previous.get('seen', {})
    if not isinstance(seen, dict) or len(seen) > 4096:
        raise ValueError('防火墙地址缓存过大或格式错误')
    seen = {ip: stamp for ip, stamp in seen.items()
            if ip in public_addresses([ip]) and isinstance(stamp, (float, int)) and not isinstance(stamp, bool)
            and math.isfinite(stamp) and stamp >= 0}
    missing = []
    complete = True
    for domain, addresses, successful in results:
        complete = complete and successful
        if not addresses:
            missing.append(domain)
        for address in public_addresses(addresses):
            seen[address] = now
    # DNS 失败时不移除旧地址；完整解析成功后保留一天，兼容客户端 DNS 缓存。
    if complete:
        seen = {ip: stamp for ip, stamp in seen.items() if now - stamp <= 86400}
    if len(seen) > 4096:
        raise ValueError('防火墙地址缓存超过上限，保留原规则')
    return seen, missing


class Firewall:
    def __init__(self, root=ROOT, plist=PLIST):
        self.root, self.plist = Path(root), Path(plist)

    def pf(self, *args):
        return command('/sbin/pfctl', *args)

    def boot(self):
        value = command('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid').stdout.strip()
        if not re.fullmatch(r'[A-Fa-f0-9-]{36}', value):
            raise ValueError('无法确认系统启动标识')
        return value

    def prepare(self):
        for path in reversed((self.root, *self.root.parents)):
            if not path.exists() and not path.is_symlink():
                path.mkdir(mode=0o755)
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
                raise ValueError('防火墙安装路径不可信')

    def require_anchor(self):
        rules = self.pf('-sr').stdout
        if not re.search(r'(?m)^\s*anchor\s+"com\.apple/(?:\*|claudeguard)"(?:\s+all)?\s*$', rules):
            raise RuntimeError('系统 PF 缺少专属锚点入口，未重载全局规则')
        parent = self.pf('-a', PARENT_ANCHOR, '-sr').stdout
        if not re.search(r'(?m)^\s*anchor\s+"(?:direct|/com\.apple/claudeguard/direct)"(?:\s+all)?\s*$', parent):
            raise RuntimeError('请先更新 ClaudeGuard 系统助手并重新检测，建立 direct 子锚点入口')

    def apply(self, seen, missing):
        self.require_anchor()
        state_path, lease_path = self.root / 'status.json', self.root / 'lease.json'
        previous = trusted_json(state_path, os.geteuid()) if state_path.exists() else {}
        lease = trusted_json(lease_path, os.geteuid()) if lease_path.exists() else {}
        boot = self.boot()
        token = lease.get('token', '')
        if not isinstance(token, str) or (token and not re.fullmatch(r'\d{1,20}', token)):
            raise ValueError('PF 引用标识错误')
        interfaces = physical_interfaces()
        content = render_rules(seen, interfaces)
        path = self.root / 'rules.pf'
        old = path.read_text() if path.exists() else None
        acquired, loaded = '', False
        try:
            atomic_text(path, content)
            self.pf('-n', '-a', ANCHOR, '-f', str(path))
            self.pf('-a', ANCHOR, '-f', str(path))
            loaded = True
            enabled_before = re.search(r'Status:\s*Enabled', self.pf('-si').stdout) is not None
            if lease.get('boot') != boot or not token or not enabled_before:
                enabled = self.pf('-E')
                match = re.search(r'Token\s*:\s*(\d{1,20})', enabled.stdout + enabled.stderr)
                if not match:
                    raise RuntimeError('PF 未返回启用引用，请检查系统 PF 状态')
                acquired = match[1]
                atomic_text(lease_path, json.dumps({'boot': boot, 'token': acquired}), 0o600)
            self.verify(seen)
            targets = set(target_networks(seen))
            added = targets - set(previous.get('targets', []))
            if previous.get('boot') != boot or previous.get('interfaces') != interfaces:
                added = targets
            for address in sorted(added):
                self.pf('-k', '::/0' if ':' in address else '0.0.0.0/0', '-k', address)
            atomic_text(state_path, json.dumps({'installed': True, 'applied_at': time.time(), 'boot': boot,
                                              'targets': sorted(targets), 'seen': seen,
                                              'interfaces': interfaces, 'unresolved': missing}, ensure_ascii=False))
        except Exception:
            if old is not None:
                atomic_text(path, old)
                if loaded:
                    self.pf('-a', ANCHOR, '-f', str(path))
            elif loaded:
                self.pf('-a', ANCHOR, '-F', 'rules')
            if acquired:
                self.pf('-X', acquired)
                if lease:
                    atomic_text(lease_path, json.dumps(lease), 0o600)
                else:
                    lease_path.unlink(missing_ok=True)
            raise

    def verify(self, addresses):
        self.require_anchor()
        actual = self.pf('-a', ANCHOR, '-sr').stdout
        if f'<{TABLE}>' not in actual or 'block drop out quick' not in actual:
            raise RuntimeError('PF 规则回读未通过')
        interfaces = physical_interfaces()
        if not interfaces or any(not re.search(r'\b' + name + r'\b', actual) for name in interfaces):
            raise RuntimeError('当前实体网卡尚未全部覆盖，请刷新规则')
        for interface in interfaces:
            details = self.pf('-v', '-s', 'Interfaces', '-i', interface).stdout
            if not details.strip() or re.search(r'\bskip\b', details, re.IGNORECASE):
                raise RuntimeError('实体网卡存在 PF 跳过规则或无法检查：' + interface)
        actual_targets = {str(ipaddress.ip_network(line.strip())) for line in
                          self.pf('-a', ANCHOR, '-t', TABLE, '-T', 'show').stdout.splitlines() if line.strip()}
        expected = {str(ipaddress.ip_network(value)) for value in target_networks(addresses)}
        if actual_targets != expected or not re.search(r'Status:\s*Enabled', self.pf('-si').stdout):
            raise RuntimeError('PF 目标表或启用状态回读未通过')

    def refresh(self):
        self.prepare()
        lock_path = self.root / 'apply.lock'
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state_path = self.root / 'status.json'
            previous = trusted_json(state_path, os.geteuid()) if state_path.exists() else {}
            # 启动先恢复固定网段和缓存，DNS 查询不能推迟基础阻断。
            self.apply(previous.get('seen', {}), list(DOMAINS))
            with ThreadPoolExecutor(max_workers=6) as pool:
                results = list(pool.map(resolve_domain, DOMAINS))
            seen, missing = merged_addresses(previous, results, time.time())
            self.apply(seen, missing)

    def install(self):
        self.prepare()
        if self.plist.is_symlink():
            raise ValueError('防火墙启动项路径不可信')
        existing = [self.root / name for name in ('firewall.py', 'rules.pf', 'status.json', 'lease.json')]
        existing += [self.plist]
        if any(path.exists() for path in existing):
            backup = Path(tempfile.mkdtemp(prefix='DirectFirewall-backup-', dir=self.root.parent))
            for path in existing:
                if path.exists():
                    if path.is_symlink() or not path.is_file():
                        raise ValueError('旧防火墙安装文件不可信')
                    shutil.copy2(path, backup / path.name)
            print('原防火墙文件备份：' + str(backup))
        script = Path(__file__).resolve().read_text()
        atomic_text(self.root / 'firewall.py', script)
        self.refresh()
        job = {'Label': LABEL, 'ProgramArguments': ['/usr/bin/python3', '-I', str(self.root / 'firewall.py'), 'refresh'],
               'RunAtLoad': True, 'StartInterval': 300, 'ProcessType': 'Background'}
        atomic_text(self.plist, plistlib.dumps(job).decode())
        subprocess.run(['/bin/launchctl', 'bootout', 'system/' + LABEL], capture_output=True, timeout=15)
        command('/bin/launchctl', 'bootstrap', 'system', str(self.plist))
        print('已安装直连防火墙；每 5 分钟维护地址与实体网卡。退出 ClaudeGuard 或代理不会卸载规则。')
        print('域名后缀仅覆盖已维护的解析地址；共享 CDN IP 的其他网站直连也会受限。')

    def uninstall(self):
        if not self.root.exists() and not self.plist.exists():
            print('直连防火墙未安装。')
            return
        self.prepare()
        subprocess.run(['/bin/launchctl', 'bootout', 'system/' + LABEL], capture_output=True, timeout=15)
        fd = os.open(self.root / 'apply.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a+b') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            lease_path = self.root / 'lease.json'
            lease = trusted_json(lease_path, os.geteuid()) if lease_path.exists() else {}
            token = lease.get('token', '')
            if not isinstance(token, str) or (token and not re.fullmatch(r'\d{1,20}', token)):
                raise ValueError('PF 引用标识错误，未释放其他引用')
            self.pf('-a', ANCHOR, '-F', 'rules')
            if TABLE in self.pf('-a', ANCHOR, '-s', 'Tables').stdout.split():
                self.pf('-a', ANCHOR, '-t', TABLE, '-T', 'kill')
            if token and lease.get('boot') == self.boot():
                self.pf('-X', token)
            self.plist.unlink(missing_ok=True)
            for name in ('firewall.py', 'rules.pf', 'status.json', 'lease.json'):
                (self.root / name).unlink(missing_ok=True)
        (self.root / 'apply.lock').unlink(missing_ok=True)
        self.root.rmdir()
        print('已卸载直连防火墙；其他 PF 规则、ClaudeGuard 防护、hosts 均保留。')


def show_status():
    path = ROOT / 'status.json'
    if not path.exists():
        print('直连防火墙：未安装或尚无成功应用记录。')
        return
    data = trusted_json(path, 0)
    print('直连防火墙：' + ('已安装' if PLIST.exists() else '安装不完整'))
    print('最近成功应用：' + time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['applied_at'])))
    print(f'目标地址/网段：{len(data["targets"])}；实体接口：' + ', '.join(data['interfaces']))
    if data['unresolved']:
        print('未解析域名（保留旧地址）：' + ', '.join(data['unresolved']))
    print('这是最近应用记录；实时内核状态需管理员执行 firewall verify 检查。')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'uninstall', 'refresh', 'status', 'preview', 'verify'))
    args = parser.parse_args()
    if args.action == 'preview':
        print(render_rules([], physical_interfaces()))
        print('待维护的域名（不代表通配符覆盖）：\n' + '\n'.join(DOMAINS))
        return
    if args.action == 'status':
        show_status()
        return
    if sys.platform != 'darwin':
        raise SystemExit('此功能只支持 macOS。')
    if os.geteuid() != 0:
        if args.action == 'refresh':
            raise SystemExit('刷新需要管理员权限。')
        shell = shlex.join(['/usr/bin/python3', '-I', str(Path(__file__).resolve()), args.action])
        script = 'do shell script ' + json.dumps(shell) + ' with administrator privileges'
        result = subprocess.run(['/usr/bin/osascript', '-e', script], capture_output=True, text=True)
        print(result.stdout.strip() or result.stderr.strip())
        raise SystemExit(result.returncode)
    worker = Firewall()
    if args.action == 'verify':
        state = trusted_json(ROOT / 'status.json', 0)
        if state.get('boot') != worker.boot():
            raise RuntimeError('没有本次开机的成功应用记录，请重新安装或刷新规则')
        worker.verify(state['seen'])
        print('已验证：PF 已启用，专属规则、目标表和当前实体网卡覆盖一致。')
        print('代理可用和目标直连阻断仍需通过独立测试连接验收。')
    else:
        getattr(worker, args.action)()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print('直连防火墙操作失败：' + str(error), file=sys.stderr)
        raise SystemExit(1)
