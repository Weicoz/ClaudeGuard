#!/usr/bin/python3
"""Root-owned, isolated macOS network worker. Imports standard library only."""
import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

LIMIT = 1048576
ANCHOR = 'com.apple/claudeguard'
ROOT = Path('/Library/Application Support/ClaudeGuard')
HOSTS = Path('/etc/hosts')
HEADERS = ('# BEGIN CLAUDEGUARD BLOCKS\n', '# BEGIN CLAUDEGUARD UPDATE BLOCKS\n')
FOOTERS = ('# END CLAUDEGUARD BLOCKS\n', '# END CLAUDEGUARD UPDATE BLOCKS\n')


def atomic_text(path, text, mode=0o600):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def trusted_read(path, uid, directory_fd=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_size > LIMIT or info.st_mode & 0o022:
            raise ValueError('untrusted regular file')
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            data = stream.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError('request too large')
        return data.decode('utf-8')
    finally:
        if fd is not None:
            os.close(fd)


def checked_directory(path, uid, directory_fd=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
    info = os.fstat(fd)
    if info.st_uid != uid or info.st_mode & 0o022:
        os.close(fd)
        raise ValueError('untrusted directory')
    return fd


def domains(values):
    if not isinstance(values, list) or len(values) > 4096:
        raise ValueError('invalid domain list')
    for value in values:
        if not isinstance(value, str) or len(value) > 253 or not value or any(
                not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                for label in value.split('.')):
            raise ValueError('invalid domain')
    return sorted(set(values))


def parse_request(text):
    value = json.loads(text)
    keys = {'schema', 'request_id', 'block_claude_domains', 'block_update_domains', 'claude_domains', 'update_domains', 'ip_addresses'}
    if not isinstance(value, dict) or set(value) != keys or type(value['schema']) is not int or value['schema'] != 2:
        raise ValueError('invalid request schema')
    if not isinstance(value['request_id'], str) or not re.fullmatch('[a-f0-9]{32}', value['request_id']):
        raise ValueError('invalid request id')
    for key in ('block_claude_domains', 'block_update_domains'):
        if type(value[key]) is not bool:
            raise ValueError('invalid block flag')
    for key in ('claude_domains', 'update_domains'):
        value[key] = domains(value[key])
    if not isinstance(value['ip_addresses'], list) or len(value['ip_addresses']) > 4096 or any(not isinstance(ip, str) or '%' in ip for ip in value['ip_addresses']):
        raise ValueError('invalid address list')
    try:
        value['ip_addresses'] = sorted({str(ipaddress.ip_address(ip)) for ip in value['ip_addresses']})
    except ValueError:
        raise ValueError('invalid address') from None
    if value['block_claude_domains'] and not value['ip_addresses']:
        raise ValueError('blocked request needs addresses')
    return value


def merged_hosts(current, request):
    result, section = [], None
    for line in current.splitlines(keepends=True):
        marker = line.rstrip('\r\n') + '\n'
        if marker in HEADERS:
            if section is not None:
                raise ValueError('nested hosts block')
            section = HEADERS.index(marker)
        elif marker in FOOTERS:
            if section != FOOTERS.index(marker):
                raise ValueError('unmatched hosts footer')
            section = None
        elif section is None:
            result.append(line)
    if section is not None:
        raise ValueError('unterminated hosts block')
    content = ''.join(result)
    if content and not content.endswith('\n'):
        content += '\n'
    for index, (flag, key) in enumerate((('block_claude_domains', 'claude_domains'), ('block_update_domains', 'update_domains'))):
        if request[flag]:
            content += HEADERS[index]
            content += ''.join(f'{ip}\t{domain}\n' for domain in request[key] for ip in ('0.0.0.0', '127.0.0.1', '::1'))
            content += FOOTERS[index]
    if len(content.encode()) > LIMIT:
        raise ValueError('hosts output too large')
    return content


class Worker:
    def __init__(self, config, uid, root=ROOT, hosts=HOSTS, pfctl='/sbin/pfctl'):
        self.config, self.uid, self.root, self.hosts, self.pfctl = Path(config), uid, Path(root), Path(hosts), pfctl
        self.root.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd = checked_directory(self.root, os.geteuid())
        os.close(fd)

    def pf(self, *args):
        return self.command(self.pfctl, *args)

    def command(self, *args):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('network application deadline exceeded')
        return subprocess.run(args, capture_output=True, text=True, check=True, timeout=min(5, remaining))

    def boot_id(self):
        value = self.command('/usr/sbin/sysctl', '-n', 'kern.bootsessionuuid').stdout.strip()
        if not re.fullmatch('[A-Fa-f0-9-]{36}', value):
            raise ValueError('invalid boot session')
        return value

    def apply(self, request):
        self.deadline = time.monotonic() + 10
        current = trusted_read(self.hosts, os.geteuid())
        content = merged_hosts(current, request)
        token_path = self.root / 'pf-token'
        rules = self.pf('-sr').stdout
        if re.search(r'\bto\s+<claude_guard>', rules):
            raise RuntimeError('legacy global PF rules require administrator migration before upgrade')
        boot = self.boot_id()
        lease = json.loads(trusted_read(token_path, os.geteuid())) if token_path.exists() else {}
        token = lease.get('token', '')
        if not isinstance(token, str) or (token and not re.fullmatch('[0-9]{1,20}', token)):
            raise ValueError('invalid PF enable token')
        if request['block_claude_domains']:
            if not re.search(r'\banchor\s+"com\.apple/(?:\*|claudeguard)"', rules):
                raise RuntimeError('main PF ruleset does not reference the ClaudeGuard anchor')
            rules_path = self.root / 'pf.verified'
            text = 'table <claude_guard> persist { ' + ' '.join(request['ip_addresses']) + ' }\n'
            text += 'block drop out quick proto { tcp, udp } to <claude_guard>\n'
            atomic_text(rules_path, text)
            try:
                self.pf('-a', ANCHOR, '-f', str(rules_path))
            finally:
                rules_path.unlink(missing_ok=True)
            if not token or lease.get('boot') != boot:
                enabled = self.pf('-E')
                match = re.search(r'Token\s*:\s*(\d+)', enabled.stdout + enabled.stderr)
                if not match:
                    raise RuntimeError('PF did not return an enable token')
                try:
                    atomic_text(token_path, json.dumps({'boot': boot, 'token': match[1]}))
                except OSError:
                    self.pf('-X', match[1])
                    raise
            for address in request['ip_addresses']:
                self.pf('-k', '::/0' if ':' in address else '0.0.0.0/0', '-k', address)
            atomic_text(self.hosts, content, 0o644)
        else:
            atomic_text(self.hosts, content, 0o644)
            self.pf('-a', ANCHOR, '-F', 'rules')
            if token_path.exists():
                if token and lease.get('boot') == boot:
                    self.pf('-X', token)
                token_path.unlink()
        self.command('/usr/bin/dscacheutil', '-flushcache')
        self.command('/usr/bin/killall', '-HUP', 'mDNSResponder')

    def run(self):
        with open(self.root / 'apply.lock', 'a+b') as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX)
            config_fd = checked_directory(self.config, self.uid)
            pending_fd = None
            try:
                pending_fd = checked_directory('pending', self.uid, config_fd)
                request = parse_request(trusted_read('request.json', self.uid, pending_fd))
            finally:
                if pending_fd is not None:
                    os.close(pending_fd)
                os.close(config_fd)
            status = {'schema': 2, 'request_id': request['request_id'], 'ok': False,
                      'blocked': request['block_claude_domains'], 'updates_blocked': request['block_update_domains']}
            try:
                self.apply(request)
                status['ok'] = True
            except Exception as error:
                status['error'] = str(error) if isinstance(error, (ValueError, RuntimeError)) else 'system application failed'
                raise
            finally:
                status['updated_at'] = time.time()
                atomic_text(self.root / 'status.json', json.dumps(status), 0o644)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--uid', type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or args.uid < 0:
        raise SystemExit('root and a valid request owner are required')
    try:
        Worker(args.config, args.uid).run()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        raise SystemExit('network request rejected or system application failed') from None


if __name__ == '__main__':
    main()
