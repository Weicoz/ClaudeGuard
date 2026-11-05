import ipaddress
import os
import socket
import subprocess
import time
import json
import stat
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

# The user daemon has no root, and we no longer use sudo/sudoers. Instead it
# stages a structured request and pokes a trigger file. The root LaunchDaemon
# validates it, merges current hosts and updates its own anchor.
# See native/macos_network_helper.py and install.sh.
CONFIG_DIR = os.path.expanduser("~/.config/claudeguard")
PENDING_DIR = os.path.join(CONFIG_DIR, "pending")
PENDING_REQUEST = os.path.join(PENDING_DIR, "request.json")
HELPER_STATUS = "/Library/Application Support/ClaudeGuard/status.json"
HELPER_BINARY = "/Library/Application Support/ClaudeGuard/hosts-helper"
REQUEST_FILE = os.path.join(PENDING_DIR, "request")

APEX_DOMAINS = [
    "claude.com",
    "claude.ai",
    "claude.usercontent.com",
    "anthropic.com",
    "anthropic.ai"
]

SUBDOMAIN_PREFIXES = [
    "", "www", "app", "api", "auth", "stats", "cdn", "assets",
    "console", "docs", "support", "feedback", "desktop-app-updates",
    "a-api", "a-cdn", "code", "status", "blog", "research", "events",
    "login", "register", "portal", "admin", "internal", "v1", "v2", "v3",
    "ws", "gateway", "proxy", "assets-proxy", "account", "settings", "billing"
]

KNOWN_RESOLVED_DOMAINS = [
    "claude.com", "www.claude.com", "console.claude.com", "docs.claude.com", "support.claude.com", "code.claude.com", "status.claude.com", "app.claude.com", "api.claude.com", "auth.claude.com",
    "claude.ai", "www.claude.ai", "app.claude.ai", "assets.claude.ai", "console.claude.ai", "a-cdn.claude.ai", "status.claude.ai", "api.claude.ai", "auth.claude.ai",
    "claude.usercontent.com", "www.claude.usercontent.com", "app.claude.usercontent.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "assets.anthropic.com", "console.anthropic.com", "docs.anthropic.com", "support.anthropic.com", "feedback.anthropic.com", "desktop-app-updates.anthropic.com", "a-api.anthropic.com", "a-cdn.anthropic.com", "status.anthropic.com", "events.anthropic.com", "portal.anthropic.com", "assets-proxy.anthropic.com", "billing.anthropic.com",
    "anthropic.ai", "www.anthropic.ai", "app.anthropic.ai", "api.anthropic.ai", "auth.anthropic.ai"
]

# External resolvers used to find the *real* server IPs. dig queries them
# directly and never consults /etc/hosts, so it still works after we've poisoned
# the hosts file with 0.0.0.0 entries.
EXTERNAL_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# Anthropic's own address ranges. pf only ever blocks IPs inside these, so an
# auxiliary page hosted on a shared CDN (e.g. the status page on CloudFront, the
# trust page on Cloudflare) never drags unrelated sites down with it. Every
# account-critical domain (claude.ai, app/api/console/auth/login.*) lives here.
ANTHROPIC_NETS = [
    ipaddress.ip_network("160.79.104.0/24"),
    ipaddress.ip_network("2607:6bc0::/32"),
]

# Fallback for when external DNS is unreachable, so pf still has something to drop.
FALLBACK_IPS = ["160.79.104.10", "2607:6bc0::10"]

# Small set of domains that actually exist and share Anthropic's dedicated IPs.
# pf blocks by IP, so resolving these is enough to discover every address the
# whole domain family sits on — no need to query dozens of subdomains, most of
# which are NXDOMAIN and just slow the block down.
PF_RESOLVE_DOMAINS = [
    "claude.ai", "www.claude.ai", "app.claude.ai", "api.claude.ai", "auth.claude.ai",
    "claude.com", "www.claude.com", "app.claude.com", "api.claude.com", "console.claude.com",
    "anthropic.com", "www.anthropic.com", "api.anthropic.com", "console.anthropic.com",
]

def _is_ip(text):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, text)
            return True
        except OSError:
            pass
    return False

def _in_anthropic_range(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ANTHROPIC_NETS)

def _dig(resolver, record_type, domain):
    """Returns (query_succeeded, ips). query_succeeded is False only when the
    resolver itself failed (timeout/unreachable) — an NXDOMAIN is a *successful*
    query with an empty answer, and must not trigger a pointless retry."""
    dig_bin = "/usr/bin/dig" if os.path.exists("/usr/bin/dig") else "dig"
    try:
        res = subprocess.run(
            [dig_bin, f"@{resolver}", "+short", "+time=1", "+tries=1", record_type, domain],
            capture_output=True, text=True, timeout=3
        )
    except Exception:
        return False, []
    if res.returncode != 0:
        return False, []
    ips = []
    for line in res.stdout.splitlines():
        line = line.strip()
        # +short can emit CNAME lines (trailing dot) — keep only literal IPs.
        if line and not line.endswith(".") and _is_ip(line):
            ips.append(line)
    return True, ips

def _resolve_one(domain):
    """A + AAAA for one domain. Batched dig is flaky, so it's one query each;
    per record type we stop at the first resolver that answers at all, only
    falling through to the next when a resolver is unreachable (an NXDOMAIN is a
    successful, empty answer and ends the loop)."""
    ips = set()
    for record_type in ("A", "AAAA"):
        for resolver in EXTERNAL_RESOLVERS:
            ok, found = _dig(resolver, record_type, domain)
            if ok:
                ips.update(found)
                break
    return ips

def resolve_ips(domains):
    """Resolve domains to literal IPv4+IPv6 via external DNS, bypassing the
    poisoned /etc/hosts. Domains are resolved in parallel to keep the block
    transition fast — a long resolve is a leak window before pf loads. This is
    what lets pf block the real servers even when a browser uses DoH and ignores
    the hosts file."""
    domains = list(domains)
    if not domains:
        return set()
    ips = set()
    with ThreadPoolExecutor(max_workers=min(16, len(domains))) as pool:
        for found in pool.map(_resolve_one, domains):
            ips.update(found)
    return ips

def resolve_domain_ips(domains):
    """The pf target set: Anthropic-owned IPs only (never a shared CDN), plus a
    fallback so a DNS outage can't leave pf with an empty table."""
    ips = {ip for ip in resolve_ips(domains) if _in_anthropic_range(ip)}
    ips.update(FALLBACK_IPS)
    return sorted(ips)

def generate_all_subdomains():
    domains = set(KNOWN_RESOLVED_DOMAINS)
    for apex in APEX_DOMAINS:
        domains.add(apex)
        for sub in SUBDOMAIN_PREFIXES:
            if sub:
                domains.add(f"{sub}.{apex}")
    return sorted(list(domains))

def sync_hosts_file(block_claude_domains, block_update_domains, config):
    """Submit one immutable request, serialize writers, require its root-owned receipt."""
    from src.policy import atomic_json, locked
    try:
        from native.macos_network_helper import domains
        blocked_domains = domains(generate_all_subdomains() + config.config.get("blocked_domains", []))
        updates = domains(config.config.get("update_domains", []))
        _ensure_pending()
        with locked(Path(PENDING_DIR) / "transaction.lock", timeout=30):
            addresses = set()
            if block_claude_domains:
                addresses.update(resolve_domain_ips(PF_RESOLVE_DOMAINS))
                custom = config.config.get("blocked_domains", [])
                if custom:
                    addresses.update(resolve_ips(custom))
            request = {"schema": 2, "request_id": uuid.uuid4().hex,
                       "block_claude_domains": bool(block_claude_domains),
                       "block_update_domains": bool(block_update_domains),
                       "claude_domains": blocked_domains, "update_domains": updates,
                       "ip_addresses": sorted(addresses)}
            atomic_json(PENDING_REQUEST, request)
            fd = os.open(REQUEST_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("请求触发器必须是普通文件")
                stream.write(request["request_id"])
                stream.flush()
                os.fsync(stream.fileno())
            if os.geteuid() == 0:
                uid = os.stat(CONFIG_DIR).st_uid
                subprocess.run([HELPER_BINARY, CONFIG_DIR, str(uid)], check=True, timeout=30, capture_output=True)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                try:
                    fd = os.open(HELPER_STATUS, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    try:
                        info = os.fstat(fd)
                        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
                            raise ValueError("系统助手回执不可信")
                        with os.fdopen(fd, encoding="utf-8") as stream:
                            fd = None
                            result = json.load(stream)
                    finally:
                        if fd is not None:
                            os.close(fd)
                    if result.get("schema") == 2 and result.get("request_id") == request["request_id"]:
                        if result.get("ok") is not True or result.get("blocked") != request["block_claude_domains"] or result.get("updates_blocked") != request["block_update_domains"]:
                            raise RuntimeError(result.get('error') or "系统助手未能应用请求")
                        return True, "系统助手已确认域名和防火墙规则"
                except FileNotFoundError:
                    pass
                time.sleep(0.1)
            raise TimeoutError("系统助手未确认请求；请升级或检查系统助手")
    except Exception as error:
        return False, f"网络拦截设置失败：{error}"


def _ensure_pending():
    os.makedirs(PENDING_DIR, mode=0o700, exist_ok=True)
    if os.path.islink(PENDING_DIR):
        raise ValueError("pending 目录不得是符号链接")
    os.chmod(PENDING_DIR, 0o700)
