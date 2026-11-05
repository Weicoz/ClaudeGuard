import urllib.request
import json
import socket
import struct
import os
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

IP_CHECK_SERVICES = [
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/all.json",
    "https://ipinfo.io/json",
    "https://icanhazip.com"
]

STUN_SERVERS = [
    ("stun.l.google.com", 19302),
    ("stun1.l.google.com", 19302),
    ("stun.cloudflare.com", 3478),
]

def _parse_stun(data, transaction_id=None):
    """Validate a complete STUN binding response before reading its address."""
    cookie = b"\x21\x12\xA4\x42"
    if len(data) < 20 or data[:2] != b"\x01\x01" or data[4:8] != cookie:
        return None
    length = int.from_bytes(data[2:4], 'big')
    if length % 4 or len(data) != 20 + length or (transaction_id is not None and data[8:20] != transaction_id):
        return None
    i, result = 20, None
    while i + 4 <= len(data):
        kind, size = struct.unpack('!HH', data[i:i + 4])
        start = i + 4
        end = start + size
        padded = end + (-size % 4)
        if padded > len(data):
            return None
        if kind in (0x0020, 0x0001) and size >= 4:
            family = data[start + 1]
            count = {1: 4, 2: 16}.get(family)
            if count is None or size != count + 4 or data[start] != 0:
                return None
            address = data[start + 4:end]
            if kind == 0x0020:
                address = bytes(a ^ b for a, b in zip(address, cookie + data[8:20]))
            result = str(ipaddress.ip_address(address))
        i = padded
    return result if i == len(data) else None

def stun_public_ip(timeout=1.0):
    """Public IP via STUN — one UDP round-trip, faster than HTTP. IP or None;
    tries each server in turn (some networks block UDP/STUN, HTTP covers those)."""
    deadline = time.monotonic() + timeout
    for host, port in STUN_SERVERS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            txid = os.urandom(12)
            msg = b"\x00\x01\x00\x00" + b"\x21\x12\xA4\x42" + txid
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(remaining)
            try:
                s.connect((host, port))
                s.send(msg)
                data = s.recv(2048)
            finally:
                s.close()
            ip = _parse_stun(data, txid)
            if ip:
                try:
                    ipaddress.ip_address(ip)
                    return ip
                except ValueError:
                    pass
        except Exception:
            continue
    return None

def fetch_public_ip(timeout=2.0, mode="http", proxy=None):
    """Resolve one transport only; no fallback to the other transport."""
    if mode not in ("http", "stun"):
        return None, "单协议检测仅支持 http 或 stun 模式"
    if mode == "stun":
        ip = stun_public_ip(timeout=min(timeout, 1.0))
        return (ip, None) if ip else (None, "未能获取 STUN 出口 IP")

    open_url = urllib.request.urlopen
    if proxy:
        open_url = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        ).open
    deadline = time.monotonic() + timeout
    for service in IP_CHECK_SERVICES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            req = urllib.request.Request(
                service,
                headers={"User-Agent": "ClaudeGuard/1.0"}
            )
            with open_url(req, timeout=remaining) as resp:
                raw = resp.read(4097)
                if len(raw) > 4096:
                    continue
                data = raw.decode("utf-8").strip()
                if data.startswith("{"):
                    payload = json.loads(data)
                    ip = payload.get("ip") or payload.get("ip_addr")
                else:
                    ip = data
                if isinstance(ip, str) and '%' not in ip:
                    return str(ipaddress.ip_address(ip.strip())), None
        except Exception:
            continue

    return None, "未能获取 HTTP 出口 IP，请检查网络或稍后重试"

def is_ip_allowed(current_ip, allowed_list):
    """
    Checks if current_ip matches any IP or CIDR range in allowed_list.
    """
    if not current_ip or not allowed_list:
        return False

    try:
        user_ip_obj = ipaddress.ip_address(current_ip)
    except ValueError:
        return False

    for entry in allowed_list:
        entry = entry.strip()
        if not entry:
            continue
        try:
            # Check exact IP or CIDR range
            if "/" in entry:
                net = ipaddress.ip_network(entry, strict=False)
                if user_ip_obj in net:
                    return True
            else:
                allowed_obj = ipaddress.ip_address(entry)
                if user_ip_obj == allowed_obj:
                    return True
        except ValueError:
            continue

    return False

def perform_ip_check(allowed_ips, timeout=2.0, mode="both", proxy=None):
    """Return (display_ip, allowed, error). Both transports must be verified.

    A confirmed unlisted IP takes precedence over a missing result. Missing
    results otherwise return ip=None so callers classify the verdict as offline.
    """
    if mode == "auto":  # migrate legacy configurations without a racing policy
        mode = "both"
    if mode not in ("both", "http", "stun"):
        return None, False, "ip_check_mode 配置有误，可选值为 both、http、stun"
    modes = ("http", "stun") if mode == "both" else (mode,)
    with ThreadPoolExecutor(max_workers=len(modes)) as pool:
        kwargs = {"proxy": proxy} if proxy else {}
        futures = {m: pool.submit(fetch_public_ip, timeout=timeout, mode=m, **kwargs) for m in modes}
        results = {m: f.result() for m, f in futures.items()}
    ips = {m: ip for m, (ip, _) in results.items() if ip}
    display = "; ".join(f"{m.upper()}: {ips.get(m) or '未获取'}" for m in modes)
    if mode != "both" and ips:
        display = next(iter(ips.values()))
    if any(not is_ip_allowed(ip, allowed_ips) for ip in ips.values()):
        return display, False, None
    if len(ips) != len(modes):
        errors = "; ".join(f"{m.upper()}: {err or '未获取出口 IP'}" for m, (ip, err) in results.items() if not ip)
        return None, False, errors
    return display, True, None
