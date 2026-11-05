"""
The brain: the one place that decides "may Claude run right now".

Verdict: "allowed" (protection off, or IP whitelisted) / "blocked" (online, IP
not whitelisted) / "offline" (IP can't be verified). Fail closed — only a
confirmed "allowed" gets through.

The source of truth is the daemon (main.swift), which publishes its verdict to
state.json on every check. Every consumer (the claude wrapper, the launcher, the
CLI) reads that same file, so the components can never disagree. If the daemon is
down (file missing or stale) the brain runs its own STUN-first check, so
protection never drops out silently.
"""
import json
import os
import time

from src.ip_checker import perform_ip_check
from src import policy
from pathlib import Path

STATE_PATH = os.path.expanduser("~/.config/claudeguard/state.json")
# The daemon rewrites state.json at least every 3s; 7s tolerates one missed tick.
STATE_MAX_AGE_SECONDS = 7.0


def read_daemon_state(max_age=None):
    """The daemon's state dict while it's fresh, or None if missing/stale."""
    try:
        with open(STATE_PATH) as f:
            d = json.load(f)
        if max_age is None:
            interval = policy.settings({"check_interval": d.get("check_interval", 3)})["check_interval"]
            max_age = max(STATE_MAX_AGE_SECONDS, interval + 4)
        stamp = d.get("updated_at", 0)
        if isinstance(stamp, bool) or not isinstance(stamp, (int, float)):
            return None
        if d.get('state') not in ('allowed', 'blocked', 'offline', 'disabled'):
            return None
        if 0 <= time.time() - stamp <= max_age:
            return d
    except Exception:
        pass
    return None


def daemon_is_up():
    """True if the daemon is running and publishing fresh state."""
    return read_daemon_state() is not None


def _same_policy(previous, current):
    if not isinstance(previous, dict):
        return False
    try:
        old, new = policy.settings(previous), policy.settings(current)
        defaults = {'allowed_ips': [], 'protection_enabled': True, 'http_proxy': ''}
        keys = (*policy.DEFAULTS, 'allowed_ips', 'protection_enabled', 'http_proxy', 'ip_check_mode')
        return all(old.get(key, defaults.get(key)) == new.get(key, defaults.get(key)) for key in keys)
    except (ValueError, TypeError):
        return False


def get_verdict(config, timeout=2.0, allow_fallback=True):
    """
    Returns (verdict, ip, err), verdict ∈ "allowed"/"blocked"/"offline".

    Order: protection off → allowed; the daemon's verdict (instant); else, when
    allow_fallback, our own configured check. allow_fallback=False returns
    "offline" while the daemon is down — for tight loops that would rather skip a
    tick than block on the network.
    """
    try:
        policy.settings(config.config)
    except (ValueError, TypeError):
        return "blocked", None, "配置无效，暂不放行"
    if not config.protection_enabled:
        return "allowed", None, None

    st = read_daemon_state()
    if st is not None and st.get('enforcement_confirmed') is False:
        return 'blocked', st.get('ip'), '系统防护执行未确认，请查看守护日志'
    if policy.advanced(config.config):
        if not allow_fallback and (st is None or not _same_policy(st.get('policy_config'), config.config)):
            return 'offline', None, '后台守护未运行，或配置尚未确认'
        result = policy.check({**config.config, "ip_check_mode": config.ip_check_mode}, Path(config.path).parent)
        return result['state'], result.get('ip'), result.get('error')

    if (st is not None
            and st.get("access_mode", "whitelist") == "whitelist"
            and st.get("detect_ip_change", False) is False
            and st.get("protection_enabled") == config.protection_enabled
            and st.get("ip_check_mode") == config.ip_check_mode
            and st.get("allowed_ips") == config.allowed_ips
            and (st.get("http_proxy") or "") == (config.config.get("http_proxy") or "")):
        v = st.get("state", "offline")
        if v == "disabled":  # the daemon has its own vocabulary; normalise it
            return "allowed", st.get("ip"), None
        return v, st.get("ip"), None

    if not allow_fallback:
        return "offline", None, "后台守护未运行，或检测结果与当前配置不一致"

    ip, is_allowed, err = perform_ip_check(config.allowed_ips, timeout=timeout, mode=config.ip_check_mode, proxy=config.config.get("http_proxy") or None)
    if ip is None:
        return "offline", None, err
    return ("allowed" if is_allowed else "blocked"), ip, err


def resolve_display_ip(config, timeout=2.0):
    """The current public IP for display only, never for a decision. Prefers the
    daemon's last known IP, else a live configured lookup. IP string or None."""
    st = read_daemon_state()
    if st is not None:
        ip = st.get("ip")
        if ip and ip not in ("No Internet", "…"):
            return ip
    try:
        ip, _, _ = perform_ip_check(config.allowed_ips, timeout=timeout, mode=config.ip_check_mode, proxy=config.config.get('http_proxy') or None)
        return ip
    except Exception:
        return None
