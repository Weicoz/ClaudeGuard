#!/usr/bin/env python3
"""Claude-W window management integrated from Weicoz/claude-w (0f001d1)."""

import argparse
from collections import deque
from contextlib import nullcontext
from datetime import datetime, time as clock_time, timedelta, timezone
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import resource
import subprocess
import sys
import time
from zoneinfo import ZoneInfo

HOME = Path.home()
LABEL = "com.weicoz.claude-window"
PLIST = HOME / "Library/LaunchAgents" / f"{LABEL}.plist"
PREFS = HOME / "Library/Preferences/com.appshub.bettbox.plist"
CACHE = HOME / ".claude/rl-cache.json"
BASE = HOME / ".local/state/claude-window"
STATE = BASE / "state.json"
CONFIG = BASE / "config.json"
HISTORY = BASE / "requests.jsonl"
LIVE_CACHE = BASE / "usage-cache.json"
LOCK = BASE / "check.lock"
WORK = BASE / "empty-workdir"
LOG = HOME / "Library/Logs/claude-window.jsonl"
ERR = HOME / "Library/Logs/claude-window.launchd.err.log"
CLAUDE = HOME / ".local/bin/claude"
INTERVAL = 600
GRACE = 600
WINDOW = 5 * 3600
MAX_PER_DAY = 4
SCHEDULE_TOLERANCE = 20 * 60


def ensure_dirs():
    for p in (BASE, WORK, LOG.parent, PLIST.parent):
        p.mkdir(parents=True, exist_ok=True)
    BASE.chmod(0o700)
    WORK.chmod(0o700)


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, ValueError, OSError):
        return {}


def write_json(path, data):
    ensure_dirs()
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
            f.write("\n")
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def log(event, **data):
    ensure_dirs()
    if LOG.exists() and LOG.stat().st_size > 5_000_000:
        LOG.replace(LOG.with_suffix(".jsonl.1"))
    record = {"at": datetime.now(timezone.utc).isoformat(), "event": event, **data}
    fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")


def epoch(value):
    try:
        if isinstance(value, (int, float)):
            n = float(value)
        elif isinstance(value, str):
            try:
                n = float(value)
            except ValueError:
                n = datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
        else:
            return None
        if n > 100_000_000_000:
            n /= 1000
        return n if 1_600_000_000 < n < 4_000_000_000 else None
    except (ValueError, OverflowError):
        return None


def percent(value):
    try:
        n = float(value)
        return n if 0 <= n <= 100 else None
    except (TypeError, ValueError):
        return None


def local_time(value):
    return datetime.fromtimestamp(value).strftime("%m-%d %H:%M") if value else "未知"


def request_time(value):
    return datetime.fromtimestamp(value).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if value else "未知"


def history_events():
    if HISTORY.exists():
        with HISTORY.open() as f:
            for line in f:
                try:
                    item = json.loads(line)
                    if isinstance(item, dict):
                        yield item
                except ValueError:
                    continue


def record_request(event, **data):
    ensure_dirs()
    record = {"at": datetime.now(timezone.utc).isoformat(), "event": event, **data}
    fd = os.open(HISTORY, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
        f.flush()
        os.fsync(f.fileno())


def migrate_history():
    """只迁入旧日志能够证明的结果时间，不推算发起时间。调用方持有 LOCK。"""
    seen = {item.get("legacy_key") for item in history_events()}
    for path in (LOG.with_suffix(".jsonl.1"), LOG):
        if not path.exists():
            continue
        with path.open() as f:
            for line in f:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                if item.get("event") not in ("sent", "failed"):
                    continue
                key = f"{item.get('event')}:{item.get('at')}"
                if key in seen:
                    continue
                record_request("legacy_" + item["event"], legacy_key=key,
                               finished_at=epoch(item.get("at")))
                seen.add(key)


def show_history(limit=20):
    records = {}
    for item in history_events():
        key = item.get("request_id") or item.get("legacy_key")
        if key:
            records.setdefault(key, {}).update(item)
    if not records:
        print("还没有真实请求历史")
        return
    for item in list(records.values())[-limit:]:
        started = item.get("started_at")
        event = item.get("event")
        label = {"request_started": "已发起，结果未记录", "sent": "成功", "failed": "失败",
                 "legacy_sent": "成功（旧记录，发起时间未知）",
                 "legacy_failed": "失败（旧记录，发起时间未知）"}.get(event, event)
        stamp = request_time(started or item.get("finished_at"))
        kind = "发起" if started else "完成"
        print(f"{kind} {stamp}；{label}")


def system_zone():
    target = os.path.realpath("/etc/localtime")
    return ZoneInfo(target.split("zoneinfo/", 1)[1])


def scheduled_due(q, state, now):
    if state.get("mode", "auto") in ("once", "daily"):
        plan = state.get("plan") or {}
        return plan.get("trigger_at") if plan.get("status") == "pending" else None
    if state.get("mode", "auto") == "auto":
        return due_time(q, state, now)
    return None


def advance_daily_plan(state, now, outcome):
    plan = state["plan"]
    zone = ZoneInfo(plan["timezone"])
    target = datetime.fromtimestamp(plan["target_reset_at"], zone)
    elapsed_targets = 0
    while target.timestamp() - WINDOW <= now + 60:
        target += timedelta(days=1)
        elapsed_targets += 1
    if isinstance(plan.get("remaining"), int):
        plan["remaining"] -= elapsed_targets
        if plan["remaining"] <= 0:
            plan.update(status="completed", last_outcome=outcome, last_outcome_at=now)
            return
    plan.update(status="pending", target_reset_at=target.timestamp(), trigger_at=target.timestamp() - WINDOW,
                last_outcome=outcome, last_outcome_at=now)


def quota(cache):
    limits = cache.get("rate_limits") or {}
    five = limits.get("five_hour") or {}
    week = limits.get("seven_day") or {}
    return {
        "observed": epoch(cache.get("observed_at")),
        "five_used": percent(five.get("used_percentage")),
        "five_reset": epoch(five.get("resets_at")),
        "week_used": percent(week.get("used_percentage")),
        "week_reset": epoch(week.get("resets_at")),
    }


def usage_cache():
    caches = (read_json(CACHE), read_json(LIVE_CACHE))
    return max(caches, key=lambda cache: epoch(cache.get("observed_at")) or 0)


def due_time(q, state, now):
    last = state.get("last_sent_at") or 0
    reset = q["five_reset"]
    if reset and not (now - 86400 <= reset <= now + WINDOW + 3600):
        reset = None
    if last and reset and reset > last:
        return reset + GRACE
    if last:
        return last + WINDOW + GRACE
    if reset and q["observed"] and now - q["observed"] < 86400:
        return reset + GRACE
    return None


def tun_ok():
    try:
        with PREFS.open("rb") as f:
            if not plistlib.load(f).get("flutter.is_tun_running"):
                return False, "bettbox_tun_off"
        route = subprocess.run(["/sbin/route", "-n", "get", "1.1.1.1"], capture_output=True, text=True, timeout=3)
        m = re.search(r"interface:\s*(utun\d+)", route.stdout)
        if route.returncode or not m:
            return False, "route_not_tun"
        iface = subprocess.run(["/sbin/ifconfig", m.group(1)], capture_output=True, text=True, timeout=3)
        if iface.returncode or not re.search(r"\binet 198\.18\.0\.1\b", iface.stdout):
            return False, "bettbox_tun_address_missing"
        return True, m.group(1)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False, "tun_check_failed"


def guard_ok():
    from src.brain import get_verdict
    from src.config import ConfigManager
    verdict, _, error = get_verdict(ConfigManager(), allow_fallback=False)
    return verdict == "allowed", error or verdict


def outlet_ok(interface=None):
    allowed, reason = guard_ok()
    if not allowed:
        return False, "claudeguard_denied:" + str(reason)
    # 使用 Claude API 的同一域名，确保验证对应域名的路由。
    expected = read_json(CONFIG).get("expected_ip")
    try:
        expected = str(ipaddress.IPv4Address(expected))
    except (ValueError, TypeError):
        return False, "expected_exit_not_configured"
    if interface is None:
        good, interface = tun_ok()
        if not good:
            return False, interface
    try:
        p = subprocess.run(
            ["/usr/bin/curl", "-4", "--http1.1", "--noproxy", "*", "--interface", interface,
             "-fsS", "--connect-timeout", "3", "--max-time", "8",
             "https://api.anthropic.com/cdn-cgi/trace"],
            capture_output=True, text=True, timeout=10,
        )
        if p.returncode:
            return False, "anthropic_route_check_failed"
        match = re.search(r"(?m)^ip=([0-9.]+)\s*$", p.stdout)
        if not match:
            return False, "anthropic_route_ip_missing"
        ip = match.group(1)
        ipaddress.IPv4Address(ip)
        return (ip == expected), ip
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False, "anthropic_route_check_failed"


def auth_ok():
    try:
        p = subprocess.run([str(CLAUDE), "auth", "status"], capture_output=True, text=True, timeout=8)
        a = json.loads(p.stdout) if p.returncode == 0 else {}
        return a.get("loggedIn") is True and a.get("authMethod") == "claude.ai" and a.get("apiProvider") == "firstParty"
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def oauth_access_token():
    """读取本机已有订阅凭据，不刷新或保存 token。"""
    custom = os.environ.get("CLAUDE_CONFIG_DIR")
    if custom and Path(custom).expanduser().resolve() != (HOME / ".claude").resolve():
        return None, "custom_credential_directory_unsupported"
    try:
        p = subprocess.run(["/usr/bin/security", "find-generic-password", "-s",
                            "Claude Code-credentials", "-w"],
                           capture_output=True, text=True, timeout=8)
        data = json.loads(p.stdout) if p.returncode == 0 else read_json(HOME / ".claude/.credentials.json")
        oauth = data.get("claudeAiOauth") or {}
        if not oauth and p.returncode != 0:
            return None, f"oauth_keychain_unavailable:{p.returncode}"
        token = oauth.get("accessToken")
        expires = epoch(oauth.get("expiresAt"))
        if expires and expires <= time.time() + 30:
            return None, "oauth_access_token_expired"
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9._~-]+", token):
            return None, "oauth_access_token_missing"
        return token, None
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return None, "oauth_credentials_unavailable"


def refresh_usage():
    """只查额度；官方流量绑定已验证的 TUN，失败绝不回退直连。"""
    good, interface = tun_ok()
    if not good:
        return False, interface
    good, detail = outlet_ok(interface)
    if not good:
        return False, f"wrong_or_unreachable_exit:{detail}"
    token, reason = oauth_access_token()
    if not token:
        return False, reason
    good, current_interface = tun_ok()
    if not good or current_interface != interface:
        return False, "tun_changed_before_usage_query"
    try:
        # curl 配置通过 stdin 传入，Authorization 不暴露在进程参数中。
        config = "header = " + json.dumps("Authorization: Bearer " + token) + "\n"
        p = subprocess.run(
            ["/usr/bin/curl", "-4", "--http1.1", "--noproxy", "*", "--interface", interface,
             "--config", "-", "-sS", "--connect-timeout", "3", "--max-time", "10",
             "--header", "anthropic-beta: oauth-2025-04-20", "--write-out", "\n%{http_code}",
             "https://api.anthropic.com/api/oauth/usage"],
            input=config, capture_output=True, text=True, timeout=12,
        )
        if p.returncode:
            return False, "usage_request_failed"
        body, _, status = p.stdout.rpartition("\n")
        if status != "200":
            return False, f"usage_http_{status if status.isdigit() else 'unknown'}"
        payload = json.loads(body)
        limits = {}
        for name in ("five_hour", "seven_day"):
            window = payload.get(name)
            if window is None:
                limits[name] = None
                continue
            used = percent(window.get("utilization"))
            reset = window.get("resets_at")
            if used is None or (reset is not None and epoch(reset) is None):
                return False, "invalid_usage_response"
            limits[name] = {"used_percentage": used, "resets_at": reset}
        if not any(limits.values()):
            return False, "invalid_usage_response"
        write_json(LIVE_CACHE, {"observed_at": time.time(), "source": "official_usage", "rate_limits": limits})
        return True, "通过 Bettbox TUN 与固定出口查询成功"
    except (OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
        return False, "usage_query_or_cache_failed"


def send_minimal(state):
    env = os.environ.copy()
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy") or key in (
            "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "CLAUDE_CODE_OAUTH_TOKEN"
        ):
            env.pop(key, None)
    command = [str(CLAUDE), "--safe-mode", "--no-chrome", "--no-session-persistence", "--tools", "",
               "-p", "--model", "haiku", "--output-format", "json", "Reply exactly OK."]
    start = time.monotonic()
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    proc = subprocess.Popen(command, cwd=WORK, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    started_at = time.time()
    request_id = f"{time.time_ns()}-{proc.pid}"
    try:
        record_request("request_started", request_id=request_id, started_at=started_at, pid=proc.pid)
        state["last_request_started_at"] = started_at
        write_json(STATE, state)
    except OSError:
        proc.kill()
        proc.communicate()
        raise
    while True:
        try:
            stdout, stderr = proc.communicate(timeout=1)
            break
        except subprocess.TimeoutExpired:
            good, reason = tun_ok()
            if not good or time.monotonic() - start > 120:
                proc.terminate()
                try:
                    proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                return False, {"request_id": request_id, "started_at": started_at,
                               "reason": "tun_lost" if not good else "timeout", "duration_s": round(time.monotonic()-start, 1)}
    detail = {"request_id": request_id, "started_at": started_at, "duration_s": round(time.monotonic()-start, 1),
              "peak_rss_mb": round(max(before, resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)/1048576, 1)}
    try:
        result = json.loads(stdout)
        detail["model"] = next(iter(result.get("modelUsage", {})), "haiku")
        detail["estimated_api_cost_usd"] = result.get("total_cost_usd")
        detail["is_error"] = result.get("is_error", False)
        usage = result.get("usage") or {}
        detail["input_tokens"] = usage.get("input_tokens")
        detail["output_tokens"] = usage.get("output_tokens")
    except ValueError:
        detail["result"] = "non_json"
    if proc.returncode or detail.get("is_error") or detail.get("result") == "non_json":
        detail["reason"] = (stderr or stdout)[-400:]
        return False, detail
    return True, detail


def check(force=False, dry_run=False):
    if not dry_run:
        ensure_dirs()
    with nullcontext() if dry_run else LOCK.open("a+") as lock:
        if not dry_run:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                print("已有一次检查在运行")
                return 0
        state, cache = read_json(STATE), usage_cache()
        q, now = quota(cache), time.time()
        mode = state.get("mode", "auto")
        scheduled = mode in ("once", "daily")
        plan = state.get("plan") or {}
        due = scheduled_due(q, state, now)
        sent = [x for x in state.get("sent_times", []) if now-x < 86400]
        state["sent_times"] = sent
        if dry_run:
            print("离线预演：不联网、不调用 Claude、不改文件或定时任务。")
            print(f"模式：{mode}；固定出口要求：{read_json(CONFIG).get('expected_ip', '未配置')}；近 24 小时成功请求 {len(sent)}/{MAX_PER_DAY}")
            print(f"缓存更新时间：{request_time(q['observed'])}；5 小时已用：{q['five_used']}%；7 天已用：{q['week_used']}%")
            print(f"预计动作：Haiku 最小请求；最早发送 {local_time(due)}")
            print("TUN、路由、实际出口、OAuth 和并发锁未验证；真实执行仍须通过全部保护检查。")
        reason = None
        if scheduled and plan.get("status") == "pending" and not isinstance(due, (int, float)):
            reason = "invalid_scheduled_plan"
        elif scheduled and plan.get("status") != "pending":
            reason = "scheduled_plan_finished"
        elif scheduled and now < due:
            reason = "scheduled_wait"
        elif scheduled and now > due + SCHEDULE_TOLERANCE:
            if mode == "daily": advance_daily_plan(state, now, "missed_late")
            else: plan["status"] = "missed_late"
            reason = "scheduled_time_missed"
        elif scheduled and state.get("last_sent_at") and state["last_sent_at"] < now and state["last_sent_at"] + WINDOW > now:
            if mode == "daily": advance_daily_plan(state, now, "missed_active_window")
            else: plan["status"] = "missed_active_window"
            reason = "known_window_still_active"
        elif scheduled and q["observed"] and q["observed"] >= due - 1800 and q["five_reset"] and q["five_reset"] > now + 60:
            reason = "satisfied_by_other_usage" if abs(q["five_reset"] - plan["target_reset_at"]) <= SCHEDULE_TOLERANCE else "missed_active_window"
            if mode == "daily": advance_daily_plan(state, now, reason)
            else: plan["status"] = reason
        elif mode == "paused" and not force:
            reason = "paused"
        elif not force and due is None:
            reason = "waiting_for_fresh_statusline_cache"
        elif not force and now < due:
            reason = "not_due"
        elif len(sent) >= MAX_PER_DAY:
            reason = "daily_cap_4"
        elif (state.get("retry_after") or 0) > now:
            reason = "error_backoff"
        elif q["week_used"] is not None and q["week_used"] >= 95 and (q["week_reset"] or now+1) > now:
            reason = "weekly_usage_above_95_percent"
        if reason:
            if mode == "daily": due = scheduled_due(q, state, now)
            if dry_run:
                print(f"预演结果：跳过 {reason}；下次最早 {local_time(due)}")
                if scheduled:
                    print(f"计划预演状态：{plan.get('status', '未知')}（未保存）")
                return 0
            log("skip", reason=reason, next_due=due)
            state["last_check_at"], state["last_event"] = now, reason
            write_json(STATE, state)
            return 0
        if dry_run:
            print("预演结果：调度条件允许尝试；网络及登录条件未验证，本次不发送。")
            return 0
        tun, tun_detail = tun_ok()
        if not tun:
            reason = tun_detail
        else:
            outlet, outlet_detail = outlet_ok()
            if not outlet:
                reason = f"wrong_or_unreachable_exit:{outlet_detail}"
            elif not auth_ok():
                reason = "subscription_oauth_not_active"
        if reason:
            log("skip", reason=reason, next_due=due)
            state["last_check_at"], state["last_event"] = now, reason
            write_json(STATE, state)
            return 0
        ok, detail = send_minimal(state)
        state["last_check_at"] = time.time()
        state["last_result"] = detail
        if ok:
            state["last_sent_at"] = time.time()
            state["sent_times"].append(state["last_sent_at"])
            state["last_event"] = "sent"
            planned_reset = plan.get("target_reset_at") if scheduled else None
            if mode == "once":
                plan["status"] = "completed"
                plan["sent_at"] = state["last_sent_at"]
            elif mode == "daily":
                advance_daily_plan(state, state["last_sent_at"], "sent")
            state.pop("retry_after", None)
            log("sent", planned_reset=planned_reset, **detail)
            print("已发送 Haiku 最小请求")
        else:
            state["last_event"] = "failed"
            state["retry_after"] = time.time() + 3600
            log("failed", **detail)
            print(f"请求失败：{detail.get('reason', 'unknown')}")
        write_json(STATE, state)
        record_request("sent" if ok else "failed", finished_at=state["last_check_at"],
                       request_id=detail["request_id"], started_at=detail["started_at"])
        return 0 if ok else 1


def show_usage(refresh=False):
    fresh = False
    if refresh:
        fresh, reason = refresh_usage()
        if not fresh:
            if reason in ("bettbox_tun_off", "route_not_tun", "bettbox_tun_address_missing", "tun_check_failed"):
                print("代理未就绪，跳过官方额度查询；仅显示本地缓存。")
            else:
                print(f"实时额度刷新失败：{reason}；显示已有缓存，未尝试直连。")
    cache, state = usage_cache(), read_json(STATE)
    q, now = quota(cache), time.time()
    age = f"{(now-q['observed'])/60:.0f} 分钟前" if q["observed"] else "无缓存"
    if fresh:
        print(f"实时额度：{request_time(q['observed'])}（官方接口，经 Bettbox TUN 与固定出口）")
    else:
        source = "官方查询缓存" if cache.get("source") == "official_usage" else "Claude Code 状态栏缓存"
        print(f"额度缓存：{age}；更新时间 {request_time(q['observed'])}（{source}）")
    for label, used, reset in (("5 小时", q["five_used"], q["five_reset"]), ("7 天", q["week_used"], q["week_reset"])):
        value = f"已用 {used:.1f}% / 剩余 {100-used:.1f}%" if used is not None else "未知"
        print(f"{label}：{value}；重置 {local_time(reset)}")
    print(f"下次计划发出：{local_time(scheduled_due(q, state, now))}")
    started = state.get("last_request_started_at")
    for item in history_events():
        started = max(started or 0, item.get("started_at") or 0)
    print(f"上次真实发起：{request_time(started)}（工具启动 Claude 请求；不含跳过/模拟检查）")
    print(f"上次成功完成：{request_time(state.get('last_sent_at'))}；近 24 小时 {len([x for x in state.get('sent_times', []) if now-x < 86400])}/{MAX_PER_DAY} 次")


def loaded():
    p = subprocess.run(["/bin/launchctl", "print", f"gui/{os.getuid()}/{LABEL}"], capture_output=True, text=True)
    return p.returncode == 0, p.stdout


def show_status(cached=False):
    active, output = loaded()
    print(f"定时任务：{'已启动' if active else '已停止'}；每 {INTERVAL//60} 分钟检查一次；未运行时常驻内存 0")
    m = re.search(r"\bpid = (\d+)", output) if active else None
    if m:
        p = subprocess.run(["/bin/ps", "-p", m.group(1), "-o", "pid=,%cpu=,rss=,etime="], capture_output=True, text=True)
        print("当前进程 PID/%CPU/RSS KiB/运行时长：", p.stdout.strip() or "无")
    state = read_json(STATE)
    mode = state.get("mode", "auto")
    if mode in ("once", "daily"):
        plan = state.get("plan") or {}
        label = (f"重复计划（剩余 {plan['remaining']} 次）" if isinstance(plan.get("remaining"), int)
                 else "每天重复" if mode == "daily" else "一次性")
        print(f"模式：{label}；计划状态：{plan.get('status', '未知')}；预计重置 {local_time(plan.get('target_reset_at'))}；计划发送 {local_time(plan.get('trigger_at'))}")
    else:
        print(f"模式：{'周期自动' if mode == 'auto' else '暂停'}")
    print(f"最近检查：{local_time(state.get('last_check_at'))}；结果：{state.get('last_event', '无')}")
    result = state.get("last_result") or {}
    if result:
        print(f"上次请求耗时：{result.get('duration_s', '未知')} 秒；峰值子进程 RSS：{result.get('peak_rss_mb', '未知')} MB")
    show_usage(refresh=not cached)
    print(f"执行日志：{LOG}")


def start():
    ensure_dirs()
    if not PLIST.exists():
        print(f"缺少 LaunchAgent：{PLIST}", file=sys.stderr)
        return 1
    if loaded()[0]:
        print("定时任务已经启动")
        return 0
    subprocess.run(["/bin/launchctl", "enable", f"gui/{os.getuid()}/{LABEL}"], check=True)
    subprocess.run(["/bin/launchctl", "bootstrap", f"gui/{os.getuid()}", str(PLIST)], check=True)
    print("定时任务已启动；只有 TUN 和配置的固定出口同时通过检查才会发请求")
    return 0


def stop():
    if loaded()[0]:
        subprocess.run(["/bin/launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"], check=True)
    subprocess.run(["/bin/launchctl", "disable", f"gui/{os.getuid()}/{LABEL}"], check=True)
    print("定时任务已停止，后续登录也保持禁用，直到再次运行 start")
    return 0


def schedule_once(day, clock, dry_run=False):
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", clock):
        raise ValueError("时间请写 HH:MM，例如 10:30")
    tz = system_zone()
    today = datetime.now(tz).date()
    if day == "tomorrow":
        target_day = today + timedelta(days=1)
    elif day == "today":
        target_day = today
    else:
        target_day = datetime.strptime(day, "%Y-%m-%d").date()
    hour, minute = map(int, clock.split(":"))
    target = datetime.combine(target_day, clock_time(hour, minute), tzinfo=tz)
    return save_schedule(target, "once", dry_run=dry_run)


def schedule_clock(clock, daily=False, times=None, dry_run=False):
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", clock):
        raise ValueError("时间请写 HH:MM，例如 10:30")
    tz = system_zone()
    now = datetime.now(tz)
    if times is not None and not 1 <= times <= 365:
        raise ValueError("重复次数须在 1 到 365 之间")
    mode = "daily" if daily or (times is not None and times > 1) else "once"
    hour, minute = map(int, clock.split(":"))
    for days in range(3):
        target = datetime.combine(now.date() + timedelta(days=days), clock_time(hour, minute), tzinfo=tz)
        if target.timestamp() - WINDOW > now.timestamp() + 60:
            return save_schedule(target, mode, remaining=times if times and times > 1 else None, dry_run=dry_run)
    raise ValueError("找不到未来可执行的发送时间")


def save_schedule(target, mode, remaining=None, dry_run=False):
    trigger = target.timestamp() - WINDOW
    if trigger <= time.time() + 60:
        raise ValueError("反推后的发送时间已过去或不足 1 分钟；请选更晚的重置时间")
    if not dry_run:
        ensure_dirs()
        with LOCK.open("a+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = read_json(STATE)
            state["mode"] = mode
            state["plan"] = {"status": "pending", "target_reset_at": target.timestamp(), "trigger_at": trigger, "timezone": str(target.tzinfo)}
            if remaining is not None:
                state["plan"]["remaining"] = remaining
            state.pop("retry_after", None)
            write_json(STATE, state)
        log("scheduled_" + mode, target_reset=target.timestamp(), trigger=trigger, remaining=remaining)
    else:
        print("离线计划预演：未保存计划、未启动任务、不联网、不调用 Claude。")
    label = f"重复 {remaining} 次" if remaining is not None else "每天重复" if mode == "daily" else "一次性"
    print(f"{label}计划：{local_time(trigger)} 左右发送；预计 {local_time(target.timestamp())} 重置（{target.tzinfo}）")
    print(f"错过发送时间超过 {SCHEDULE_TOLERANCE//60} 分钟或当时已有活跃窗口，就不补发")
    return 0 if dry_run else start()


def cancel_schedule():
    ensure_dirs()
    with LOCK.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_json(STATE)
        if state.get("mode") in ("once", "daily") and (state.get("plan") or {}).get("status") == "pending":
            state["plan"]["status"] = "cancelled"
        state["mode"] = "paused"
        write_json(STATE, state)
    log("schedule_cancelled")
    return stop()


def resume_auto():
    ensure_dirs()
    with LOCK.open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_json(STATE)
        state["mode"] = "auto"
        state.pop("plan", None)
        write_json(STATE, state)
    log("auto_resumed")
    return start()


def kill_claude(dry_run=False):
    """Reuse ClaudeGuard's native session closer; no separate process matching."""
    binary = HOME / ".local/share/ClaudeGuard/bin/ClaudeGuardMenuBar"
    command = [str(binary), "--kill-sessions"]
    if dry_run:
        command.append("--dry-run")
    return subprocess.run(command, check=False).returncode


def main():
    if len(sys.argv) > 1 and re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", sys.argv[1]):
        quick = argparse.ArgumentParser(prog="claude-w", description="直接按目标重置时间安排；自动反推 5 小时")
        quick.add_argument("time", help="目标重置时间 HH:MM（下一次可执行的日期）")
        repetition = quick.add_mutually_exclusive_group()
        repetition.add_argument("-d", "--daily", action="store_true", help="每天重复，直到 cancel")
        repetition.add_argument("-n", "--times", type=int, help="连续安排 N 个目标日期")
        quick.add_argument("--dry-run", action="store_true", help="离线预览计划，不保存或启动任务")
        args = quick.parse_args()
        return schedule_clock(args.time, daily=args.daily, times=args.times, dry_run=args.dry_run)
    parser = argparse.ArgumentParser(
        prog="claude-w",
        description="Claude 5 小时窗口监控；代理未就绪时不发请求",
        epilog="快捷设置：claude-w 10:00（一次）；claude-w 10:00 -n 3（三次）；claude-w 10:00 -d（每天）",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("logs")
    for name in ("start", "stop", "poke", "cancel", "auto"):
        action = sub.add_parser(name)
        action.add_argument("--dry-run", action="store_true", help="仅预览，不执行")
    for name in ("status", "usage"):
        query = sub.add_parser(name, help="查询实时额度；代理不可用时显示缓存")
        query.add_argument("--cached", action="store_true", help="仅显示本地缓存，不发网络请求")
    history = sub.add_parser("history", help="显示真实请求历史，区分发起与完成时间")
    history.add_argument("--limit", type=int, default=20, help="显示最近 N 次请求，默认 20")
    kill = sub.add_parser("kill", aliases=["ckill"], help="强制终止 Claude 相关进程，可能丢失未保存内容")
    kill.add_argument("--dry-run", action="store_true", help="仅列出进程，不终止")
    config = sub.add_parser("config", help="配置固定出口 IPv4；未配置时不会发送请求")
    config.add_argument("--expected-ip", type=ipaddress.IPv4Address, required=True)
    config.add_argument("--dry-run", action="store_true", help="仅预览固定出口配置，不保存")
    schedule = sub.add_parser("schedule", help="按目标重置时间创建一次性计划并启动任务")
    schedule.add_argument("day", help="tomorrow、today 或 YYYY-MM-DD")
    schedule.add_argument("time", help="目标重置时间 HH:MM（本机时区）")
    schedule.add_argument("--dry-run", action="store_true", help="离线预览计划，不保存或启动任务")
    for name in ("check", "dry-run"):
        test = sub.add_parser(name, help="离线预演检查" if name == "dry-run" else "执行窗口检查")
        test.add_argument("--dry-run", action="store_true", default=name == "dry-run", help="离线预演，不联网或写入")
        test.add_argument("--force", action="store_true", help="预演/执行立即尝试，仍受额度等保护")
    args = parser.parse_args()
    if args.command in ("kill", "ckill"): return kill_claude(dry_run=args.dry_run)
    if args.command == "history":
        if args.limit < 1: parser.error("--limit 必须大于 0")
        show_history(args.limit)
        return 0
    if args.command == "config":
        if args.dry_run:
            print(f"预演：将固定出口设为 {args.expected_ip}；目标 {CONFIG}；未保存。")
            return 0
        write_json(CONFIG, {"expected_ip": str(args.expected_ip)})
        print("固定出口已配置；下次检查生效")
        return 0
    if args.command in ("start", "stop", "cancel", "auto") and args.dry_run:
        actions = {"start": "启用并启动定时任务", "stop": "停止并禁用定时任务",
                   "cancel": "取消计划、切换暂停并停止任务", "auto": "清除计划、恢复周期自动模式并启动任务"}
        print(f"预演：{actions[args.command]}；目标 {STATE} / {PLIST}；未修改或执行。")
        return 0
    if args.command == "start": return start()
    if args.command == "stop": return stop()
    if args.command == "schedule": return schedule_once(args.day, args.time, dry_run=args.dry_run)
    if args.command == "cancel": return cancel_schedule()
    if args.command == "auto": return resume_auto()
    if args.command == "status": show_status(cached=args.cached); return 0
    if args.command == "usage": show_usage(refresh=not args.cached); return 0
    if args.command == "logs":
        if not LOG.exists(): print("还没有日志"); return 0
        for line in deque(LOG.open(), maxlen=20): print(line.rstrip())
        return 0
    if args.command == "poke": return check(force=True, dry_run=args.dry_run)
    return check(force=args.force, dry_run=args.dry_run)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"任务错误：{exc}", file=sys.stderr)
        sys.exit(1)
