"""隔离验证请求时间、旧历史、出口保护、安装和进程终止；无真实外部副作用。"""

from contextlib import redirect_stdout
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import sys
if sys.platform == "darwin":
    from src import window_manager as app
    from src import window_install as installer


@unittest.skipUnless(sys.platform == "darwin", "macOS window manager")
class ToolTests(unittest.TestCase):
    def test_guard_denial_prevents_official_exit_and_usage_queries(self):
        with patch.object(app, "guard_ok", return_value=(False, "blocked")), patch.object(app, "tun_ok", return_value=(True, "utun0")), patch.object(app.subprocess, "run") as run, patch.object(app, "oauth_access_token") as token:
            self.assertEqual(app.outlet_ok(), (False, "claudeguard_denied:blocked"))
            self.assertFalse(app.refresh_usage()[0])
            run.assert_not_called()
            token.assert_not_called()

    def test_new_window_install_is_disabled_and_does_not_start(self):
        import plistlib
        with patch.object(app.subprocess, "run") as run, redirect_stdout(io.StringIO()):
            installer.install()
        self.assertTrue(plistlib.loads(app.PLIST.read_bytes())["Disabled"])
        run.assert_not_called()

    def test_window_uninstall_restores_legacy_commands_and_preserves_data(self):
        bindir = app.HOME / ".local/bin"
        bindir.mkdir(parents=True)
        old = app.HOME / "old-window.py"
        old.write_text("legacy")
        (bindir / "claude-w").symlink_to(old)
        app.write_json(app.STATE, {"mode": "paused"})
        with patch.object(app.subprocess, "run"), redirect_stdout(io.StringIO()):
            installer.install()
            installer.uninstall()
        self.assertEqual((bindir / "claude-w").resolve(), old.resolve())
        self.assertEqual(app.read_json(app.STATE), {"mode": "paused"})
        self.assertFalse(app.PLIST.exists())

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        home = Path(self.temp.name)
        base = home / ".local/state/claude-window"
        paths = {"HOME": home, "BASE": base, "WORK": base / "empty-workdir",
                 "STATE": base / "state.json", "CONFIG": base / "config.json",
                 "HISTORY": base / "requests.jsonl", "LOCK": base / "check.lock",
                 "LIVE_CACHE": base / "usage-cache.json",
                 "LOG": home / "Library/Logs/claude-window.jsonl",
                 "PLIST": home / "Library/LaunchAgents/com.weicoz.claude-window.plist",
                 "ERR": home / "Library/Logs/claude-window.err.log",
                 "CACHE": home / ".claude/rl-cache.json", "CLAUDE": home / "bin/claude"}
        self.patcher = patch.multiple(app, **paths)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        app.ensure_dirs()
        gate = patch.object(app, "guard_ok", return_value=(True, "allowed"))
        gate.start()
        self.addCleanup(gate.stop)

    def invoke_check(self, success=True):
        proc = Mock(pid=12345, returncode=0 if success else 1)

        def reply(**kwargs):
            events = list(app.history_events())
            self.assertEqual(events[0]["event"], "request_started")
            self.assertGreater(app.read_json(app.STATE)["last_request_started_at"], 0)
            return json.dumps({"is_error": not success, "usage": {}}), ""

        proc.communicate.side_effect = reply
        with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
             patch.object(app, "outlet_ok", return_value=(True, "test-exit")), \
             patch.object(app, "auth_ok", return_value=True), \
             patch.object(app.subprocess, "Popen", return_value=proc), \
             redirect_stdout(io.StringIO()):
            code = app.check(force=True)
        return code, list(app.history_events()), app.read_json(app.STATE)

    def test_real_start_recorded_before_response_and_status(self):
        code, events, state = self.invoke_check()
        self.assertEqual(code, 0)
        self.assertEqual([e["event"] for e in events], ["request_started", "sent"])
        self.assertEqual(events[0]["started_at"], state["last_request_started_at"])
        self.assertEqual(events[0]["request_id"], events[1]["request_id"])
        self.assertLessEqual(events[0]["started_at"], state["last_sent_at"])
        self.assertEqual(app.HISTORY.stat().st_mode & 0o777, 0o600)
        output = io.StringIO()
        with patch.object(app, "loaded", return_value=(False, "")), redirect_stdout(output):
            app.show_status(cached=True)
        self.assertIn("上次真实发起：" + app.request_time(state["last_request_started_at"]), output.getvalue())

    def test_failed_request_has_start_but_no_success_timestamp(self):
        code, events, state = self.invoke_check(success=False)
        self.assertEqual(code, 1)
        self.assertEqual(events[-1]["event"], "failed")
        self.assertGreater(state["last_request_started_at"], 0)
        self.assertNotIn("last_sent_at", state)

    def test_skipped_and_dry_run_do_not_create_request_history(self):
        with patch.object(app.subprocess, "Popen") as popen, redirect_stdout(io.StringIO()):
            app.check()
            with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
                 patch.object(app, "outlet_ok", return_value=(True, "test-exit")), \
                 patch.object(app, "auth_ok", return_value=True):
                app.check(force=True, dry_run=True)
        popen.assert_not_called()
        self.assertFalse(app.HISTORY.exists())
        self.assertNotIn("last_request_started_at", app.read_json(app.STATE))

    def test_launch_failure_does_not_forge_start(self):
        with patch.object(app.subprocess, "Popen", side_effect=OSError("模拟无法启动")):
            with self.assertRaises(OSError):
                app.send_minimal({})
        self.assertFalse(app.HISTORY.exists())

    def test_result_history_failure_keeps_success_state(self):
        record = app.record_request

        def fail_result(event, **data):
            if event == "sent":
                raise OSError("模拟历史文件无法写入")
            return record(event, **data)

        with patch.object(app, "record_request", side_effect=fail_result):
            with self.assertRaises(OSError):
                self.invoke_check()
        self.assertGreater(app.read_json(app.STATE)["last_sent_at"], 0)

    def test_legacy_history_migration_is_idempotent_and_honest(self):
        app.LOG.write_text(json.dumps({"event": "sent", "at": "2026-10-01T00:00:00+00:00",
                                       "duration_s": 8, "private_text": "不迁入"}) + "\n")
        app.migrate_history()
        app.migrate_history()
        events = list(app.history_events())
        self.assertEqual(len(events), 1)
        self.assertNotIn("started_at", events[0])
        self.assertNotIn("private_text", events[0])
        output = io.StringIO()
        with redirect_stdout(output):
            app.show_history()
            app.show_usage()
        self.assertIn("发起时间未知", output.getvalue())
        self.assertIn("上次真实发起：未知", output.getvalue())

    def test_pending_start_survives_without_result(self):
        app.record_request("request_started", request_id="pending", started_at=1790812800)
        output = io.StringIO()
        with redirect_stdout(output):
            app.show_history()
        self.assertIn("已发起，结果未记录", output.getvalue())

    def test_missing_or_wrong_exit_never_launches_claude(self):
        with patch.object(app.subprocess, "run") as run:
            self.assertEqual(app.outlet_ok(), (False, "expected_exit_not_configured"))
            run.assert_not_called()
        app.write_json(app.CONFIG, {"expected_ip": "203.0.113.1"})
        with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
             patch.object(app.subprocess, "run", return_value=Mock(returncode=0, stdout="ip=203.0.113.2\n")):
            self.assertFalse(app.outlet_ok()[0])
        with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
             patch.object(app, "outlet_ok", return_value=(False, "wrong-exit")), \
             patch.object(app.subprocess, "Popen") as popen:
            app.check(force=True)
        popen.assert_not_called()
        self.assertFalse(app.HISTORY.exists())

    def test_kill_delegates_to_native_guard(self):
        with patch.object(app.subprocess, "run", return_value=Mock(returncode=0)) as run:
            self.assertEqual(app.kill_claude(dry_run=True), 0)
            self.assertEqual(run.call_args.args[0], [str(app.HOME / ".local/share/ClaudeGuard/bin/ClaudeGuardMenuBar"), "--kill-sessions", "--dry-run"])
            self.assertEqual(app.kill_claude(), 0)
            self.assertEqual(run.call_args.args[0][-1], "--kill-sessions")

    def test_install_preserves_state_plist_and_old_exit(self):
        bindir = app.HOME / ".local/bin"
        bindir.mkdir(parents=True)
        (bindir / "claude-window").write_text('EXPECTED_IP = "203.0.113.1"\n')
        app.PLIST.write_bytes("已有任务配置".encode())
        app.write_json(app.STATE, {"mode": "daily", "plan": {"status": "pending"}})
        state_before = app.STATE.read_bytes()
        with redirect_stdout(io.StringIO()):
            installer.install()
        self.assertEqual(app.STATE.read_bytes(), state_before)
        self.assertEqual(app.PLIST.read_bytes(), "已有任务配置".encode())
        self.assertEqual(app.read_json(app.CONFIG)["expected_ip"], "203.0.113.1")
        self.assertTrue((bindir / "claude-w").is_symlink())
        self.assertEqual((bindir / "claude-window").resolve(), (bindir / "claude-w").resolve())
        self.assertIn('kill "$@"', (bindir / "ckill").read_text())

    def test_shortcut_and_kill_alias_route_without_external_calls(self):
        with patch.object(app.sys, "argv", ["claude-w", "10:00", "-n", "3"]), \
             patch.object(app, "schedule_clock", return_value=0) as schedule:
            self.assertEqual(app.main(), 0)
        schedule.assert_called_once_with("10:00", daily=False, times=3, dry_run=False)
        for command in ("kill", "ckill"):
            with patch.object(app.sys, "argv", ["claude-w", command, "--dry-run"]), \
                 patch.object(app, "kill_claude", return_value=0) as kill:
                self.assertEqual(app.main(), 0)
            kill.assert_called_once_with(dry_run=True)

    def test_live_usage_blocked_without_proxy_or_correct_exit(self):
        with patch.object(app, "tun_ok", return_value=(False, "bettbox_tun_off")), \
             patch.object(app, "outlet_ok") as outlet, \
             patch.object(app, "oauth_access_token") as token, \
             patch.object(app.subprocess, "run") as run:
            self.assertEqual(app.refresh_usage(), (False, "bettbox_tun_off"))
        outlet.assert_not_called()
        token.assert_not_called()
        run.assert_not_called()
        output = io.StringIO()
        with patch.object(app, "tun_ok", return_value=(False, "bettbox_tun_off")), \
             patch.object(app.subprocess, "run") as run, redirect_stdout(output):
            app.show_usage(refresh=True)
        self.assertIn("代理未就绪，跳过官方额度查询", output.getvalue())
        run.assert_not_called()
        with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
             patch.object(app, "outlet_ok", return_value=(False, "wrong-exit")), \
             patch.object(app, "oauth_access_token") as token, \
             patch.object(app.subprocess, "run") as run:
            self.assertFalse(app.refresh_usage()[0])
        token.assert_not_called()
        run.assert_not_called()

    def test_live_usage_pins_proxy_and_never_exposes_token_in_args(self):
        payload = {"five_hour": {"utilization": 12, "resets_at": "2026-10-08T12:00:00Z"},
                   "seven_day": {"utilization": 46, "resets_at": None},
                   "private_data": "不保存"}
        with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
             patch.object(app, "outlet_ok", return_value=(True, "test-exit")), \
             patch.object(app, "auth_ok", return_value=True), \
             patch.object(app, "oauth_access_token", return_value=("fake_test_token", None)), \
             patch.object(app.subprocess, "run", return_value=Mock(returncode=0, stdout=json.dumps(payload) + "\n200")) as run:
            self.assertTrue(app.refresh_usage()[0])
        args = run.call_args.args[0]
        self.assertEqual(args[args.index("--interface") + 1], "utun0")
        self.assertEqual(args[args.index("--config") + 1], "-")
        self.assertNotIn("fake_test_token", " ".join(args))
        self.assertIn("fake_test_token", run.call_args.kwargs["input"])
        cache = app.read_json(app.LIVE_CACHE)
        self.assertEqual(app.quota(cache)["five_used"], 12)
        self.assertNotIn("fake_test_token", app.LIVE_CACHE.read_text())
        self.assertNotIn("private_data", cache)
        self.assertEqual(app.LIVE_CACHE.stat().st_mode & 0o777, 0o600)
        self.assertFalse(app.HISTORY.exists())
        self.assertFalse(app.STATE.exists())

    def test_proxy_change_before_usage_does_not_send(self):
        with patch.object(app, "tun_ok", side_effect=[(True, "utun0"), (False, "bettbox_tun_off")]), \
             patch.object(app, "outlet_ok", return_value=(True, "test-exit")), \
             patch.object(app, "auth_ok", return_value=True), \
             patch.object(app, "oauth_access_token", return_value=("fake_test_token", None)), \
             patch.object(app.subprocess, "run") as run:
            self.assertEqual(app.refresh_usage(), (False, "tun_changed_before_usage_query"))
        run.assert_not_called()

    def test_live_query_failure_preserves_cache_and_reports_staleness(self):
        app.write_json(app.LIVE_CACHE, {"observed_at": 1790812800, "source": "official_usage",
                                      "rate_limits": {"five_hour": {"used_percentage": 12}}})
        before = app.LIVE_CACHE.read_bytes()
        for response in ('{}\n429', '{}\n401', '{"five_hour":{"utilization":999}}\n200', '[]\n200'):
            with patch.object(app, "tun_ok", return_value=(True, "utun0")), \
                 patch.object(app, "outlet_ok", return_value=(True, "test-exit")), \
                 patch.object(app, "auth_ok", return_value=True), \
                 patch.object(app, "oauth_access_token", return_value=("fake_test_token", None)), \
                 patch.object(app.subprocess, "run", return_value=Mock(returncode=0, stdout=response)):
                self.assertFalse(app.refresh_usage()[0])
            self.assertEqual(app.LIVE_CACHE.read_bytes(), before)
        output = io.StringIO()
        with patch.object(app, "refresh_usage", return_value=(False, "usage_http_429")), redirect_stdout(output):
            app.show_usage(refresh=True)
        self.assertIn("实时额度刷新失败", output.getvalue())
        self.assertIn("额度缓存", output.getvalue())
        self.assertIn("更新时间", output.getvalue())
        self.assertNotIn("实时额度：", output.getvalue())

    def test_offline_command_selects_newest_cache_without_network(self):
        app.CACHE.parent.mkdir(parents=True)
        app.write_json(app.CACHE, {"observed_at": 1790812800, "rate_limits": {}})
        app.write_json(app.LIVE_CACHE, {"observed_at": 1790812801, "rate_limits": {}})
        self.assertEqual(app.usage_cache()["observed_at"], 1790812801)
        app.write_json(app.CACHE, {"observed_at": 1790812802, "rate_limits": {}})
        self.assertEqual(app.usage_cache()["observed_at"], 1790812802)
        with patch.object(app.sys, "argv", ["claude-w", "status", "--cached"]), \
             patch.object(app, "show_status") as status:
            app.main()
        status.assert_called_once_with(cached=True)

    def test_expired_oauth_credentials_fail_without_echoing_token(self):
        data = {"claudeAiOauth": {"accessToken": "fake_secret", "expiresAt": 1790812800000}}
        with patch.object(app.subprocess, "run", return_value=Mock(returncode=0, stdout=json.dumps(data))), \
             patch.object(app.time, "time", return_value=1790813000):
            self.assertEqual(app.oauth_access_token(), (None, "oauth_access_token_expired"))

    def test_dry_run_is_offline_and_preserves_even_missed_daily_plan(self):
        now = 1791500000
        states = [
            {},
            {"mode": "paused"},
            {"mode": "auto", "retry_after": now + 1000},
            {"mode": "auto", "sent_times": [now - 1] * 4},
            {"mode": "once", "plan": {"status": "pending", "trigger_at": now + 3600,
                                         "target_reset_at": now + 3600 + app.WINDOW}},
            {"mode": "daily", "plan": {"status": "pending", "trigger_at": now - 3600,
                                          "target_reset_at": now - 3600 + app.WINDOW,
                                          "timezone": "Asia/Singapore", "remaining": 3}},
        ]
        app.write_json(app.CONFIG, {"expected_ip": "203.0.113.1"})
        app.write_json(app.LIVE_CACHE, {"observed_at": now, "rate_limits": {"seven_day": {"used_percentage": 20}}})
        for state in states:
            with self.subTest(state=state):
                app.write_json(app.STATE, state)
                before = {p.relative_to(app.HOME): (p.read_bytes(), p.stat().st_mode) for p in app.HOME.rglob('*') if p.is_file()}
                output = io.StringIO()
                with patch.object(app.subprocess, "run", side_effect=AssertionError("dry-run spawned process")), \
                     patch.object(app.subprocess, "Popen", side_effect=AssertionError("dry-run invoked Claude")), \
                     patch.object(app, "ensure_dirs", side_effect=AssertionError("dry-run writes directories")), \
                     patch.object(app, "write_json", side_effect=AssertionError("dry-run writes state")), \
                     patch.object(app, "log", side_effect=AssertionError("dry-run writes logs")), \
                     patch.object(app.time, "time", return_value=now), redirect_stdout(output):
                    self.assertEqual(app.check(force=True, dry_run=True), 0)
                after = {p.relative_to(app.HOME): (p.read_bytes(), p.stat().st_mode) for p in app.HOME.rglob('*') if p.is_file()}
                self.assertEqual(before, after)
                self.assertIn("未验证", output.getvalue())
                self.assertNotIn("可发送：", output.getvalue())

    def test_preview_commands_do_not_write_run_network_or_change_launchagent(self):
        commands = [
            ["dry-run"], ["dry-run", "--force"], ["check", "--dry-run"],
            ["poke", "--dry-run"], ["10:00", "--dry-run"],
            ["10:00", "-n", "3", "--dry-run"], ["10:00", "-d", "--dry-run"],
            ["schedule", "2099-01-01", "10:00", "--dry-run"],
            ["start", "--dry-run"], ["stop", "--dry-run"],
            ["auto", "--dry-run"], ["cancel", "--dry-run"],
            ["config", "--expected-ip", "203.0.113.1", "--dry-run"],
        ]
        with patch.object(app, "ensure_dirs", side_effect=AssertionError("preview writes directories")), \
             patch.object(app, "write_json", side_effect=AssertionError("preview writes state")), \
             patch.object(app, "log", side_effect=AssertionError("preview writes logs")), \
             patch.object(app.subprocess, "run", side_effect=AssertionError("preview invokes subprocess")), \
             patch.object(app.subprocess, "Popen", side_effect=AssertionError("preview invokes Claude")):
            for args in commands:
                with self.subTest(args=args), patch.object(app.sys, "argv", ["claude-w", *args]), redirect_stdout(io.StringIO()):
                    self.assertEqual(app.main(), 0)
        self.assertFalse(app.STATE.exists())
        self.assertFalse(app.LOG.exists())
        self.assertFalse(app.LOCK.exists())

    def test_schedule_preview_preserves_plan_and_matches_real_schedule(self):
        app.write_json(app.STATE, {"mode": "auto", "retry_after": 1791500000})
        before = app.STATE.read_bytes()
        target = datetime.now(app.system_zone()) + timedelta(days=1)
        preview, actual = io.StringIO(), io.StringIO()
        with patch.object(app, "start", side_effect=AssertionError("preview starts task")), redirect_stdout(preview):
            self.assertEqual(app.save_schedule(target, "daily", remaining=3, dry_run=True), 0)
        self.assertEqual(app.STATE.read_bytes(), before)
        with patch.object(app, "start", return_value=0) as start, redirect_stdout(actual):
            app.save_schedule(target, "daily", remaining=3)
        start.assert_called_once()
        self.assertTrue(preview.getvalue().endswith(actual.getvalue()))
        self.assertEqual(app.read_json(app.STATE)["plan"]["trigger_at"], target.timestamp() - app.WINDOW)

    def test_dry_run_on_fresh_install_creates_no_directories(self):
        missing = app.HOME / "nonexistent"
        with patch.multiple(app, STATE=missing / "state.json", CONFIG=missing / "config.json",
                            CACHE=missing / "rl-cache.json", LIVE_CACHE=missing / "usage-cache.json",
                            BASE=missing, LOCK=missing / "check.lock"), \
             patch.object(app.subprocess, "run", side_effect=AssertionError("network not allowed")), \
             patch.object(app.subprocess, "Popen", side_effect=AssertionError("Claude not allowed")), \
             redirect_stdout(io.StringIO()):
            app.check(dry_run=True)
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
