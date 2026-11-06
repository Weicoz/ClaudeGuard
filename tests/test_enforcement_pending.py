"""A transient daemon recheck must block new starts without killing a live CLI."""
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import Mock, patch

from src import brain
from src.config import ConfigManager


class PendingEnforcementTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.config = ConfigManager(str(Path(directory.name) / 'config.json'))
        self.config.config.update(allowed_ips=['203.0.113.10'], ip_check_mode='http')
        self.snapshot = {'state': 'offline', 'ip': '203.0.113.10', 'enforcement_confirmed': False,
                         'enforcement_error': '', 'protection_enabled': True,
                         'access_mode': 'whitelist', 'detect_ip_change': False,
                         'ip_check_mode': 'http', 'allowed_ips': ['203.0.113.10']}

    def test_pending_is_unverified_and_never_an_allow(self):
        for state in ('offline', 'allowed'):
            with self.subTest(state=state), patch.object(brain, 'read_daemon_state', return_value={**self.snapshot, 'state': state}), patch.object(brain, 'perform_ip_check') as fallback:
                verdict, _, reason = brain.get_verdict(self.config)
                self.assertEqual(verdict, 'offline')
                self.assertIn('重新确认', reason)
                fallback.assert_not_called()

    def test_pending_advanced_policy_does_not_probe_or_allow(self):
        for mode in ('risk', 'whitelist'):
            self.config.config.update(access_mode=mode, allow_unknown_ip=True)
            with self.subTest(mode=mode), patch.object(brain, 'read_daemon_state', return_value=self.snapshot), patch.object(brain.policy, 'check') as check:
                self.assertEqual(brain.get_verdict(self.config)[0], 'offline')
                check.assert_not_called()

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS CLI wrapper')
    def test_pending_cannot_launch_a_new_session(self):
        from src import cli_wrapper
        with patch.object(cli_wrapper, 'ConfigManager', return_value=self.config), patch.object(brain, 'read_daemon_state', return_value=self.snapshot), patch.object(cli_wrapper, 'run_real_claude') as launch, patch.object(cli_wrapper, 'sync_hosts_file') as apply, patch.object(cli_wrapper, 'force_restore_terminal'), patch.object(cli_wrapper.signal, 'signal'), self.assertRaises(SystemExit) as exit_info:
            cli_wrapper.main()
        self.assertEqual(exit_info.exception.code, 1)
        launch.assert_not_called()
        apply.assert_not_called()

    def test_failure_and_known_denial_stay_blocked(self):
        snapshots = [
            {**self.snapshot, 'state': 'blocked'},
            {**self.snapshot, 'state': 'allowed', 'enforcement_error': '系统防护执行失败'},
            {'state': 'allowed', 'enforcement_confirmed': False},
        ]
        for snapshot in snapshots:
            with self.subTest(snapshot=snapshot), patch.object(brain, 'read_daemon_state', return_value=snapshot):
                self.assertEqual(brain.get_verdict(self.config)[0], 'blocked')

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS CLI wrapper')
    def test_live_monitor_survives_pending_then_allowed(self):
        from src import cli_wrapper
        self.config.save_config()
        stop = Mock()
        stop.wait.side_effect = [False, False, True]
        child = Mock()
        child.poll.side_effect = [None, None, 0]
        confirmed = {**self.snapshot, 'state': 'allowed', 'enforcement_confirmed': True}
        info = {'blocked': False}
        with patch.object(brain, 'read_daemon_state', side_effect=[self.snapshot, confirmed]):
            cli_wrapper.monitor_and_enforce(self.config, child, stop, info)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()
        self.assertFalse(info['blocked'])
        self.assertEqual(stop.wait.call_count, 3)

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS CLI wrapper')
    def test_live_monitor_still_stops_on_real_failure(self):
        from src import cli_wrapper
        self.config.save_config()
        stop = Mock(); stop.wait.return_value = False
        child = Mock(); child.poll.side_effect = [None, 0, 0]
        info = {'blocked': False}
        failed = {**self.snapshot, 'enforcement_error': '助手失败'}
        with patch.object(brain, 'read_daemon_state', return_value=failed):
            cli_wrapper.monitor_and_enforce(self.config, child, stop, info)
        child.terminate.assert_called_once()
        self.assertTrue(info['blocked'])

    @unittest.skipUnless(sys.platform == 'darwin', 'macOS CLI wrapper')
    def test_abnormal_exit_during_pending_is_not_reported_as_policy_denial(self):
        from src import cli_wrapper
        executable = Path(self.config.path).parent / 'claude'
        executable.write_text('#!/bin/sh\nexit 7\n')
        executable.chmod(0o755)
        self.config.config['real_claude_cli_path'] = str(executable)
        self.config.save_config()
        child = Mock(returncode=7)
        with patch.object(cli_wrapper.subprocess, 'Popen', return_value=child), patch.object(cli_wrapper.threading, 'Thread'), patch.object(cli_wrapper, 'force_restore_terminal'), patch.object(brain, 'read_daemon_state', return_value=self.snapshot), patch.object(cli_wrapper, 'print_block_banner') as banner, self.assertRaises(SystemExit) as exit_info:
            cli_wrapper.run_real_claude(self.config)
        self.assertEqual(exit_info.exception.code, 7)
        banner.assert_not_called()
