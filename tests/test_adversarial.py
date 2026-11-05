import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from src import brain, policy
from src.config import ConfigManager


class AdversarialPolicyTests(unittest.TestCase):
    def test_invalid_boolean_never_disables_protection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            for key, value in [('protection_enabled', 0), ('protection_enabled', ''),
                               ('allow_unknown_ip', 'true'), ('check_interval', True)]:
                with self.subTest(key=key, value=value):
                    path.write_text(json.dumps({'allowed_ips': ['203.0.113.10'], key: value}))
                    config = ConfigManager(str(path))
                    with patch.object(brain, 'perform_ip_check', return_value=('203.0.113.10', True, None)), patch.object(brain, 'read_daemon_state', return_value=None):
                        self.assertEqual(brain.get_verdict(config)[0], 'blocked')

    def test_future_daemon_state_is_not_fresh(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state.json'
            path.write_text(json.dumps({'state': 'allowed', 'updated_at': time.time() + 3600}))
            with patch.object(brain, 'STATE_PATH', str(path)):
                self.assertIsNone(brain.read_daemon_state())

    def test_policy_validates_all_trust_boundary_types(self):
        for data in ({'protection_enabled': 0}, {'allowed_ips': '203.0.113.10'},
                     {'allowed_ips': ['not-an-ip']}, {'allowed_ips': ['fe80::1%utun0']},
                     {'http_proxy': 0}, {'http_proxy': False}, {'http_proxy': 'http://bad%xx:7897'}, {'http_proxy': 'broken-proxy'}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                policy.settings(data)


@unittest.skipUnless(os.name == 'posix', 'POSIX helper')
class HelperAdversarialTests(unittest.TestCase):
    def test_fifo_input_is_rejected_without_blocking(self):
        from native.macos_network_helper import trusted_read
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            started = time.monotonic()
            with self.assertRaises(ValueError):
                trusted_read(fifo, os.getuid())
            self.assertLess(time.monotonic() - started, 0.5)

    def test_failed_copy_preserves_original_destination(self):
        from native import macos_network_helper as helper
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'hosts'
            destination.write_text('127.0.0.1 localhost\n')
            with patch.object(helper.os, 'fsync', side_effect=OSError('disk full')), self.assertRaises(OSError):
                helper.atomic_text(destination, 'replacement')
            self.assertEqual(destination.read_text(), '127.0.0.1 localhost\n')
            self.assertEqual(list(Path(directory).iterdir()), [destination])

class AdmissionEnforcementTests(unittest.TestCase):
    def test_failed_enforcement_never_becomes_an_allow(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / 'config.json'))
            for access in ('whitelist', 'risk'):
                config.config['access_mode'] = access
                with patch.object(brain, 'read_daemon_state', return_value={'state': 'allowed', 'enforcement_confirmed': False}), patch.object(policy, 'check') as check:
                    self.assertEqual(brain.get_verdict(config)[0], 'blocked')
                    check.assert_not_called()

    def test_no_fallback_advanced_check_cannot_run_without_daemon(self):
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / 'config.json'))
            config.config['access_mode'] = 'risk'
            with patch.object(brain, 'read_daemon_state', return_value=None), patch.object(policy, 'check') as check:
                self.assertEqual(brain.get_verdict(config, allow_fallback=False)[0], 'offline')
                check.assert_not_called()

    @unittest.skipUnless(os.sys.platform == 'darwin', 'macOS launchers')
    def test_launchers_stop_after_a_failed_system_receipt(self):
        from src import cli_wrapper, app_launcher
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / 'config.json'))
            config.config.update(access_mode='risk')
            for module, entry, launch in ((cli_wrapper, 'main', 'run_real_claude'), (app_launcher, 'launch_claude_desktop', 'open_real_app')):
                with self.subTest(entry=entry), patch.object(module, 'ConfigManager', return_value=config), patch.object(module, 'get_verdict', return_value=('allowed', '203.0.113.10', None)), patch.object(module, 'sync_hosts_file', return_value=(False, 'receipt failed')), patch.object(module, launch) as start, patch.object(cli_wrapper, 'repair_cli'), patch.object(cli_wrapper, 'force_restore_terminal'), patch.object(app_launcher, 'show_mac_alert'), patch.object(cli_wrapper.signal, 'signal'), self.assertRaises(SystemExit):
                    getattr(module, entry)()
                start.assert_not_called()


class ProbeParserTests(unittest.TestCase):
    def test_stun_rejects_wrong_transaction_cookie_and_truncation(self):
        from src.ip_checker import _parse_stun
        txid = bytes(range(12))
        header = b'\x01\x01\x00\x0c\x21\x12\xa4\x42' + txid
        address = b'\x00\x01\x00\x08\x00\x01\x01\xbb\xcb\x00\x71\x0a'
        packet = header + address
        self.assertEqual(_parse_stun(packet, txid), '203.0.113.10')
        for bad in (packet[:-1], packet + b'\x00', packet[:4] + b'xxxx' + packet[8:]):
            self.assertIsNone(_parse_stun(bad, txid))
        self.assertIsNone(_parse_stun(packet, b'x' * 12))
        # A trailing malformed attribute invalidates a previously valid address.
        self.assertIsNone(_parse_stun(packet[:2] + b'\x00\x10' + packet[4:] + b'\x00\x01\xff\xff', txid))

    def test_json_ip_and_response_size_are_validated(self):
        from src import ip_checker
        from unittest.mock import MagicMock
        for value in (b'{"ip":"garbage"}', b'{"ip":1234}', b'{"ip":"fe80::1%utun0"}', b'x' * 4097):
            response = MagicMock()
            response.__enter__.return_value.read.return_value = value
            with self.subTest(value=value[:30]), patch.object(ip_checker.urllib.request, 'urlopen', return_value=response):
                self.assertIsNone(ip_checker.fetch_public_ip()[0])
                response.__enter__.return_value.read.assert_called_with(4097)


class ExceptionFailClosedTests(unittest.TestCase):
    def test_probe_exception_does_not_allow_when_unknown_is_disabled(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(policy, 'detect', side_effect=RuntimeError('network failure')):
            self.assertEqual(policy.check({'allow_unknown_ip': False}, Path(directory))['state'], 'blocked')

    def test_corrupt_latch_with_unknown_allowed_is_still_denied(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'admission-state.json').write_text('{broken')
            with patch.object(policy, 'detect', side_effect=RuntimeError('network failure')):
                self.assertEqual(policy.check({'allow_unknown_ip': True}, Path(directory))['state'], 'blocked')

@unittest.skipUnless(os.sys.platform == 'darwin', 'macOS network client')
class NetworkReceiptTests(unittest.TestCase):
    def run_request(self, outcome='success'):
        from src import network_guard as client
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pending = root / 'pending'
            status = root / 'status.json'
            values = dict(CONFIG_DIR=str(root), PENDING_DIR=str(pending),
                          PENDING_REQUEST=str(pending / 'request.json'),
                          REQUEST_FILE=str(pending / 'request'), HELPER_STATUS=str(status))
            def apply(*args, **kwargs):
                request = json.loads((pending / 'request.json').read_text())
                status.write_text(json.dumps({'schema': 2, 'request_id': request['request_id'] if outcome != 'stale' else 'b' * 32,
                                              'ok': outcome != 'failed', 'blocked': False, 'updates_blocked': False}))
                status.chmod(0o666 if outcome == 'writable' else 0o644)
                return SimpleNamespace(returncode=0)
            original_fstat = os.fstat
            def root_owned(fd):
                info = list(original_fstat(fd))
                info[4] = 0
                return os.stat_result(info)
            with patch.multiple(client, **values), patch.object(client.os, 'geteuid', return_value=0), patch.object(client.os, 'fstat', side_effect=root_owned), patch.object(client.subprocess, 'run', side_effect=apply), patch.object(client.time, 'sleep'), patch.object(client.time, 'monotonic', side_effect=[0, 0, 0, 16] if outcome == 'stale' else None, return_value=0):
                config = SimpleNamespace(config={'blocked_domains': [], 'update_domains': []})
                return client.sync_hosts_file(False, False, config)

    def test_matching_receipt_required_and_writable_receipt_rejected(self):
        self.assertTrue(self.run_request()[0])
        for outcome in ('failed', 'stale', 'writable'):
            with self.subTest(outcome=outcome):
                self.assertFalse(self.run_request(outcome)[0])

    def test_legacy_pf_preflight_preserves_installation(self):
        import sys
        repo = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            fake = home / 'tools'
            fake.mkdir()
            for name, body in {'uname': '#!/bin/sh\ncase "$1" in -s) echo Darwin;; -m) echo arm64;; esac\n',
                               'sudo': '#!/bin/sh\necho "block drop out quick proto tcp from any to <claude_guard>"\n'}.items():
                path = fake / name
                path.write_text(body)
                path.chmod(0o755)
            env = {**os.environ, 'HOME': str(home), 'PATH': str(fake) + ':' + os.environ['PATH']}
            result = subprocess.run(['/bin/bash', str(repo / 'install.sh')], env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Legacy global ClaudeGuard PF rules detected', result.stderr)
            self.assertFalse((home / '.local').exists())
            trigger = home / 'trigger'
            os.mkfifo(trigger)
            body = (repo / 'install.sh').read_text().split("<<'PYTRIGGER'\n", 1)[1].split('\nPYTRIGGER', 1)[0]
            result = subprocess.run([sys.executable, '-', str(trigger)], input=body, capture_output=True, text=True, timeout=2)
            self.assertNotEqual(result.returncode, 0, 'Installer accepted a FIFO trigger')



class LiteralIPTests(unittest.TestCase):
    def test_non_literal_and_scoped_ips_are_not_policy_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            for value in (True, 1, 'fe80::1%utun0'):
                result = policy.evaluate({'ip_check_mode': 'http', 'allowed_ips': ['::/0', '0.0.0.0/0']}, {'http': value}, Path(directory))
                self.assertEqual(result['state'], 'blocked')
