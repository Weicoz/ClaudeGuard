import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

if os.name == 'posix':
    from native import macos_network_helper as helper


@unittest.skipUnless(sys.platform == 'darwin', 'macOS helper')
class MacOSHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / 'config'
        (self.config / 'pending').mkdir(parents=True, mode=0o700)
        self.hosts = self.root / 'hosts'
        self.hosts.write_text('127.0.0.1 localhost\n10.0.0.1 unrelated.local\n')
        self.request = {'schema': 2, 'request_id': 'a' * 32, 'block_claude_domains': True,
                        'block_update_domains': True, 'claude_domains': ['claude.ai'],
                        'update_domains': ['desktop-app-updates.anthropic.com'], 'ip_addresses': ['203.0.113.10']}
        self.worker = helper.Worker(self.config, os.getuid(), self.root / 'system', self.hosts)
        self.calls = []
        def command(*args):
            self.calls.append(args)
            text = 'anchor "com.apple/*" all\n' if args[-1] == '-sr' else ''
            if args[-1] == '-E':
                return SimpleNamespace(stdout='', stderr='Token : 123456')
            return SimpleNamespace(stdout=text, stderr='')
        self.worker.command = command
        self.worker.boot_id = lambda: 'boot-a'

    def submit(self):
        (self.config / 'pending/request.json').write_text(json.dumps(self.request))
        self.worker.run()
        return json.loads((self.worker.root / 'status.json').read_text())

    def test_only_owned_anchor_and_reference_are_changed(self):
        self.assertTrue(self.submit()['ok'])
        self.assertIn(('/sbin/pfctl', '-a', helper.ANCHOR, '-f', str(self.worker.root / 'pf.verified')), self.calls)
        self.assertIn('10.0.0.1 unrelated.local', self.hosts.read_text())
        for args in self.calls:
            self.assertNotIn('-d', args)
            self.assertNotIn('states', args)
            if '-f' in args or '-F' in args:
                self.assertEqual(args[1:3], ('-a', helper.ANCHOR))
        self.calls.clear()
        self.request.update(request_id='b' * 32, block_claude_domains=False, block_update_domains=False)
        self.assertTrue(self.submit()['ok'])
        self.assertIn(('/sbin/pfctl', '-X', '123456'), self.calls)
        self.assertEqual(self.hosts.read_text(), '127.0.0.1 localhost\n10.0.0.1 unrelated.local\n')

    def test_unprivileged_payload_cannot_write_other_hosts_or_pf_rules(self):
        with self.assertRaises(ValueError):
            helper.checked_directory(self.config, os.getuid() + 1)
        self.config.chmod(0o777)
        try:
            with self.assertRaises(ValueError):
                helper.checked_directory(self.config, os.getuid())
        finally:
            self.config.chmod(0o700)
        for field, value in [('claude_domains', ['evil.test\n1.2.3.4 bank.test']), ('ip_addresses', ['include /etc/pf.conf']), ('ip_addresses', [True])]:
            request = copy.deepcopy(self.request)
            request[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                helper.parse_request(json.dumps(request))
        pending = self.config / 'pending/request.json'
        real = self.root / 'malicious'
        real.write_text(json.dumps(self.request))
        pending.symlink_to(real)
        with self.assertRaises(OSError):
            self.worker.run()
        self.assertEqual(self.calls, [])

    def test_system_failure_receipt_is_false_and_host_contents_survive(self):
        old = self.hosts.read_bytes()
        original = self.worker.command
        def failing(*args):
            if '-f' in args:
                raise subprocess.CalledProcessError(1, args)
            return original(*args)
        self.worker.command = failing
        with self.assertRaises(subprocess.CalledProcessError):
            self.submit()
        status = json.loads((self.worker.root / 'status.json').read_text())
        self.assertFalse(status['ok'])
        self.assertEqual(status['request_id'], self.request['request_id'])
        self.assertEqual(self.hosts.read_bytes(), old)

    def test_reboot_does_not_release_another_boots_enable_token(self):
        self.submit()
        self.worker.boot_id = lambda: 'boot-b'
        self.calls.clear()
        self.request['block_claude_domains'] = False
        self.submit()
        self.assertFalse(any('-X' in args for args in self.calls))

    def test_legacy_global_rules_and_missing_anchor_fail_closed(self):
        original = self.worker.command
        for text in ('block drop out quick to <claude_guard>\n', ''):
            self.worker.command = lambda *args: SimpleNamespace(stdout=text, stderr='') if args[-1] == '-sr' else original(*args)
            old = self.hosts.read_bytes()
            with self.assertRaises(RuntimeError):
                self.submit()
            self.assertEqual(self.hosts.read_bytes(), old)

    def test_no_newline_footer_is_removed_without_losing_unrelated_text(self):
        current = '127.0.0.1 localhost\n# BEGIN CLAUDEGUARD BLOCKS\n0.0.0.0 claude.ai\n# END CLAUDEGUARD BLOCKS'
        request = {**self.request, 'block_claude_domains': False, 'block_update_domains': False}
        self.assertEqual(helper.merged_hosts(current, request), '127.0.0.1 localhost\n')

    def test_ipv6_zone_cannot_inject_pf_syntax(self):
        self.request['ip_addresses'] = ['fe80::1%utun0\n}\npass out all\n#']
        with self.assertRaises(ValueError):
            self.submit()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.hosts.read_text(), '127.0.0.1 localhost\n10.0.0.1 unrelated.local\n')

    def test_existing_host_edits_are_merged_at_apply_time(self):
        self.submit()
        self.hosts.write_text(self.hosts.read_text() + '10.0.0.2 added-later.local\n')
        self.request['block_claude_domains'] = False
        self.submit()
        self.assertIn('added-later.local', self.hosts.read_text())
