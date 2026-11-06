"""直连防火墙的隔离验证；不调用生产 PF、DNS、launchd 或管理员授权。"""
import json
import os
from pathlib import Path
import plistlib
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

if os.name == 'posix':
    from native import macos_direct_firewall as firewall


@unittest.skipUnless(os.name == 'posix', 'PF 工具隔离测试需要 POSIX')
class DirectFirewallTests(unittest.TestCase):
    def test_scope_and_private_dns_answers(self):
        text = firewall.render_rules(['8.8.8.8', '2606:4700::1111', '127.0.0.1',
                                      '10.0.0.1', '198.18.0.1', '::1', 'ff02::1', 'x\npass out all'], ['en0'])
        for network in firewall.NETWORKS:
            self.assertIn(network, text)
        self.assertIn('2606:4700::1111', text)
        for value in ['127.0.0.1', '10.0.0.1', '198.18.0.1', '::1 ', 'ff02::1', 'pass out all']:
            self.assertNotIn(value, text)
        self.assertIn('out quick on { en0 }', text)
        for interfaces in ([], ['utun0'], ['en0\npass out all']):
            with self.assertRaises(ValueError):
                firewall.render_rules([], interfaces)

    def test_dns_failure_preserves_cache_and_expiry_requires_complete_success(self):
        previous = {'seen': {'8.8.8.8': 1, '1.1.1.1': 999999}}
        seen, missing = firewall.merged_addresses(previous, [('claude.ai', set(), False)], 100000)
        self.assertEqual(set(seen), {'8.8.8.8', '1.1.1.1'})
        self.assertEqual(missing, ['claude.ai'])
        seen, missing = firewall.merged_addresses(previous, [('claude.ai', {'9.9.9.9'}, True)], 100000)
        self.assertEqual(set(seen), {'9.9.9.9', '1.1.1.1'})
        self.assertEqual(missing, [])

    def test_dns_nxdomain_is_not_a_transport_failure(self):
        result = SimpleNamespace(returncode=0, stdout='{"Status": 3}')
        with patch.object(firewall.subprocess, 'run', return_value=result):
            self.assertEqual(firewall.resolve_domain('claude.app'), ('claude.app', set(), True))
        result.stdout = '{"Status": 0, "Answer": [{"type": 1, "data": "160.79.104.10"}]}'
        with patch.object(firewall.subprocess, 'run', return_value=result):
            self.assertEqual(firewall.resolve_domain('claude.ai'), ('claude.ai', {'160.79.104.10'}, True))
        self.assertEqual(firewall.target_networks(['160.79.104.10']), list(firewall.NETWORKS))

    def test_dns_rejects_fake_addresses_and_bad_https_answers(self):
        for response in ('{"Status": 0, "Answer": [{"type": 1, "data": "198.18.0.8"}]}',
                         '{"Status": 2}', '{"Status": 0, "TC": true}', 'not json', '[]'):
            result = SimpleNamespace(returncode=0, stdout=response)
            with patch.object(firewall.subprocess, 'run', return_value=result) as run:
                domain, addresses, successful = firewall.resolve_domain('claude.ai')
                self.assertFalse(successful)
                self.assertFalse(addresses)
                self.assertIn('--proto', run.call_args.args[0])

    def test_physical_interfaces_exclude_tunnels_and_loopback(self):
        with patch.object(firewall.socket, 'if_nameindex', return_value=[(1, 'lo0'), (2, 'en0'), (3, 'utun0'), (4, 'bridge0')]):
            self.assertEqual(self.original_interfaces(), ['bridge0', 'en0'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name) / 'firewall'
        root.mkdir()
        self.worker = firewall.Firewall(root, Path(self.temp.name) / 'job.plist')
        self.original_interfaces = firewall.physical_interfaces
        self.calls = []
        self.live_text = ''
        self.enabled = False
        self.boot = '12345678-1234-1234-1234-123456789abc'

        def fake_command(*args):
            self.calls.append(args)
            stdout, stderr = '', ''
            if args[0] == '/sbin/pfctl':
                flags = args[1:]
                if flags == ('-sr',):
                    stdout = 'anchor "com.apple/*" all\n'
                elif flags == ('-a', firewall.PARENT_ANCHOR, '-sr'):
                    stdout = 'anchor "direct" all\n'
                elif flags == ('-si',):
                    stdout = 'Status: ' + ('Enabled' if self.enabled else 'Disabled')
                elif flags == ('-E',):
                    self.enabled, stderr = True, 'Token : 123456\n'
                elif 'Interfaces' in flags:
                    stdout = flags[-1] + '\n'
                elif flags[:2] == ('-a', firewall.ANCHOR) and '-f' in flags:
                    self.live_text = Path(flags[-1]).read_text()
                elif flags == ('-a', firewall.ANCHOR, '-sr'):
                    stdout = self.live_text
                elif flags[-2:] == ('-T', 'show'):
                    stdout = '\n'.join(self.live_text.split('persist { ', 1)[1].split(' }', 1)[0].split())
            elif args[0] == '/usr/sbin/sysctl':
                stdout = self.boot
            return SimpleNamespace(stdout=stdout, stderr=stderr, returncode=0)

        self.runner = fake_command
        self.addCleanup(patch.stopall)
        patch.object(firewall, 'command', side_effect=fake_command).start()
        patch.object(firewall, 'physical_interfaces', return_value=['en0']).start()
        self.worker.prepare = lambda: None

    def test_repeated_apply_owns_one_reference_and_kills_only_new_targets(self):
        self.worker.apply({'8.8.8.8': 10}, [])
        self.worker.apply({'8.8.8.8': 10}, [])
        self.assertEqual(self.calls.count(('/sbin/pfctl', '-E')), 1)
        kills = [call for call in self.calls if '-k' in call]
        self.assertEqual(len(kills), 4)
        self.assertIn(('/sbin/pfctl', '-k', '::/0', '-k', '2607:6bc0::/32'), kills)
        for call in self.calls:
            if call[0] == '/sbin/pfctl':
                self.assertNotIn('-d', call)
                self.assertNotIn('states', call)
                if '-f' in call or '-F' in call:
                    self.assertIn(firewall.ANCHOR, call)

    def test_failed_replacement_restores_old_rules(self):
        self.worker.apply({}, [])
        previous = (self.worker.root / 'rules.pf').read_text()

        def failure(*args):
            if args[-2:] == ('-T', 'show'):
                return SimpleNamespace(stdout='8.8.4.4', stderr='')
            return self.runner(*args)

        with patch.object(firewall, 'command', side_effect=failure), self.assertRaises(RuntimeError):
            self.worker.apply({'8.8.8.8': 10}, [])
        self.assertEqual(self.live_text, previous)
        self.assertEqual((self.worker.root / 'rules.pf').read_text(), previous)

    def test_missing_anchor_never_loads_or_enables_pf(self):
        for rules in ('', 'anchor "com.apple/*" in proto tcp all\n'):
            with patch.object(firewall, 'command', return_value=SimpleNamespace(stdout=rules, stderr='')):
                with self.assertRaises(RuntimeError):
                    self.worker.apply({}, [])
        self.assertEqual(self.calls, [])

    def test_live_verification_rejects_skipped_interface(self):
        self.worker.apply({}, [])

        def skipped(*args):
            if 'Interfaces' in args:
                return SimpleNamespace(stdout='en0 (skip)\n', stderr='')
            return self.runner(*args)

        with patch.object(firewall, 'command', side_effect=skipped), self.assertRaises(RuntimeError):
            self.worker.verify({})

    def test_refresh_applies_fixed_ranges_before_dns_and_keeps_old_ips(self):
        self.worker.apply({'8.8.8.8': 1}, [])
        events = []
        original = self.worker.apply
        self.worker.apply = lambda seen, missing: (events.append('apply'), original(seen, missing))[-1]

        def resolve(domain):
            self.assertEqual(events[0], 'apply')
            return domain, set(), False

        with patch.object(firewall, 'resolve_domain', side_effect=resolve):
            self.worker.refresh()
        data = json.loads((self.worker.root / 'status.json').read_text())
        self.assertIn('8.8.8.8', data['seen'])
        self.assertEqual(data['unresolved'], list(firewall.DOMAINS))

    def test_install_and_uninstall_touch_only_owned_files_and_anchor(self):
        with patch.object(self.worker, 'refresh', side_effect=lambda: self.worker.apply({}, [])), patch.object(firewall.subprocess, 'run'):
            self.worker.install()
        job = plistlib.loads(self.worker.plist.read_bytes())
        self.assertEqual(job['StartInterval'], 300)
        self.assertEqual(job['ProgramArguments'][-1], 'refresh')
        self.assertIn('-I', job['ProgramArguments'])
        self.calls.clear()
        with patch.object(firewall.subprocess, 'run'):
            self.worker.uninstall()
        self.assertIn(('/sbin/pfctl', '-X', '123456'), self.calls)
        self.assertFalse(self.worker.root.exists())
        self.assertTrue(all(firewall.ANCHOR in call or '-X' in call or 'sysctl' in call[0] for call in self.calls))

    def test_uninstall_does_not_release_previous_boot_token(self):
        self.worker.apply({}, [])
        self.boot = '87654321-4321-4321-4321-cba987654321'
        self.calls.clear()
        with patch.object(firewall.subprocess, 'run'):
            self.worker.uninstall()
        self.assertFalse(any('-X' in call for call in self.calls))

    def test_state_symlink_and_bad_permissions_are_rejected(self):
        path = Path(self.temp.name) / 'data.json'
        path.write_text('{}')
        link = path.with_name('link.json')
        link.symlink_to(path)
        with self.assertRaises(OSError):
            firewall.trusted_json(link, os.getuid())
        path.chmod(0o666)
        with self.assertRaises(ValueError):
            firewall.trusted_json(path, os.getuid())


if __name__ == '__main__':
    unittest.main()
