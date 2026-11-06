"""macOS 自动防护只改网络，不因策略拒绝终止已有会话。"""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch


@unittest.skipUnless(sys.platform == 'darwin', 'macOS CLI wrapper')
class NetworkOnlySessionTests(unittest.TestCase):
    def test_migration_disables_legacy_monitor_flag_and_keeps_network_policy_active(self):
        from src.config import ConfigManager
        from src import policy
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / 'config.json'))
            config.config.update(allowed_ips=['203.0.113.10'], ip_check_mode='http')
            config.save_config()
            config.migrate_network_only()
            legacy_data = json.loads(Path(config.path).read_text())
            self.assertIs(legacy_data['protection_enabled'], False)
            self.assertTrue(config.protection_enabled)
            result = policy.evaluate(config.config, {'http': '203.0.113.20'}, directory)
            self.assertEqual(result['state'], 'blocked')
            backups = list(Path(directory).glob('config-before-network-only-*.json'))
            self.assertEqual(len(backups), 1)
            self.assertTrue(json.loads(backups[0].read_text())['protection_enabled'])
            config.protection_enabled = False
            self.assertFalse(config.config['protection_enabled'])
            self.assertFalse(config.config['network_protection_enabled'])

    def test_known_denial_blocks_network_without_terminating_child(self):
        from src import cli_wrapper
        from src.config import ConfigManager
        with tempfile.TemporaryDirectory() as directory:
            config = ConfigManager(str(Path(directory) / 'config.json'))
            config.save_config()
            child = Mock()
            child.poll.return_value = None
            stop = Mock()
            stop.wait.side_effect = [False, True]
            with patch.object(cli_wrapper, 'get_verdict', return_value=('blocked', '203.0.113.10', '出口未通过')), patch.object(cli_wrapper, 'sync_hosts_file', return_value=(True, 'ok')) as network:
                cli_wrapper.monitor_and_enforce(config, child, stop, {})
            child.terminate.assert_not_called()
            child.kill.assert_not_called()
            network.assert_called_once_with(block_claude_domains=True, block_update_domains=config.block_auto_updates, config=config)


if __name__ == '__main__':
    unittest.main()
