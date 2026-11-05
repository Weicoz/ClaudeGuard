"""Run the installer's real plist generator without changing launchd or PF."""
import os
from pathlib import Path
import plistlib
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'macOS menu bar installer')
class MenuBarInstallerTests(unittest.TestCase):
    def test_login_starts_a_resident_menu_and_an_independent_guard(self):
        script = (Path(__file__).resolve().parents[1] / 'install.sh').read_text()
        generator = script.split("<<'PYPLIST'\n", 1)[1].split('\nPYPLIST', 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            guard, menu = root / 'guard.plist', root / 'menu.plist'
            install = root / 'Application & Data/ClaudeGuard'
            subprocess.run([sys.executable, '-', str(guard), str(install), str(menu)], input=generator,
                           text=True, check=True, env={**os.environ, 'HOME': directory})
            background, resident = plistlib.loads(guard.read_bytes()), plistlib.loads(menu.read_bytes())
            self.assertEqual(background['ProgramArguments'], [str(install / 'bin/ClaudeGuardMenuBar'), '--daemon'])
            self.assertEqual(resident['ProgramArguments'], [str(install / 'ClaudeGuard.app/Contents/MacOS/ClaudeGuardMenuBar'), '--menu-bar'])
            self.assertNotEqual(resident['Label'], background['Label'])
            self.assertTrue(resident['RunAtLoad'])
            self.assertEqual(resident['KeepAlive'], {'SuccessfulExit': False})
            self.assertTrue(resident['StandardErrorPath'].startswith(directory + '/Library/Logs/ClaudeGuard/'))
