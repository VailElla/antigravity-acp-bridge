#!/usr/bin/env python3
"""Check that bootstrapping validates the executable and protects existing state."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class BootstrapTests(unittest.TestCase):
    def test_isolated_setup_checks_hash_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake = root / "mock-agy"
            fake.write_bytes(b"not a real upstream executable")
            digest = hashlib.sha512(fake.read_bytes()).hexdigest()
            destination = root / "private"
            script = Path(__file__).resolve().with_name("bootstrap.py")
            common = [sys.executable, "-I", "-B", str(script), "--agy", str(fake),
                      "--client-version", "test", "--root", str(destination)]

            bad = subprocess.run([*common, "--sha512", "0" * 128], capture_output=True)
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse(destination.exists())

            created = subprocess.run([*common, "--sha512", digest], capture_output=True, check=True)
            token = (destination / "auth_token.txt").read_text().strip()
            self.assertGreaterEqual(len(token), 24)
            self.assertNotIn(token.encode(), created.stdout + created.stderr)
            config = json.loads((destination / "bridge_config.json").read_text())
            self.assertEqual(config["expected_sha512"], digest)
            self.assertEqual(config["listen_host"], "127.0.0.1")
            if os.name != "nt":
                self.assertEqual((destination.stat().st_mode & 0o777), 0o700)
                self.assertEqual(((destination / "auth_token.txt").stat().st_mode & 0o777), 0o600)
            repeated = subprocess.run([*common, "--sha512", digest], capture_output=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual((destination / "auth_token.txt").read_text().strip(), token)


if __name__ == "__main__":
    unittest.main()
