#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Smoke test: the CLI module must import with only its declared dependencies.

This guards against a runtime dependency being used in code but missing from
`setup.py` / `requirements.txt` (e.g. `keyring`, which a fresh `pip install`
must pull in or the console script crashes on startup).
"""

import sys
import os
import subprocess
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))


class CliImportTest(unittest.TestCase):
    def test_cli_module_imports(self):
        # Importing the entry-point module exercises every top-level import
        # (keyring, boto3, lxml, yaml, requests, ...). If any declared
        # dependency is missing, this raises ModuleNotFoundError.
        from aws_assume_role import aws_assume_role
        self.assertTrue(callable(aws_assume_role.main))

    def test_script_runs_from_a_source_checkout(self):
        # Run by path, the modules fall back to importing each other without
        # the aws_assume_role package prefix
        script = os.path.join(os.path.dirname(__file__), '..', 'src', 'aws_assume_role', 'aws_assume_role.py')
        result = subprocess.run([sys.executable, script, '--help'], capture_output=True, text=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--credential-process', result.stdout)


if __name__ == '__main__':
    unittest.main()
