#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for ConfigFileWriter, which saves the credentials for --profile and --file."""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_assume_role.writer import ConfigFileWriter  # noqa: E402


class CreateFileTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def write_and_read(self, path, read_path):
        ConfigFileWriter().update_config({'__section__': 'dev', 'region': 'us-east-1'}, path)
        with open(read_path) as f:
            return f.read()

    def test_creates_a_file_named_without_a_directory(self):
        # --file creds puts the file in the current directory
        cwd = os.getcwd()
        os.chdir(self.dir)
        self.addCleanup(os.chdir, cwd)

        contents = self.write_and_read('creds', os.path.join(self.dir, 'creds'))

        self.assertEqual(contents, '\n[dev]\nregion = us-east-1\n')

    def test_creates_missing_parent_directories(self):
        path = os.path.join(self.dir, 'aws', 'credentials')

        self.assertEqual(self.write_and_read(path, path), '\n[dev]\nregion = us-east-1\n')


if __name__ == '__main__':
    unittest.main()
