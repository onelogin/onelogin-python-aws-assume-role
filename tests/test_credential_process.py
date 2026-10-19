#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for --credential-process: the JSON contract the AWS CLI/SDKs
parse from stdout, the credential cache, and keeping prompts off stdout."""

import sys
import os
import io
import json
import shutil
import stat
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_assume_role import aws_assume_role  # noqa: E402


def _options(**overrides):
    values = dict(subdomain='acme', username='user@acme.com', app_id='123',
                  aws_account_id='111111111111', aws_role_name='Admin',
                  profile_name='dev', credential_process=True)
    values.update(overrides)
    return mock.Mock(**values)


def _sts_response(expires_in=timedelta(hours=1)):
    return {
        'Credentials': {
            'AccessKeyId': 'ASIAEXAMPLE',
            'SecretAccessKey': 'secret',
            'SessionToken': 'token',
            'Expiration': datetime.now(timezone.utc).replace(microsecond=0) + expires_in,
        },
        'AssumedRoleUser': {'Arn': 'arn:aws:sts::111111111111:assumed-role/Admin/user@acme.com'},
    }


class CredentialProcessTest(unittest.TestCase):
    def setUp(self):
        self.cache_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.cache_dir)
        patches = [
            mock.patch.object(aws_assume_role, 'CREDENTIAL_CACHE_DIR', self.cache_dir),
            # No terminal: prompts fall back to stderr, as under CI or an IDE
            mock.patch.object(aws_assume_role, 'TERMINAL_INPUT', os.path.join(self.cache_dir, 'missing')),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_credential_process(self, options, assume_role):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(aws_assume_role, 'assume_role', side_effect=assume_role) as patched, \
                redirect_stdout(stdout), redirect_stderr(stderr):
            aws_assume_role.credential_process(options)
        return patched, stdout.getvalue(), stderr.getvalue()

    def test_prints_only_the_credential_process_json_on_stdout(self):
        response = _sts_response()

        def assume_role(options):
            print("OneLogin Username: ")
            return response

        _, stdout, stderr = self.run_credential_process(_options(), assume_role)

        self.assertEqual(json.loads(stdout), {
            'Version': 1,
            'AccessKeyId': 'ASIAEXAMPLE',
            'SecretAccessKey': 'secret',
            'SessionToken': 'token',
            'Expiration': response['Credentials']['Expiration'].strftime('%Y-%m-%dT%H:%M:%SZ'),
            'AccountId': '111111111111',
        })
        self.assertIn("OneLogin Username:", stderr)

    def test_expiration_is_converted_to_utc(self):
        response = _sts_response()
        utc_expiration = response['Credentials']['Expiration']
        response['Credentials']['Expiration'] = utc_expiration.astimezone(timezone(timedelta(hours=-7)))

        _, stdout, _ = self.run_credential_process(_options(), lambda options: response)

        self.assertEqual(json.loads(stdout)['Expiration'], utc_expiration.strftime('%Y-%m-%dT%H:%M:%SZ'))

    def test_reuses_cached_credentials_until_near_expiry(self):
        self.run_credential_process(_options(), lambda options: _sts_response())

        patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_not_called()
        self.assertEqual(json.loads(stdout)['AccessKeyId'], 'ASIAEXAMPLE')

    def test_logs_in_again_when_cached_credentials_are_near_expiry(self):
        self.run_credential_process(_options(), lambda options: _sts_response(timedelta(minutes=9)))

        patched, _, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_called_once()

    def test_cache_is_per_role(self):
        self.run_credential_process(_options(), lambda options: _sts_response())

        patched, _, _ = self.run_credential_process(_options(aws_role_name='ReadOnly'), lambda options: _sts_response())

        patched.assert_called_once()

    def test_ignores_a_corrupt_cache_file(self):
        cache_path = aws_assume_role.get_credential_cache_path(_options())
        with open(cache_path, 'w') as f:
            f.write('not json')

        patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_called_once()
        self.assertEqual(json.loads(stdout)['Version'], 1)

    @unittest.skipIf(os.name == 'nt', "POSIX permissions")
    def test_cache_file_is_private(self):
        self.run_credential_process(_options(), lambda options: _sts_response())

        cache_path = aws_assume_role.get_credential_cache_path(_options())
        self.assertEqual(stat.S_IMODE(os.stat(cache_path).st_mode), 0o600)

    def test_bare_exit_from_a_prompt_is_a_failure(self):
        def assume_role(options):
            sys.exit()

        with self.assertRaises(SystemExit) as raised:
            self.run_credential_process(_options(), assume_role)

        self.assertEqual(raised.exception.code, 1)

    def test_restores_stdin(self):
        stdin = sys.stdin
        self.run_credential_process(_options(), lambda options: _sts_response())

        self.assertIs(sys.stdin, stdin)


class CredentialProcessOptionsTest(unittest.TestCase):
    def get_options(self, *args):
        with mock.patch.object(sys, 'argv', ['onelogin-aws-assume-role'] + list(args)), \
                mock.patch.object(aws_assume_role, 'get_config', return_value=None):
            return aws_assume_role.get_options()

    def test_credential_process_flag(self):
        self.assertTrue(self.get_options('--credential-process').credential_process)
        self.assertFalse(self.get_options().credential_process)

    def test_rejects_options_that_write_or_repeat(self):
        for args in (['--loop', '2'], ['--interactive'], ['--file', 'creds']):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.get_options('--credential-process', *args)


if __name__ == '__main__':
    unittest.main()
