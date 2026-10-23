#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for --credential-process: the JSON contract the AWS CLI/SDKs
parse from stdout, the credential cache, and keeping prompts off stdout."""

import sys
import os
import io
import contextlib
import json
import shutil
import stat
import tempfile
import threading
import unittest
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_assume_role import aws_assume_role, credential_process, options, prompts  # noqa: E402


def _options(**overrides):
    values = dict(subdomain='acme', username='user@acme.com', app_id='123',
                  aws_account_id='111111111111', aws_role_name='Admin',
                  profile_name='dev', duration=3600, credential_process=True)
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
        no_terminal = os.path.join(self.cache_dir, 'missing', 'tty')
        patches = [
            mock.patch.object(credential_process, 'CREDENTIAL_CACHE_DIR', self.cache_dir),
            # No terminal: prompts fall back to stderr, as under CI or an IDE
            mock.patch.object(credential_process, 'TERMINAL_INPUT', no_terminal),
            mock.patch.object(credential_process, 'TERMINAL_OUTPUT', no_terminal),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_credential_process(self, options, assume_role):
        stdout, stderr = io.StringIO(), io.StringIO()
        assume_role = mock.Mock(side_effect=assume_role)
        with redirect_stdout(stdout), redirect_stderr(stderr):
            credential_process.credential_process(options, assume_role)
        return assume_role, stdout.getvalue(), stderr.getvalue()

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

    def test_reuses_cached_credentials_until_the_refresh_time(self):
        self.run_credential_process(_options(), lambda options: _sts_response())

        patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_not_called()
        self.assertEqual(json.loads(stdout)['AccessKeyId'], 'ASIAEXAMPLE')

    def write_cache(self, refresh_time, **overrides):
        credentials = {'Version': 1, 'AccessKeyId': 'ASIACACHED', 'SecretAccessKey': 'secret',
                       'SessionToken': 'token', 'Expiration': '2099-01-01T00:00:00Z'}
        credentials.update(overrides)
        cache_path = credential_process.get_credential_cache_path(_options())
        credential_process.write_cached_credentials(cache_path, credentials, refresh_time)

    def test_logs_in_again_after_the_refresh_time(self):
        self.write_cache(datetime.now(timezone.utc) - timedelta(seconds=1))

        patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_called_once()
        self.assertEqual(json.loads(stdout)['AccessKeyId'], 'ASIAEXAMPLE')

    def test_ignores_incomplete_cached_credentials(self):
        for overrides in ({'Version': 2}, {'SessionToken': ''}, {'Expiration': None}):
            with self.subTest(overrides=overrides):
                self.write_cache(datetime.now(timezone.utc) + timedelta(hours=1), **overrides)

                patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

                patched.assert_called_once()
                self.assertEqual(json.loads(stdout)['AccessKeyId'], 'ASIAEXAMPLE')

    def test_fifteen_minute_sessions_are_reused(self):
        # STS's shortest session starts inside botocore's 15-minute advisory window,
        # which re-runs the process straight away; that must not log in again
        self.run_credential_process(_options(), lambda options: _sts_response(timedelta(minutes=15)))

        patched, _, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_not_called()

    def test_refresh_time_is_before_the_advisory_refresh_window(self):
        expiration = datetime.now(timezone.utc) + timedelta(hours=1)

        self.assertEqual(credential_process.get_refresh_time(expiration), expiration - timedelta(minutes=15))

    def test_refresh_time_for_sessions_inside_the_advisory_window_is_the_mandatory_window(self):
        expiration = datetime.now(timezone.utc) + timedelta(minutes=15)

        self.assertEqual(credential_process.get_refresh_time(expiration), expiration - timedelta(minutes=10))

    def test_cache_is_per_role(self):
        self.run_credential_process(_options(), lambda options: _sts_response())

        patched, _, _ = self.run_credential_process(_options(aws_role_name='ReadOnly'), lambda options: _sts_response())

        patched.assert_called_once()

    def test_reuses_a_login_that_finished_while_waiting_for_the_lock(self):
        @contextlib.contextmanager
        def other_run_logs_in_first(cache_path):
            self.write_cache(datetime.now(timezone.utc) + timedelta(hours=1))
            yield

        with mock.patch.object(credential_process, 'credential_cache_lock', other_run_logs_in_first):
            patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_not_called()
        self.assertEqual(json.loads(stdout)['AccessKeyId'], 'ASIACACHED')

    @unittest.skipIf(credential_process.fcntl is None, "no flock on Windows")
    def test_cache_lock_makes_a_concurrent_run_wait(self):
        cache_path = credential_process.get_credential_cache_path(_options())
        acquired = threading.Event()

        def concurrent_run():
            with credential_process.credential_cache_lock(cache_path):
                acquired.set()

        with credential_process.credential_cache_lock(cache_path):
            thread = threading.Thread(target=concurrent_run)
            thread.start()
            self.assertFalse(acquired.wait(0.2))
        thread.join(5)

        self.assertTrue(acquired.is_set())

    def test_cache_is_per_duration(self):
        self.run_credential_process(_options(duration=43200), lambda options: _sts_response(timedelta(hours=12)))

        patched, _, _ = self.run_credential_process(_options(duration=900), lambda options: _sts_response())

        patched.assert_called_once()

    def test_ignores_a_corrupt_cache_file(self):
        cache_path = credential_process.get_credential_cache_path(_options())
        with open(cache_path, 'w') as f:
            f.write('not json')

        patched, stdout, _ = self.run_credential_process(_options(), lambda options: _sts_response())

        patched.assert_called_once()
        self.assertEqual(json.loads(stdout)['Version'], 1)

    @unittest.skipIf(os.name == 'nt', "POSIX permissions")
    def test_cache_file_is_private(self):
        self.run_credential_process(_options(), lambda options: _sts_response())

        cache_path = credential_process.get_credential_cache_path(_options())
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

    def test_keeps_stdin_without_a_terminal_input(self):
        # Windows: getpass only hides the password while sys.stdin is the original
        console = os.path.join(self.cache_dir, 'console')
        stdin = sys.stdin
        with mock.patch.object(credential_process, 'TERMINAL_INPUT', None), \
                mock.patch.object(credential_process, 'TERMINAL_OUTPUT', console), \
                credential_process.prompts_on_terminal():
            self.assertIs(sys.stdin, stdin)
            print("OneLogin Password: ")

        with open(console) as f:
            self.assertEqual(f.read(), "OneLogin Password: \n")


class ReadLineTest(unittest.TestCase):
    def test_returns_the_stripped_answer(self):
        with mock.patch.object(sys, 'stdin', io.StringIO("  dev \n")):
            self.assertEqual(prompts.read_line(), "dev")

    def test_exits_when_input_runs_out(self):
        # get_selection used to re-read '' forever at end of file
        with mock.patch.object(sys, 'stdin', io.StringIO("not a number\n")), \
                self.assertRaises(SystemExit) as raised:
            prompts.get_selection(2)

        self.assertIn("end of file", raised.exception.code)


class CredentialProcessOptionsTest(unittest.TestCase):
    def get_options(self, *args):
        with mock.patch.object(sys, 'argv', ['onelogin-aws-assume-role'] + list(args)), \
                mock.patch.object(options, 'get_config', return_value=None):
            return options.get_options()

    def test_credential_process_flag(self):
        self.assertTrue(self.get_options('--credential-process').credential_process)
        self.assertFalse(self.get_options().credential_process)

    def test_rejects_options_that_write_or_repeat(self):
        for args in (['--loop', '2'], ['--interactive'], ['--file', 'creds']):
            with self.subTest(args=args), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.get_options('--credential-process', *args)


class MainTest(unittest.TestCase):
    def test_credential_process_logs_in_with_assume_role(self):
        selected = _options()
        with mock.patch.object(aws_assume_role, 'get_options', return_value=selected), \
                mock.patch.object(aws_assume_role, 'credential_process') as patched:
            aws_assume_role.main()

        patched.assert_called_once_with(selected, aws_assume_role.assume_role)


if __name__ == '__main__':
    unittest.main()
