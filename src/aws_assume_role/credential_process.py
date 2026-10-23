"""
--credential-process: prints the credentials as JSON for the AWS
credential_process setting, cached until they are about to expire.
"""

import contextlib
import hashlib
import json
import os
import sys
import tempfile

from datetime import datetime, timedelta, timezone

try:
    import fcntl
except ImportError:  # Windows
    fcntl = None


CREDENTIAL_CACHE_DIR = os.path.join(os.path.expanduser('~/.aws'), 'onelogin', 'cache')
CREDENTIAL_TIME_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
# botocore re-runs a credential_process on every API call once its credentials are
# within 15 minutes of expiry (advisory refresh), and blocks on it within 10
# minutes (mandatory refresh).
ADVISORY_REFRESH_WINDOW = timedelta(minutes=15)
MANDATORY_REFRESH_WINDOW = timedelta(minutes=10)
TERMINAL_OUTPUT = 'CONOUT$' if os.name == 'nt' else '/dev/tty'
# Windows getpass only hides the password while sys.stdin is the original one, and
# reads the console directly anyway, so stdin is left alone there.
TERMINAL_INPUT = None if os.name == 'nt' else '/dev/tty'


def get_credential_cache_path(options):
    """
    Returns the cache file for the role these options select, so changing the
    role, profile or duration in the config doesn't keep serving the old credentials.
    """
    key = json.dumps([options.subdomain, options.username, options.app_id,
                      options.aws_account_id, options.aws_role_name, options.profile_name, options.duration])
    return os.path.join(CREDENTIAL_CACHE_DIR, hashlib.sha256(key.encode('utf-8')).hexdigest() + '.json')


def get_refresh_time(expiration):
    """
    Returns when cached credentials should be replaced: before botocore's advisory
    refresh window, so a long-running SDK client doesn't run this tool for every
    request. 15-minute sessions start inside that window, so those are kept until
    the mandatory window instead of logging in again on every command.
    """
    if expiration - datetime.now(timezone.utc) > ADVISORY_REFRESH_WINDOW:
        return expiration - ADVISORY_REFRESH_WINDOW
    return expiration - MANDATORY_REFRESH_WINDOW


def read_cached_credentials(cache_path):
    """
    Returns the cached credential_process output, or None when there is none or
    it is due to be replaced.
    """
    try:
        with open(cache_path) as f:
            cached = json.load(f)
        refresh_time = datetime.strptime(cached['RefreshTime'], CREDENTIAL_TIME_FORMAT).replace(tzinfo=timezone.utc)
        credentials = cached['Credentials']
        complete = credentials['Version'] == 1 and all(
            credentials[key] for key in ('AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration'))
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if not complete or datetime.now(timezone.utc) >= refresh_time:
        return None
    return credentials


def write_cached_credentials(cache_path, credentials, refresh_time):
    try:
        os.makedirs(os.path.dirname(cache_path), mode=0o700, exist_ok=True)
        # mkstemp creates the file 0600; the rename stops a concurrent run reading it half-written
        fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(cache_path))
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump({'RefreshTime': refresh_time.strftime(CREDENTIAL_TIME_FORMAT),
                           'Credentials': credentials}, f)
            os.replace(tmp_path, cache_path)
        except OSError:
            os.remove(tmp_path)
            raise
    except OSError as e:
        print("Unable to cache the AWS credentials: %s" % e, file=sys.stderr)


@contextlib.contextmanager
def credential_cache_lock(cache_path):
    """
    Holds a lock on the cache entry while logging in, so concurrent runs for the
    same profile (e.g. several Terraform providers) wait and reuse one login
    instead of each prompting for MFA. Runs unlocked on Windows, or when the
    lock file can't be created.
    """
    lock_file = None
    if fcntl is not None:
        try:
            os.makedirs(os.path.dirname(cache_path), mode=0o700, exist_ok=True)
            lock_file = open(cache_path + '.lock', 'a')
        except OSError:
            pass
    with lock_file or contextlib.nullcontext():
        if lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
        yield


@contextlib.contextmanager
def prompts_on_terminal():
    """
    Sends prompts and messages to the user's terminal while running as a
    credential_process: the AWS CLI/SDK parses stdout as the credentials and
    captures stderr, so neither reaches the user. Falls back to stderr when there
    is no terminal (e.g. when started by an IDE).
    """
    saved_stdin, saved_stdout = sys.stdin, sys.stdout
    with contextlib.ExitStack() as stack:
        try:
            terminal_out = stack.enter_context(open(TERMINAL_OUTPUT, 'w'))
            terminal_in = stack.enter_context(open(TERMINAL_INPUT)) if TERMINAL_INPUT else saved_stdin
        except OSError:
            terminal_in, terminal_out = saved_stdin, sys.stderr
        sys.stdin, sys.stdout = terminal_in, terminal_out
        try:
            yield
        finally:
            sys.stdin, sys.stdout = saved_stdin, saved_stdout


def credential_process(options, assume_role):
    """
    Prints the credentials in the format the AWS CLI/SDKs expect from a
    credential_process. They run it for every command, so the credentials are
    cached until they are about to expire instead of logging in to OneLogin each time.
    https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html
    """
    cache_path = get_credential_cache_path(options)
    output = read_cached_credentials(cache_path)
    if output is None:
        with credential_cache_lock(cache_path):
            # Another run may have logged in while this one waited for the lock
            output = read_cached_credentials(cache_path) or log_in_for_credential_process(options, cache_path, assume_role)
    print(json.dumps(output, indent=2))


def log_in_for_credential_process(options, cache_path, assume_role):
    with prompts_on_terminal():
        try:
            aws_session_token = assume_role(options)
        except SystemExit as e:
            # Prompts give up with a bare sys.exit(); the AWS CLI must see that as a failure
            if not e.code:
                sys.exit(1)
            raise
    credentials = aws_session_token['Credentials']
    expiration = credentials['Expiration'].astimezone(timezone.utc)
    output = {
        'Version': 1,
        'AccessKeyId': credentials['AccessKeyId'],
        'SecretAccessKey': credentials['SecretAccessKey'],
        'SessionToken': credentials['SessionToken'],
        'Expiration': expiration.strftime(CREDENTIAL_TIME_FORMAT),
        'AccountId': aws_session_token['AssumedRoleUser']['Arn'].split(':')[4],
    }
    write_cached_credentials(cache_path, output, get_refresh_time(expiration))
    return output
