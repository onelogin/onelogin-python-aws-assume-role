"""
Command-line options, merged with the defaults in onelogin.aws.json.
"""

import argparse
import json
import os


def get_options():
    parser = argparse.ArgumentParser()

    parser.add_argument("-i", "--client_id",
                        dest="client_id",
                        help="A valid OneLogin API client_id")
    parser.add_argument("-s", "--client_secret",
                        dest="client_secret",
                        help="A valid OneLogin API client_secret")
    parser.add_argument("-r", "--region",
                        dest="region",
                        default="us",
                        help="Onelogin region. us or eu  (Default value: us)")
    parser.add_argument("-t", "--time",
                        dest="time",
                        default=45,
                        type=int,
                        help="Sleep time between iterations, in minutes  [15-60 min]")
    parser.add_argument("-l", "--loop",
                        dest="loop",
                        default=1,
                        type=int,
                        help="Number of iterations")
    parser.add_argument("-p", "--profile",
                        dest="profile_name",
                        help="Save Temporal AWS credentials using that profile name")
    parser.add_argument("-f", "--file",
                        dest="file",
                        help="Set a custom path to save the AWS credentials. (if not used, default AWS path is used)")
    parser.add_argument("-u", "--onelogin-username",
                        dest="username",
                        help="OneLogin username (email address)")
    parser.add_argument("--onelogin-password",
                        dest="password",
                        help="OneLogin password")
    parser.add_argument("--otp",
                        dest="otp",
                        help="2FA OTP")
    parser.add_argument("-a", "--onelogin-app-id",
                        dest="app_id",
                        help="OneLogin app id")
    parser.add_argument("-d", "--onelogin-subdomain",
                        dest="subdomain",
                        help="OneLogin subdomain")
    parser.add_argument("-z", "--duration",
                        dest="duration",
                        type=int,
                        help="Desired AWS Credential Duration")
    parser.add_argument("-x", "--interactive",
                        dest="interactive",
                        default=False,
                        action="store_true",
                        help="Be asked how to proceed in each iteration?")
    parser.add_argument("-c", "--config-file-path",
                        dest="config_file_path",
                        help="Path to config file (onelogin.aws.json)")
    parser.add_argument("--aws-region",
                        dest="aws_region",
                        help="AWS region to use")
    parser.add_argument("--aws-account-id",
                        dest="aws_account_id",
                        help="AWS account id from where to select the role")
    parser.add_argument("--aws-role-name",
                        dest="aws_role_name",
                        help="AWS role name to select")
    parser.add_argument("--cache-saml",
                        dest="cache_saml",
                        default=False,
                        help="Store and use cached SAML Response and the Onelogin info to retrieve it.",
                        action="store_true")
    parser.add_argument("--role_order",
                        dest="role_order",
                        default=False,
                        help="By default in order to select Account/Role, the list will be ordered by account ids. Enable this to list by role name instead.",
                        action="store_true")
    parser.add_argument("--ip",
                        dest="ip",
                        help="The IP address to use for the SAML assertion")
    parser.add_argument("--saml-api-version",
                        dest="saml_api_version",
                        type=int,
                        default=1,
                        help="The version of the OneLogin SAML APIs to use")
    parser.add_argument("--keychain-service",
                        dest="keychain_service",
                        help="Service name in the OSX Keychain entry, seen as \"Where\" in the Keychain GUI")
    parser.add_argument("--keychain-account",
                        dest="keychain_account",
                        help="Account name in the OSX Keychain entry.")
    parser.add_argument("--credential-process",
                        dest="credential_process",
                        default=False,
                        action="store_true",
                        help="Print the credentials as JSON for the AWS credential_process setting, reusing them until they are about to expire")
    options = parser.parse_args()

    if options.credential_process and (options.file or options.loop != 1 or options.interactive):
        parser.error("--credential-process can't be combined with --file, --loop or --interactive")

    # Track which options were provided via command line
    # These should not be overridden by config file values
    cli_provided = {
        'app_id': options.app_id is not None,
        'subdomain': options.subdomain is not None,
        'username': options.username is not None,
        'profile_name': options.profile_name is not None,
        'duration': options.duration is not None,
        'aws_region': options.aws_region is not None,
        'aws_account_id': options.aws_account_id is not None,
        'aws_role_name': options.aws_role_name is not None,
    }

    # Read params from file, but only use them
    # if no value provided on command line
    config = get_config(options.config_file_path)
    if config is not None:
        if 'app_id' in config.keys() and config['app_id'] and not cli_provided['app_id']:
            options.app_id = config['app_id']
        if 'subdomain' in config.keys() and config['subdomain'] and not cli_provided['subdomain']:
            options.subdomain = config['subdomain']
        if 'username' in config.keys() and config['username'] and not cli_provided['username']:
            options.username = config['username']
        if 'profile' in config.keys() and config['profile'] and not cli_provided['profile_name']:
            options.profile_name = config['profile']
        if 'duration' in config.keys() and config['duration'] and not cli_provided['duration']:
            options.duration = config['duration']
        if 'aws_region' in config.keys() and config['aws_region'] and not cli_provided['aws_region']:
            options.aws_region = config['aws_region']
        if 'aws_account_id' in config.keys() and config['aws_account_id'] and not cli_provided['aws_account_id']:
            options.aws_account_id = config['aws_account_id']
        if 'aws_role_name' in config.keys() and config['aws_role_name'] and not cli_provided['aws_role_name']:
            options.aws_role_name = config['aws_role_name']
        # Profile-specific values override global config defaults (but not CLI arguments)
        if 'profiles' in config.keys() and config['profiles'] and options.profile_name and options.profile_name in config['profiles'].keys():
            profile = config['profiles'][options.profile_name]
            if 'aws_account_id' in profile.keys() and profile['aws_account_id'] and not cli_provided['aws_account_id']:
                options.aws_account_id = profile['aws_account_id']
            if 'aws_role_name' in profile.keys() and profile['aws_role_name'] and not cli_provided['aws_role_name']:
                options.aws_role_name = profile['aws_role_name']
            if 'aws_region' in profile.keys() and profile['aws_region'] and not cli_provided['aws_region']:
                options.aws_region = profile['aws_region']
            if 'app_id' in profile.keys() and profile['app_id'] and not cli_provided['app_id']:
                options.app_id = profile['app_id']
        if 'keychain_service' in config.keys() and config['keychain_service'] and not options.keychain_service:
            options.keychain_service = config['keychain_service']
        if 'keychain_account' in config.keys() and config['keychain_account'] and not options.keychain_account:
            options.keychain_account = config['keychain_account']
        if options.keychain_service and not options.keychain_account:
            options.keychain_account = options.username.split("@")[0]
        if options.keychain_account and not options.keychain_service:
            options.keychain_service = 'onelogin'
    options.time = options.time
    if options.time < 15:
        options.time = 15
    elif options.time > 60:
        options.time = 60

    if not options.duration:
        options.duration = 3600
    elif options.duration < 900:
        options.duration = 900
    elif options.duration > 43200:
        options.duration = 43200

    if not options.saml_api_version:
        options.saml_api_version = 1
    elif options.saml_api_version < 1:
        options.saml_api_version = 1
    elif options.saml_api_version > 2:
        options.saml_api_version = 2

    return options


def get_config(config_file_path):
    json_data = None
    config_file_name = 'onelogin.aws.json'

    if config_file_path is not None and os.path.isfile(os.path.join(config_file_path, config_file_name)):
        json_data = open(os.path.join(config_file_path, config_file_name)).read()
    elif os.path.isfile(config_file_name):
        json_data = open(config_file_name).read()
    elif os.path.isfile(os.path.expanduser('~') + '/.onelogin/' + config_file_name):
        json_data = open(os.path.expanduser('~') + '/.onelogin/' + config_file_name).read()
    if json_data is not None:
        return json.loads(json_data)
