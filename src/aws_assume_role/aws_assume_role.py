#!/usr/bin/python

import argparse
import base64
import boto3
import botocore.client
import getpass
import json
import os
import sys
import time

from base64 import b64decode
from botocore.exceptions import ClientError
from datetime import datetime
from lxml import etree as ET
from onelogin.api.client import OneLoginClient

try:
    from aws_assume_role.writer import ConfigFileWriter
    from aws_assume_role.accounts import process_account_and_role_choices
except ImportError:
    from writer import ConfigFileWriter
    from accounts import process_account_and_role_choices


MFA_ATTEMPTS_FOR_WARNING = 3
TIME_SLEEP_ON_RESPONSE_PENDING = 15
MAX_ITER_GET_SAML_RESPONSE = 6
DEFAULT_AWS_DIR = os.path.expanduser('~/.aws')
SAML_CACHE_PATH = os.path.join(DEFAULT_AWS_DIR, 'saml_cache.txt')


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

    options = parser.parse_args()

    # Read params from file, but only use them
    # if no value provided on command line
    config = get_config(options.config_file_path)
    if config is not None:
        if 'app_id' in config.keys() and config['app_id'] and not options.app_id:
            options.app_id = config['app_id']
        if 'subdomain' in config.keys() and config['subdomain'] and not options.subdomain:
            options.subdomain = config['subdomain']
        if 'username' in config.keys() and config['username'] and not options.username:
            options.username = config['username']
        if 'profile' in config.keys() and config['profile'] and not options.profile_name:
            options.profile_name = config['profile']
        if 'duration' in config.keys() and config['duration'] and not options.duration:
            options.duration = config['duration']
        if 'aws_region' in config.keys() and config['aws_region'] and not options.aws_region:
            options.aws_region = config['aws_region']
        if 'aws_account_id' in config.keys() and config['aws_account_id'] and not options.aws_account_id:
            options.aws_account_id = config['aws_account_id']
        if 'aws_role_name' in config.keys() and config['aws_role_name'] and not options.aws_role_name:
            options.aws_role_name = config['aws_role_name']
        if 'profiles' in config.keys() and config['profiles'] and options.profile_name and options.profile_name in config['profiles'].keys():
            profile = config['profiles'][options.profile_name]
            if 'aws_account_id' in profile.keys() and profile['aws_account_id'] and not options.aws_account_id:
                options.aws_account_id = profile['aws_account_id']
            if 'aws_role_name' in profile.keys() and profile['aws_role_name'] and not options.aws_role_name:
                options.aws_role_name = profile['aws_role_name']
            if 'aws_region' in profile.keys() and profile['aws_region'] and not options.aws_region:
                options.aws_region = profile['aws_region']
            if 'app_id' in profile.keys() and profile['app_id'] and not options.app_id:
                options.app_id = profile['app_id']

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


def get_client(options):
    client_id = client_secret = ip = json_data = None
    region = 'us'
    client_file_name = 'onelogin.sdk.json'

    if options.client_id is not None and options.client_secret is not None:
        client_id = options.client_id
        client_secret = options.client_secret
        region = options.region
        ip = options.ip
    else:
        if options.config_file_path is not None and os.path.isfile(os.path.join(options.config_file_path, client_file_name)):
            json_data = open(os.path.join(options.config_file_path, client_file_name)).read()
        elif os.path.isfile(client_file_name):
            json_data = open(client_file_name).read()
        elif os.path.isfile(os.path.expanduser('~') + '/.onelogin/' + client_file_name):
            json_data = open(os.path.expanduser('~') + '/.onelogin/' + client_file_name).read()
        if json_data is not None:
            data = json.loads(json_data)
            if 'client_id' in data.keys() and 'client_secret' in data.keys():
                client_id = data['client_id']
                client_secret = data['client_secret']
                if 'region' in data.keys() and data['region']:
                    region = data['region']
                if 'ip' in data.keys() and data['ip']:
                    ip = data['ip']

    if not client_id or not client_secret:
        raise Exception("OneLogin Client ID and Secret are required")
    client = OneLoginClient(client_id, client_secret, region)
    client.api_configuration["assertion"] = options.saml_api_version
    if ip:
        client.ip = ip
    client.prepare_token()
    if client.error == 401 or client.access_token is None:
        raise Exception("Invalid client_id and client_secret. Access_token could not be retrieved")
    return client


def check_device_exists(devices, device_id):
    for device in devices:
        if device.id == device_id:
            return True
    return False


def get_saml_response(client, username_or_email, password, app_id, onelogin_subdomain, ip=None, mfa_verify_info=None, cmd_otp=None):
    saml_endpoint_response = client.get_saml_assertion(username_or_email, password, app_id, onelogin_subdomain, ip)

    try_get_saml_response = 0
    verified_with_push = False
    while saml_endpoint_response is None or saml_endpoint_response.type == "pending":
        if saml_endpoint_response is None:
            if client.error in ['400', '401']:
                error_msg = "\n\nError %s. %s" % (client.error, client.error_description)
                if client.error_description == "Invalid subdomain":
                    print(error_msg)
                    print("\nOnelogin Instance Sub Domain: ")
                    onelogin_subdomain = sys.stdin.readline().strip()
                elif client.error_description in ["Authentication Failed: Invalid user credentials",
                                                  "password is empty"]:
                    print(error_msg)
                    password = getpass.getpass("\nOneLogin Password: ")
                elif client.error_description == "username is empty":
                    print(error_msg)
                    print("OneLogin Username: ")
                    username_or_email = sys.stdin.readline().strip()
                else:
                    raise Exception(error_msg)
            elif client.error is not None:
                print("Error %s. %s" % (client.error, client.error_description))

        if saml_endpoint_response and saml_endpoint_response.type == "pending":
            time.sleep(TIME_SLEEP_ON_RESPONSE_PENDING)
        saml_endpoint_response = client.get_saml_assertion(username_or_email, password, app_id, onelogin_subdomain, ip)
        try_get_saml_response += 1
        if try_get_saml_response == MAX_ITER_GET_SAML_RESPONSE:
            print("Not able to get a SAMLResponse with success status after %s iteration(s)." % MAX_ITER_GET_SAML_RESPONSE)
            sys.exit()

    if saml_endpoint_response and saml_endpoint_response.type == None:
        print("SAML assertion failed with message: ", saml_endpoint_response.message)
        sys.exit()

    if saml_endpoint_response and saml_endpoint_response.type == "success":
        if saml_endpoint_response.mfa is not None:
            device_type = None
            mfa = saml_endpoint_response.mfa
            devices = mfa.devices
            state_token = mfa.state_token

            if mfa_verify_info is None or 'device_id' not in mfa_verify_info:
                print("\nMFA Required")
                print("Authenticate using one of these devices:")
            else:
                if not check_device_exists(devices, mfa_verify_info['device_id']):
                    print("\nThe device selected with ID %s is not available anymore" % mfa_verify_info['device_id'])
                    print("Those are the devices available now:")
                    mfa_verify_info = None
                else:
                    device_id = mfa_verify_info['device_id']
                    device_type = mfa_verify_info['device_type']

            # Consider case 0 or MFA that requires a trigger
            if mfa_verify_info is None or device_type in ["OneLogin SMS", "OneLogin Protect"]:
                if mfa_verify_info is None:
                    print("-----------------------------------------------------------------------")
                    for index, device in enumerate(devices):
                        print(" " + str(index) + " | " + device.type)

                    print("-----------------------------------------------------------------------")

                    if len(devices) > 1:
                        print("\nSelect the desired MFA Device [0-%s]: " % (len(devices) - 1))
                        device_selection = get_selection(len(devices))
                    else:
                        device_selection = 0
                    device = devices[device_selection]
                    device_id = device.id
                    device_type = device.type

                    mfa_verify_info = {
                        'device_id': device_id,
                        'device_type': device_type,
                    }

                if device_type == "OneLogin SMS":
                    # Trigger SMS
                    saml_endpoint_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, None, do_not_notify=True)
                    print("SMS with OTP token sent to device %s" % device_id)
                elif device_type == "OneLogin Protect":
                    try_get_saml_response_verified = 0
                    # Trigger PUSH and try verify
                    if 'otp_token' not in mfa_verify_info:
                        saml_endpoint_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, None, do_not_notify=False)
                        print("PUSH with OTP token sent to device %s" % device_id)
                    while saml_endpoint_response and saml_endpoint_response.type == "pending" and try_get_saml_response_verified < MAX_ITER_GET_SAML_RESPONSE:
                        time.sleep(TIME_SLEEP_ON_RESPONSE_PENDING)
                        saml_endpoint_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, None, do_not_notify=True)
                        try_get_saml_response_verified += 1

                    if saml_endpoint_response and saml_endpoint_response.type == 'success':
                        verified_with_push = True
                    else:
                        print("PUSH notification not confirmed, trying manual mode")

                if not verified_with_push:
                    if cmd_otp:
                        otp_token = cmd_otp
                    else:
                        # Otherwise, let's request OTP token to be inserted manually
                        print("Enter the OTP Token for %s: " % device_type)
                        otp_token = sys.stdin.readline().strip()
            elif 'otp_token' not in mfa_verify_info:
                if cmd_otp:
                    otp_token = cmd_otp
                else:
                    print("Enter the OTP Token for %s: " % mfa_verify_info['device_type'])
                    otp_token = sys.stdin.readline().strip()
            else:
                otp_token = mfa_verify_info['otp_token']

            if not verified_with_push:
                saml_endpoint_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, otp_token, do_not_notify=True)

                mfa_error = 0
                while client.error or saml_endpoint_response is None:
                    if client.error_description == "State token is invalid or expired":
                        # State token expired so the OTP Token was not able to be processed
                        # regenerate new SAMLResponse and get new state_token
                        return get_saml_response(client, username_or_email, password, app_id, onelogin_subdomain, ip, mfa_verify_info)
                    else:
                        if mfa_error > MFA_ATTEMPTS_FOR_WARNING and len(devices) > 1:
                            print("The OTP Token was not able to be processed after %s attempts, Do you want to select a new MFA method? (y/n)" % MFA_ATTEMPTS_FOR_WARNING)
                            answer = get_yes_or_not()
                            if answer == 'y':
                                # Let's regenerate the SAMLResponse and initialize again the count
                                print("\n")
                                return get_saml_response(client, username_or_email, password, app_id, onelogin_subdomain, ip, None)
                            else:
                                print("Ok, Try introduce a new OTP Token then: ")
                        else:
                            if device_type == "OneLogin SMS":
                                # Trigger SMS, before ask for OTP
                                saml_endpoint_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, None, do_not_notify=True)

                            if client.error_description == "Failed authentication with this factor":
                                print("The OTP Token was invalid or expired, please introduce a new one: ")
                            else:
                                print("The OTP Token was not able to be processed, please introduce a new one: ")

                        otp_token = sys.stdin.readline().strip()
                        saml_endpoint_response = client.get_saml_assertion_verifying(app_id, device_id, state_token, otp_token, do_not_notify=True)

                    mfa_error = mfa_error + 1
                    mfa_verify_info['otp_token'] = otp_token

    if saml_endpoint_response.saml_response is not None:
        print("\nObtained SAMLResponse from OneLogin to be used at AWS")
    result = {
        'saml_response': saml_endpoint_response.saml_response,
        'mfa_verify_info': mfa_verify_info,
        'username_or_email': username_or_email,
        'password': password,
        'onelogin_subdomain': onelogin_subdomain
    }
    return result


def get_attributes(saml_response):
    if not saml_response:
        return {}

    saml_response_xml = base64.b64decode(saml_response)
    saml_response_elem = ET.fromstring(saml_response_xml)
    NSMAP = {
        'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol',
        'saml': 'urn:oasis:names:tc:SAML:2.0:assertion'
    }
    attributes = {}
    attribute_nodes = saml_response_elem.xpath('//saml:AttributeStatement/saml:Attribute', namespaces=NSMAP)
    for attribute_node in attribute_nodes:
        attr_name = attribute_node.get('Name')
        values = []
        for attr in attribute_node.iterchildren('{%s}AttributeValue' % NSMAP['saml']):
            values.append(element_text(attr))
        attributes[attr_name] = values
    return attributes


def element_text(node):
    ET.strip_tags(node, ET.Comment)
    return node.text


def get_yes_or_not():
    answer = None
    while (answer != 'y' and answer != 'n'):
        answer = sys.stdin.readline().strip().lower()
    return answer


def get_selection(max):
    answer = None
    while (answer is None or type(answer) != int or answer not in range(0, max)):
        answer = sys.stdin.readline().strip()
        try:
            answer = int(answer)
        except:
            pass
    return answer


def get_duration():
    answer = None
    while (answer is None or type(answer) != int or answer not in range(900, 43200)):
        answer = sys.stdin.readline().strip()
        try:
            answer = int(answer)
        except:
            pass
    return answer


def ask_iteration_new_user():
    print("\nDo you want to select a new user?  (y/n)")
    answer = get_yes_or_not()
    if answer == 'y':
        return True
    else:
        sys.exit()


def get_data_from_cache():
    """
    Gets the SAML assertion and related user information from cache.
    Returns:
        cache_contents (dict): decoded SAML assertion.
    """
    if not os.path.exists(SAML_CACHE_PATH):
        print('Cache file does not exist!')
        return

    with open(SAML_CACHE_PATH, 'r') as f:
        cache_contents = json.load(f)

    return cache_contents


def write_data_to_cache(contents):
    """
    Writes SAML assertion and related user information from OneLogin to a cache file.
    Arguments:
        contents (dict): all not confidential information from OneLogin returned after a successful SAML authentication.
    """
    print('Writing SAML cache to {saml_cache}'.format(saml_cache=SAML_CACHE_PATH))
    # Avoid storing password and otp_token
    if 'password' in contents:
        del contents['password']
    if 'mfa_verify_info' in contents and contents['mfa_verify_info'] and 'otp_token' in contents['mfa_verify_info']:
        del contents['mfa_verify_info']['otp_token']

    if not os.path.exists(DEFAULT_AWS_DIR):
        os.makedirs(DEFAULT_AWS_DIR)
    with open(SAML_CACHE_PATH, 'w') as f:
        json.dump(contents, f)


def clean_cache():
    """
    Removes the file that contains the cached data
    """
    if os.path.exists(SAML_CACHE_PATH):
        os.remove(SAML_CACHE_PATH)
        print('Cache cleaned.')


def is_valid_saml_assertion(saml_xml):
    """
    Validates that a SAML assertion has not expired by checking the 'NotBefore' and 'NotOnOrAfter' attributes.
    Arguments:
        saml_xml (str): SAML assertion XML as a string.
    Returns:
        bool: True if assertion is not yet expired, False if it is.
    """
    if saml_xml is None:
        return False

    try:
        doc = ET.fromstring(saml_xml)
        conditions = list(doc.iter(tag='{urn:oasis:names:tc:SAML:2.0:assertion}Conditions'))
        if conditions:
            not_before_str = conditions[0].get('NotBefore')
            not_on_or_after_str = conditions[0].get('NotOnOrAfter')

            now = datetime.utcnow()
            not_before = datetime.strptime(not_before_str, "%Y-%m-%dT%H:%M:%SZ")
            not_on_or_after = datetime.strptime(not_on_or_after_str, "%Y-%m-%dT%H:%M:%SZ")

            if not_before <= now < not_on_or_after:
                return True
        return False
    except Exception as e:
        return False


def append_iterations(iterations):
    iterations.append(iterations[-1] + 1)
    return iterations


def main():
    print("\nOneLogin AWS Assume Role Tool\n")

    options = get_options()

    client = get_client(options)

    client.get_access_token()

    mfa_verify_info = None
    role_arn = principal_arn = None
    default_aws_region = 'us-west-2'
    ip = None

    if hasattr(client, 'ip'):
        ip = client.ip

    profile_name = "default"
    if options.profile_name is not None:
        profile_name = options.profile_name

    if options.file is None:
        aws_file = os.path.expanduser('~/.aws/credentials')
    else:
        aws_file = options.file

    cmd_otp = None
    if options.otp:
        cmd_otp = options.otp

    config_file_writer = None
    botocore_config = botocore.client.Config(signature_version=botocore.UNSIGNED)
    ask_for_user_again = False
    ask_for_role_again = False
    sleep = False
    iterations = list(range(0, options.loop))
    duration = options.duration
    username_or_email = password = app_id = onelogin_subdomain = None
    result = None

    for i in iterations:
        if sleep:
            time.sleep(options.time * 60)
            sleep = False

            if result is not None and not is_valid_saml_assertion(b64decode(result['saml_response'])):
                result = None
        # Only use the otp provided by the command line on the first loop
        if i > 0:
            cmd_otp = None

        if options.cache_saml:
            cached_data = get_data_from_cache()
            if cached_data:
                if is_valid_saml_assertion(b64decode(cached_data['saml_response'])):
                    print("Found a valid SAML cache for the user %s" % cached_data['username_or_email'])
                    result = cached_data

                    username_or_email = result['username_or_email']
                    onelogin_subdomain = result['onelogin_subdomain']
                    mfa_verify_info = result['mfa_verify_info']
                    app_id = result['app_id']
                else:
                    print("The cached SAML expired for the user %s" % cached_data['username_or_email'])
                    if i == 0:
                        print("Reuse rest of the data?  (y/n)")
                        answer = get_yes_or_not()
                        if answer == 'y':
                            username_or_email = cached_data['username_or_email']
                            onelogin_subdomain = cached_data['onelogin_subdomain']
                            mfa_verify_info = cached_data['mfa_verify_info']
                            app_id = cached_data['app_id']
                        else:
                            clean_cache()

        # Allow user set a new profile name when switching from User or Role
        if ask_for_user_again or ask_for_role_again:
            if not (options.profile_name is None and options.file is None):
                print("Do you want to set a new profile name?  (y/n)")
                answer = get_yes_or_not()
                if answer == 'y':
                    print("Profile name: ")
                    profile_name = sys.stdin.readline().strip()

        missing_onelogin_data = username_or_email is None or password is None or app_id is None or onelogin_subdomain is None

        if ask_for_user_again:
            print("OneLogin Username: ")
            username_or_email = sys.stdin.readline().strip()

            password = getpass.getpass("\nOneLogin Password: ")
            ask_for_user_again = False
            ask_for_role_again = True
        elif result is None and missing_onelogin_data:
            # Capture OneLogin Account Details
            if username_or_email is None:
                if options.username:
                    username_or_email = options.username
                else:
                    print("OneLogin Username: ")
                    username_or_email = sys.stdin.readline().strip()

            if password is None:
                if options.password:
                    password = options.password
                else:
                    password = getpass.getpass("\nOneLogin Password: ")

            if app_id is None:
                if options.app_id:
                    app_id = options.app_id
                else:
                    print("\nAWS App ID: ")
                    app_id = sys.stdin.readline().strip()

            if options.subdomain:
                onelogin_subdomain = options.subdomain
            else:
                print("\nOnelogin Instance Sub Domain: ")
                onelogin_subdomain = sys.stdin.readline().strip()

        if result is None:
            result = get_saml_response(client, username_or_email, password, app_id, onelogin_subdomain, ip, mfa_verify_info, cmd_otp)

            username_or_email = result['username_or_email']
            password = result['password']
            onelogin_subdomain = result['onelogin_subdomain']
            mfa_verify_info = result['mfa_verify_info']

            if options.cache_saml:
                cached_content = result
                cached_content['app_id'] = app_id
                write_data_to_cache(cached_content)

        saml_response = result['saml_response']

        if i == 0 or ask_for_role_again:
            if ask_for_role_again:
                duration = options.duration

            attributes = get_attributes(saml_response)
            if 'https://aws.amazon.com/SAML/Attributes/Role' not in attributes.keys():
                print("SAMLResponse from Identity Provider does not contain AWS Role info")
                if ask_iteration_new_user():
                    ask_for_user_again = True
                    result = None
                    iterations = append_iterations(iterations)
                    continue
            else:
                roles = attributes['https://aws.amazon.com/SAML/Attributes/Role']

                selected_role = None
                if len(roles) > 1:
                    print("\nAvailable AWS Roles")
                    print("-----------------------------------------------------------------------")
                    info_indexed_by_account = {}
                    info_indexed_by_roles = {}

                    for role in roles:
                        role_info = role.split(",")[0].split(":")
                        account_id = role_info[4]
                        role_name = role_info[5].replace("role/", "")

                        if account_id not in info_indexed_by_account:
                            info_indexed_by_account[account_id] = {}
                        info_indexed_by_account[account_id][role_name] = role

                        if options.role_order:
                            if role_name not in info_indexed_by_roles:
                                info_indexed_by_roles[role_name] = {}
                            info_indexed_by_roles[role_name][account_id] = role

                    selection_info, role_option = process_account_and_role_choices(info_indexed_by_account, info_indexed_by_roles, options)

                    print("-----------------------------------------------------------------------")

                    if role_option is None:
                        if options.aws_account_id and options.aws_role_name:
                            print("SAMLResponse from Identity Provider does not contain available AWS Role: %s for AWS Account: %s" % (options.aws_role_name, options.aws_account_id))
                        print("Select the desired AWS Role [0-%s]: " % (len(roles) - 1))
                        role_option = get_selection(len(roles))

                    selected_role = selection_info[role_option]
                    print("Option %s selected, AWS Role: %s" % (role_option, selected_role))
                elif len(roles) == 1 and roles[0]:
                    data = roles[0].split(',')
                    if data[0] == 'Default' or not data[1]:
                        print("SAMLResponse from Identity Provider does not contain available AWS Account/Role for this user")
                        if ask_iteration_new_user():
                            ask_for_user_again = True
                            result = None
                            iterations = append_iterations(iterations)
                            continue
                    else:
                        selected_role = roles[0]
                        print("Unique AWS Role available selected: %s" % (selected_role))
                else:
                    print("SAMLResponse from Identity Provider does not contain available AWS Role for this user")
                    if ask_iteration_new_user():
                        ask_for_user_again = True
                        result = None
                        iterations = append_iterations(iterations)
                        continue

                selected_role_data = selected_role.split(',')
                role_arn = selected_role_data[0]
                principal_arn = selected_role_data[1]
                ask_for_user_again = False

        if i == 0:
            # AWS Region
            if options.aws_region:
                aws_region = options.aws_region
            else:
                print("\nAWS Region (" + default_aws_region + "): ")
                aws_region = sys.stdin.readline().strip()
            if not aws_region or aws_region == "-":
                aws_region = default_aws_region

        conn = boto3.client('sts', region_name=aws_region, config=botocore_config)
        try:
            if not role_arn or role_arn == "Default" or not principal_arn:
                print("Missing/Invalid selected AWS Role or Account")
                if ask_iteration_new_user():
                    ask_for_user_again = True
                    result = None
                    iterations = append_iterations(iterations)
                    continue
            aws_session_token = conn.assume_role_with_saml(
                RoleArn=role_arn,
                PrincipalArn=principal_arn,
                SAMLAssertion=saml_response,
                DurationSeconds=duration
            )
        except ClientError as err:
            if hasattr(err, 'message'):
                error_msg = err.message
            else:
                error_msg = err.__str__()

            if 'Token must be redeemed within 5 minutes of issuance' in error_msg or \
               'An error occurred (ExpiredTokenException) when calling the AssumeRoleWithSAML operation' in error_msg:
                print(error_msg)
                print("Generating a new SAMLResponse with the data already provided....")
                result = None
                iterations = append_iterations(iterations)
                ask_for_user_again = False
                ask_for_role_again = False
                continue
            elif "The requested DurationSeconds exceeds the MaxSessionDuration set for this role." in error_msg:
                print(error_msg)
                print("Introduce a new value, to be used on this Role, for DurationSeconds between 900 and 43200. Previously was %s" % duration)
                duration = get_duration()
                iterations = append_iterations(iterations)
                ask_for_user_again = False
                ask_for_role_again = False
                continue
            elif "Not authorized to perform sts:AssumeRoleWithSAML" in error_msg:
                print(error_msg)
                ask_for_user_again = True
                result = None
                iterations = append_iterations(iterations)
                continue
            elif "Request ARN is invalid" in error_msg:
                print(error_msg)
                ask_for_user_again = False
                ask_for_role_again = True
                iterations = append_iterations(iterations)
                continue
            else:
                raise err

        access_key_id = aws_session_token['Credentials']['AccessKeyId']
        secret_access_key = aws_session_token['Credentials']['SecretAccessKey']
        session_token = aws_session_token['Credentials']['SessionToken']
        security_token = aws_session_token['Credentials']['SessionToken']
        session_expiration = aws_session_token['Credentials']['Expiration'].strftime('%Y-%m-%dT%H:%M:%S%z')
        arn = aws_session_token['AssumedRoleUser']['Arn']

        if options.profile_name is None and options.file is None:
            action = "export"
            if sys.platform.startswith('win'):
                action = "set"

            print("\n-----------------------------------------------------------------------\n")
            print("Success!\n")
            print("Assumed Role User: %s\n" % arn)
            print("Temporary AWS Credentials Granted via OneLogin\n")
            print("Copy/Paste to set these as environment variables\n")
            print("-----------------------------------------------------------------------\n")

            print("%s AWS_SESSION_TOKEN=%s\n" % (action, session_token))
            print("%s AWS_ACCESS_KEY_ID=%s\n" % (action, access_key_id))
            print("%s AWS_SECRET_ACCESS_KEY=%s\n" % (action, secret_access_key))
            print("%s AWS_SESSION_EXPIRATION=%s\n" % (action, session_expiration))
            print("%s AWS_SECURITY_TOKEN=%s\n" % (action, security_token))
            print("%s AWS_REGION=%s\n" % (action, aws_region))
        else:
            if options.file is None:
                options.file = os.path.expanduser('~/.aws/credentials')

            if options.profile_name is None:
                options.profile_name = "default"

            if config_file_writer is None:
                config_file_writer = ConfigFileWriter()

            updated_config = {
                '__section__': profile_name,
                'aws_access_key_id': access_key_id,
                'aws_secret_access_key': secret_access_key,
                'aws_session_token': session_token,
                'aws_session_expiration': session_expiration,
                'aws_security_token': security_token,
                'region': aws_region
            }
            config_file_writer.update_config(updated_config, aws_file)

            print("Success!\n")
            print("Temporary AWS Credentials Granted via OneLogin\n")
            print("Updated AWS profile '%s' located at %s" % (profile_name, aws_file))

        if options.interactive:
            print("\n\nThe process regenerated credentials for user %s with AWS Role %s " % (username_or_email, selected_role))
            print("Do you want to execute now the process for the same user but with other AWS Role?  (y/n)")
            answer = get_yes_or_not()
            if answer == 'y':
                ask_for_user_again = False
                ask_for_role_again = True
                iterations = append_iterations(iterations)
                continue
            else:
                print("Do you want to execute now the process for other user?  (y/n)")
                ask_for_user_again = True
                result = None
                iterations = append_iterations(iterations)
                continue

        if i < len(iterations) - 1:
            print("This process will regenerate credentials %s more times.\n" % (len(iterations) - i - 1))
            print("Press Ctrl + C to exit")
            sleep = True
        else:
            print("\nExecuted a total of %s iterations" % len(iterations))


if __name__ == '__main__':
    main()
