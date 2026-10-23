"""
Logs in to OneLogin (including MFA) and gets the SAMLResponse for the AWS app.
"""

import getpass
import json
import os
import sys
import time

try:
    from aws_assume_role.onelogin_client import OneLoginClient
    from aws_assume_role.prompts import read_line, get_yes_or_not, get_selection
except ImportError:
    from onelogin_client import OneLoginClient
    from prompts import read_line, get_yes_or_not, get_selection


MFA_ATTEMPTS_FOR_WARNING = 3
TIME_SLEEP_ON_RESPONSE_PENDING = 15
MAX_ITER_GET_SAML_RESPONSE = 6


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
                    onelogin_subdomain = read_line()
                elif client.error_description in ["Authentication Failed: Invalid user credentials",
                                                  "password is empty"]:
                    print(error_msg)
                    password = getpass.getpass("\nOneLogin Password: ")
                elif client.error_description == "username is empty":
                    print(error_msg)
                    print("OneLogin Username: ")
                    username_or_email = read_line()
                else:
                    # An unrecognized 400/401 here is typically a wrong AWS app
                    # id (or an app the user isn't entitled to). Fail fast rather
                    # than re-submitting credentials, which can lock the account.
                    raise Exception(error_msg + "\nVerify that the AWS app id is "
                                    "correct and assigned to this user.")
            elif client.error is not None:
                # Any other error (e.g. app not found, rate limited, server
                # error) will not be resolved by re-sending the same request.
                # Retrying would burn login attempts and can lock the OneLogin
                # account, so stop here instead of looping (see issue 69).
                print("Error %s. %s" % (client.error, client.error_description))
                sys.exit(1)

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

            if mfa.user and mfa.user.get('id'):
                enriched = client.get_otp_devices(mfa.user['id'])
                if enriched:
                    devices = enriched

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
                        label = device.auth_factor_name or device.type
                        if device.display_name:
                            label += " (%s)" % device.display_name
                        print(" " + str(index) + " | " + label)

                    print("-----------------------------------------------------------------------")

                    if len(devices) > 1:
                        print("\nSelect the desired MFA Device [0-%s]: " % (len(devices) - 1))
                        device_selection = get_selection(len(devices))
                    else:
                        device_selection = 0
                    device = devices[device_selection]
                    device_id = device.id
                    device_type = device.auth_factor_name or device.type

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
                        otp_token = read_line()
            elif 'otp_token' not in mfa_verify_info:
                if cmd_otp:
                    otp_token = cmd_otp
                else:
                    print("Enter the OTP Token for %s: " % mfa_verify_info['device_type'])
                    otp_token = read_line()
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

                        otp_token = read_line()
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
