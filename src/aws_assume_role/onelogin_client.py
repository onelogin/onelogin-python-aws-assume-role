#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, OneLogin, Inc.
# All rights reserved.

"""
Minimal OneLogin client for the AWS assume-role flow.

Historically this tool depended on the ``onelogin`` Python SDK. That SDK was
rewritten as an OpenAPI-generated client (3.x/4.x): the hand-written
``OneLoginClient`` god-object this tool was built on was removed, and the
generated SAML-assertion response model rejects the success-case payload (the
API returns ``data`` as a base64 string on success but the model types it as a
list). See GitHub issue 76.

The tool only ever calls three documented OneLogin REST endpoints
(token, generate SAML assertion, verify factor), so rather than depend on a
fragile SDK we talk to those endpoints directly with ``requests``. This module
exposes the small subset of the old ``OneLoginClient`` surface the CLI uses, so
the calling code is unchanged.

The response-parsing logic (``handle_saml_endpoint_response`` and the
``SAMLEndpointResponse``/``MFA``/``Device`` shapes) is ported verbatim from the
behaviour of onelogin-python-sdk 2.0.4, the last release with the old API.
"""

import datetime

import requests


# OneLogin API endpoint templates. The first ``%s`` is the subdomain
# (``api.<region>`` or a custom account subdomain); the second, where present,
# is the API version (1 or 2).
TOKEN_REQUEST_URL = "https://%s.onelogin.com/auth/oauth2/v2/token"
GET_SAML_ASSERTION_URL = "https://%s.onelogin.com/api/%s/saml_assertion"
GET_SAML_VERIFY_FACTOR = "https://%s.onelogin.com/api/%s/saml_assertion/verify_factor"
# The User Management API is versioned independently of the SAML Assertion
# API, so this path hardcodes v1 rather than reusing the assertion version.
GET_OTP_DEVICES_URL = "https://%s.onelogin.com/api/1/users/%s/otp_devices"

# Versions supported by the SAML assertion endpoints; the last entry is the
# default when the caller does not request a specific version.
SAML_ASSERTION_VERSIONS = [1, 2]


class Device(object):
    def __init__(self, data):
        self.id = data.get('device_id', data.get('id'))
        self.type = str(data.get('device_type', data.get('type_display_name', data.get('type', ''))))
        self.display_name = data.get('user_display_name', '')
        self.auth_factor_name = data.get('auth_factor_name', '')
        self.default = data.get('default', False)
        self.active = data.get('active', True)
        self.needs_trigger = data.get('needs_trigger', False)


class MFA(object):
    def __init__(self, data):
        self.state_token = str(data.get('state_token', ''))
        self.callback_url = str(data.get('callback_url', ''))
        self.user = data.get('user')
        self.devices = []
        for device in data.get('devices', []) or []:
            self.devices.append(Device(device))


class SAMLEndpointResponse(object):
    def __init__(self, status_type, status_message):
        self.type = status_type
        self.message = str(status_message)
        self.mfa = None
        self.saml_response = None


def extract_error_message(content):
    """Pull a human-readable error description out of an API error body."""
    message = ''
    if content and 'status' in content:
        status = content['status']
        if isinstance(status, dict):
            if 'message' in status:
                if isinstance(status['message'], dict):
                    message = status['message'].get('description', '')
                else:
                    message = status['message']
            elif 'type' in status:
                message = status['type']
    return message


def handle_saml_endpoint_response(content, version_id):
    """Build a SAMLEndpointResponse from a decoded SAML-assertion API body.

    Ported from onelogin-python-sdk 2.0.4. ``content`` is the parsed JSON of a
    200 response from ``saml_assertion`` or ``saml_assertion/verify_factor``.
    """
    saml_endpoint_response = None
    try:
        if version_id == 1:
            if (content and 'status' in content and 'message' in content['status']
                    and 'type' in content['status']):
                status_type = content['status']['type']
                status_message = content['status']['message']
                saml_endpoint_response = SAMLEndpointResponse(status_type, status_message)
                if 'data' in content:
                    if status_message == 'Success':
                        saml_endpoint_response.saml_response = str(content['data'])
                    else:
                        saml_endpoint_response.mfa = MFA(content['data'][0])
        elif version_id == 2:
            if 'message' in content:
                status_type = None
                if content['message'] == "Success" or "MFA is required" in content['message']:
                    status_type = "success"
                elif "pending" in content['message']:
                    status_type = "pending"
                status_message = content['message']
                saml_endpoint_response = SAMLEndpointResponse(status_type, status_message)
                if 'data' in content:
                    saml_endpoint_response.saml_response = str(content['data'])
                elif "state_token" in content:
                    saml_endpoint_response.mfa = MFA(content)
    except Exception:
        pass
    return saml_endpoint_response


class OneLoginClient(object):
    """A drop-in replacement for the subset of onelogin 2.0.4's OneLoginClient
    that this CLI relies on, implemented directly against the OneLogin REST API.
    """

    def __init__(self, client_id, client_secret, region='us', subdomain=None,
                 default_timeout=(10, 60)):
        self.client_id = client_id
        self.client_secret = client_secret
        self.region = "us" if region is None else region
        self.subdomain = subdomain
        self.default_timeout = default_timeout

        self.access_token = None
        self.refresh_token = None
        self.expiration = None
        self.ip = None
        # Mirrors the old SDK: callers set api_configuration["assertion"] to pin
        # the SAML assertion API version.
        self.api_configuration = {}

        self.error = None
        self.error_description = None

    # -- helpers -----------------------------------------------------------

    def _get_subdomain(self):
        return self.subdomain if self.subdomain else "api.%s" % self.region

    def _assertion_version(self):
        version = self.api_configuration.get('assertion')
        if version in SAML_ASSERTION_VERSIONS:
            return version
        return SAML_ASSERTION_VERSIONS[-1]

    def clean_error(self):
        self.error = None
        self.error_description = None

    def set_error(self, response):
        self.error = str(response.status_code)
        try:
            content = response.json()
        except ValueError:
            content = None
        self.error_description = extract_error_message(content)

    def get_headers(self):
        return {
            'Content-Type': 'application/json',
            'User-Agent': 'onelogin-aws-assume-role',
        }

    def get_authorized_headers(self, bearer=True):
        headers = self.get_headers()
        if bearer:
            headers['Authorization'] = "bearer %s" % self.access_token
        else:
            headers['Authorization'] = "client_id:%s, client_secret:%s" % (
                self.client_id, self.client_secret)
        return headers

    # -- OAuth token -------------------------------------------------------

    def is_expired(self):
        return (self.expiration is not None
                and datetime.datetime.now() > self.expiration)

    def get_access_token(self):
        """Generate an OAuth access token from the API credentials."""
        self.clean_error()
        url = TOKEN_REQUEST_URL % self._get_subdomain()
        headers = self.get_authorized_headers(bearer=False)
        response = requests.post(url, headers=headers,
                                 json={'grant_type': 'client_credentials'},
                                 timeout=self.default_timeout)
        if response.status_code == 200:
            data = response.json()
            # The v2 token response can be flat or wrapped in {status, data}.
            if isinstance(data, dict) and 'data' in data and 'access_token' not in data:
                token = data['data'][0] if isinstance(data['data'], list) else data['data']
            else:
                token = data
            self.access_token = token.get('access_token')
            self.refresh_token = token.get('refresh_token')
            expires_in = token.get('expires_in')
            if expires_in:
                self.expiration = (datetime.datetime.now()
                                   + datetime.timedelta(seconds=expires_in))
            return token
        self.set_error(response)

    def prepare_token(self):
        if self.access_token is None:
            self.get_access_token()
        elif self.is_expired():
            self.get_access_token()

    # -- SAML assertion ----------------------------------------------------

    def _retrieve_saml_assertion(self, url, data, version_id):
        self.clean_error()
        response = requests.post(url, headers=self.get_authorized_headers(bearer=True),
                                 json=data, timeout=self.default_timeout)
        if response.status_code == 200:
            try:
                content = response.json()
            except ValueError:
                content = None
            return handle_saml_endpoint_response(content, version_id)
        self.set_error(response)

    def get_saml_assertion(self, username_or_email, password, app_id, subdomain,
                           ip_address=None):
        version_id = self._assertion_version()
        url = GET_SAML_ASSERTION_URL % (self._get_subdomain(), version_id)
        data = {
            'username_or_email': username_or_email,
            'password': password,
            'app_id': app_id,
            'subdomain': subdomain,
        }
        if ip_address:
            data['ip_address'] = ip_address
        return self._retrieve_saml_assertion(url, data, version_id)

    def get_saml_assertion_verifying(self, app_id, device_id, state_token,
                                     otp_token=None, url_endpoint=None,
                                     do_not_notify=False):
        version_id = self._assertion_version()
        url = url_endpoint or (GET_SAML_VERIFY_FACTOR % (self._get_subdomain(), version_id))
        data = {
            'app_id': int(app_id),
            'device_id': str(device_id),
            'state_token': str(state_token),
            'do_not_notify': do_not_notify,
        }
        if otp_token:
            data['otp_token'] = otp_token
        return self._retrieve_saml_assertion(url, data, version_id)

    # -- MFA Devices ------------------------------------------------------

    def get_otp_devices(self, user_id):
        """Fetch the full OTP device list for a user from the devices endpoint.

        Returns a list of Device objects with richer metadata than the SAML
        assertion response provides (display name, active status, etc.).
        Returns an empty list on error, leaving self.error set.
        """
        self.clean_error()
        url = GET_OTP_DEVICES_URL % (self._get_subdomain(), user_id)
        response = requests.get(url, headers=self.get_authorized_headers(),
                                timeout=self.default_timeout)
        if response.status_code == 200:
            try:
                content = response.json()
            except ValueError:
                return []
            devices_data = content.get('data', {})
            if isinstance(devices_data, dict):
                otp_devices = devices_data.get('otp_devices', [])
            else:
                otp_devices = []
            return [Device(d) for d in otp_devices if d.get('active', True)]
        self.set_error(response)
        return []
