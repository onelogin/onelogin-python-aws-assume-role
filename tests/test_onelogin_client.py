#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for the requests-based OneLogin client compatibility layer.

These exercise the response-parsing shim (ported from onelogin 2.0.4) against
the documented SAML-assertion response shapes, plus the URL/version/header
helpers. The live token + SAML round-trip is validated manually before release
(it needs a configured OneLogin <-> AWS connector).
"""

import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_assume_role import onelogin_client  # noqa: E402
from aws_assume_role.onelogin_client import (  # noqa: E402
    OneLoginClient,
    SAMLEndpointResponse,
    MFA,
    Device,
    handle_saml_endpoint_response,
    extract_error_message,
)


def _fake_response(status_code, json_body):
    resp = mock.Mock()
    resp.status_code = status_code
    resp.json.return_value = json_body
    return resp


class HandleSamlEndpointResponseV1Test(unittest.TestCase):
    def test_success_returns_saml_response(self):
        content = {
            'status': {'type': 'success', 'message': 'Success', 'error': False, 'code': 200},
            'data': 'PHNhbWxQUkVTUE9OU0U+',
        }
        resp = handle_saml_endpoint_response(content, 1)
        self.assertIsInstance(resp, SAMLEndpointResponse)
        self.assertEqual(resp.type, 'success')
        self.assertEqual(resp.message, 'Success')
        self.assertEqual(resp.saml_response, 'PHNhbWxQUkVTUE9OU0U+')
        self.assertIsNone(resp.mfa)

    def test_mfa_required_parses_devices_and_state_token(self):
        content = {
            'status': {'type': 'success', 'message': 'MFA is required', 'error': False, 'code': 200},
            'data': [{
                'state_token': 'state-123',
                'callback_url': 'https://api.us.onelogin.com/cb',
                'devices': [
                    {'device_id': 111, 'device_type': 'OneLogin Protect'},
                    {'device_id': 222, 'device_type': 'OneLogin SMS'},
                ],
            }],
        }
        resp = handle_saml_endpoint_response(content, 1)
        self.assertEqual(resp.type, 'success')
        self.assertIsNone(resp.saml_response)
        self.assertIsInstance(resp.mfa, MFA)
        self.assertEqual(resp.mfa.state_token, 'state-123')
        self.assertEqual(len(resp.mfa.devices), 2)
        self.assertEqual(resp.mfa.devices[0].id, 111)
        self.assertEqual(resp.mfa.devices[0].type, 'OneLogin Protect')

    def test_malformed_body_returns_none(self):
        self.assertIsNone(handle_saml_endpoint_response({}, 1))
        self.assertIsNone(handle_saml_endpoint_response(None, 1))


class HandleSamlEndpointResponseV2Test(unittest.TestCase):
    def test_success(self):
        content = {'message': 'Success', 'data': 'PHNhbWw+'}
        resp = handle_saml_endpoint_response(content, 2)
        self.assertEqual(resp.type, 'success')
        self.assertEqual(resp.saml_response, 'PHNhbWw+')

    def test_mfa_required(self):
        content = {
            'message': 'MFA is required',
            'state_token': 'state-xyz',
            'devices': [{'device_id': 9, 'device_type': 'OneLogin Protect'}],
        }
        resp = handle_saml_endpoint_response(content, 2)
        self.assertEqual(resp.type, 'success')
        self.assertIsInstance(resp.mfa, MFA)
        self.assertEqual(resp.mfa.state_token, 'state-xyz')
        self.assertEqual(resp.mfa.devices[0].id, 9)

    def test_pending(self):
        content = {'message': 'Authentication pending on OL Protect'}
        resp = handle_saml_endpoint_response(content, 2)
        self.assertEqual(resp.type, 'pending')


class ExtractErrorMessageTest(unittest.TestCase):
    def test_nested_description(self):
        content = {'status': {'message': {'description': 'App not found'}}}
        self.assertEqual(extract_error_message(content), 'App not found')

    def test_plain_message(self):
        content = {'status': {'message': 'Invalid subdomain'}}
        self.assertEqual(extract_error_message(content), 'Invalid subdomain')

    def test_type_fallback(self):
        content = {'status': {'type': 'bad request'}}
        self.assertEqual(extract_error_message(content), 'bad request')

    def test_empty(self):
        self.assertEqual(extract_error_message({}), '')
        self.assertEqual(extract_error_message(None), '')


class DeviceTest(unittest.TestCase):
    def test_api_style_keys(self):
        d = Device({'device_id': 5, 'device_type': 'OneLogin SMS'})
        self.assertEqual(d.id, 5)
        self.assertEqual(d.type, 'OneLogin SMS')

    def test_legacy_style_keys(self):
        d = Device({'id': 7, 'type': 'OneLogin Protect'})
        self.assertEqual(d.id, 7)
        self.assertEqual(d.type, 'OneLogin Protect')


class OneLoginClientHelpersTest(unittest.TestCase):
    def test_subdomain_from_region(self):
        client = OneLoginClient('id', 'secret', region='eu')
        self.assertEqual(client._get_subdomain(), 'api.eu')

    def test_custom_subdomain_wins(self):
        client = OneLoginClient('id', 'secret', region='us', subdomain='acme')
        self.assertEqual(client._get_subdomain(), 'acme')

    def test_region_defaults_to_us(self):
        client = OneLoginClient('id', 'secret', region=None)
        self.assertEqual(client._get_subdomain(), 'api.us')

    def test_assertion_version_default_is_last(self):
        client = OneLoginClient('id', 'secret')
        self.assertEqual(client._assertion_version(), 2)

    def test_assertion_version_honors_configuration(self):
        client = OneLoginClient('id', 'secret')
        client.api_configuration['assertion'] = 1
        self.assertEqual(client._assertion_version(), 1)

    def test_assertion_version_rejects_out_of_range(self):
        client = OneLoginClient('id', 'secret')
        client.api_configuration['assertion'] = 9
        self.assertEqual(client._assertion_version(), 2)

    def test_token_header_format(self):
        client = OneLoginClient('the-id', 'the-secret')
        headers = client.get_authorized_headers(bearer=False)
        self.assertEqual(headers['Authorization'],
                         'client_id:the-id, client_secret:the-secret')

    def test_bearer_header_format(self):
        client = OneLoginClient('id', 'secret')
        client.access_token = 'tok-123'
        headers = client.get_authorized_headers(bearer=True)
        self.assertEqual(headers['Authorization'], 'bearer tok-123')


class RequestConstructionTest(unittest.TestCase):
    @mock.patch.object(onelogin_client.requests, 'post')
    def test_get_access_token_request(self, post):
        post.return_value = _fake_response(200, {
            'access_token': 'tok', 'refresh_token': 'ref', 'expires_in': 36000,
        })
        client = OneLoginClient('cid', 'csecret', region='us')
        client.get_access_token()

        url = post.call_args[0][0]
        headers = post.call_args[1]['headers']
        body = post.call_args[1]['json']
        self.assertEqual(url, 'https://api.us.onelogin.com/auth/oauth2/v2/token')
        self.assertEqual(headers['Authorization'], 'client_id:cid, client_secret:csecret')
        self.assertEqual(body, {'grant_type': 'client_credentials'})
        self.assertEqual(client.access_token, 'tok')
        self.assertIsNone(client.error)

    @mock.patch.object(onelogin_client.requests, 'post')
    def test_get_access_token_error(self, post):
        post.return_value = _fake_response(401, {
            'status': {'message': 'Authentication Failed', 'error': True, 'code': 401},
        })
        client = OneLoginClient('cid', 'csecret')
        client.get_access_token()
        self.assertIsNone(client.access_token)
        self.assertEqual(client.error, '401')
        self.assertEqual(client.error_description, 'Authentication Failed')

    @mock.patch.object(onelogin_client.requests, 'post')
    def test_get_saml_assertion_request(self, post):
        post.return_value = _fake_response(200, {
            'status': {'type': 'success', 'message': 'Success', 'error': False, 'code': 200},
            'data': 'PHNhbWw+',
        })
        client = OneLoginClient('cid', 'csecret', region='eu')
        client.access_token = 'bearer-tok'
        client.api_configuration['assertion'] = 1
        resp = client.get_saml_assertion('user@x.com', 'pw', 12345, 'acme', ip_address='9.9.9.9')

        url = post.call_args[0][0]
        headers = post.call_args[1]['headers']
        body = post.call_args[1]['json']
        self.assertEqual(url, 'https://api.eu.onelogin.com/api/1/saml_assertion')
        self.assertEqual(headers['Authorization'], 'bearer bearer-tok')
        self.assertEqual(body, {
            'username_or_email': 'user@x.com', 'password': 'pw',
            'app_id': 12345, 'subdomain': 'acme', 'ip_address': '9.9.9.9',
        })
        self.assertEqual(resp.saml_response, 'PHNhbWw+')

    @mock.patch.object(onelogin_client.requests, 'post')
    def test_verify_factor_request(self, post):
        post.return_value = _fake_response(200, {
            'status': {'type': 'success', 'message': 'Success', 'error': False, 'code': 200},
            'data': 'PHNhbWw+',
        })
        client = OneLoginClient('cid', 'csecret')
        client.access_token = 'bearer-tok'
        client.api_configuration['assertion'] = 1
        client.get_saml_assertion_verifying('12345', '678', 'state-tok',
                                            otp_token='999999', do_not_notify=True)

        url = post.call_args[0][0]
        body = post.call_args[1]['json']
        self.assertEqual(url, 'https://api.us.onelogin.com/api/1/saml_assertion/verify_factor')
        self.assertEqual(body, {
            'app_id': 12345, 'device_id': '678', 'state_token': 'state-tok',
            'do_not_notify': True, 'otp_token': '999999',
        })


if __name__ == '__main__':
    unittest.main()
