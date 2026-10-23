"""
Reads the AWS roles from a SAMLResponse, checks whether it has expired, and
caches it for --cache-saml.
"""

import base64
import json
import os

from datetime import datetime
from lxml import etree as ET


DEFAULT_AWS_DIR = os.path.expanduser('~/.aws')
SAML_CACHE_PATH = os.path.join(DEFAULT_AWS_DIR, 'saml_cache.txt')


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
