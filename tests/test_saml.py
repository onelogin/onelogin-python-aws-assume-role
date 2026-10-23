#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""Unit tests for reading the SAMLResponse: the AWS roles and the expiry check."""

import base64
import os
import pathlib
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from aws_assume_role import saml  # noqa: E402

ROLE_ATTRIBUTE = 'https://aws.amazon.com/SAML/Attributes/Role'
ROLE = 'arn:aws:iam::111111111111:role/Admin,arn:aws:iam::111111111111:saml-provider/OneLogin'


def _saml_xml(role_value, doctype=''):
    now = datetime.utcnow()
    return (
        '%s<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion>'
        '<saml:Conditions NotBefore="%s" NotOnOrAfter="%s"/><saml:AttributeStatement>'
        '<saml:Attribute Name="%s"><saml:AttributeValue>%s</saml:AttributeValue></saml:Attribute>'
        '</saml:AttributeStatement></saml:Assertion></samlp:Response>'
    ) % (doctype, (now - timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ'),
         (now + timedelta(minutes=5)).strftime('%Y-%m-%dT%H:%M:%SZ'), ROLE_ATTRIBUTE, role_value)


def _get_attributes(saml_xml):
    return saml.get_attributes(base64.b64encode(saml_xml.encode('utf-8')))


class GetAttributesTest(unittest.TestCase):
    def test_reads_the_roles(self):
        self.assertEqual(_get_attributes(_saml_xml(ROLE)), {ROLE_ATTRIBUTE: [ROLE]})

    def test_does_not_read_local_files_through_external_entities(self):
        # lxml < 5 resolves external entities by default (XXE)
        tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp_dir)
        secret = pathlib.Path(tmp_dir, 'secret.txt')
        secret.write_text('secret-from-disk')
        doctype = '<!DOCTYPE samlp:Response [<!ENTITY x SYSTEM "%s">]>' % secret.as_uri()

        attributes = _get_attributes(_saml_xml('&x;', doctype))

        self.assertNotIn('secret-from-disk', repr(attributes))

    def test_does_not_expand_entities(self):
        # Nested entities can expand into a huge document
        doctype = '<!DOCTYPE samlp:Response [<!ENTITY x "%s">]>' % ROLE

        self.assertNotIn(ROLE, _get_attributes(_saml_xml('&x;', doctype))[ROLE_ATTRIBUTE])


class IsValidSamlAssertionTest(unittest.TestCase):
    def test_current_assertion_is_valid(self):
        self.assertTrue(saml.is_valid_saml_assertion(_saml_xml(ROLE).encode('utf-8')))


if __name__ == '__main__':
    unittest.main()
