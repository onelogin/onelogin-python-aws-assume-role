#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, OneLogin, Inc.
# All rights reserved.

from setuptools import setup


version = {}
with open("src/onelogin/aws-assume-role/version.py") as fp:
    exec(fp.read(), version)

setup(
    name='onelogin-aws-assume-role',
    version=version['__version__'],
    description="Assume an AWS Role and get temporary credentials using OneLogin",
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],
    author='OneLogin',
    author_email='support@onelogin.com',
    license='MIT',
    url='https://github.com/onelogin/onelogin-python-aws-cli-assume-role',
    packages=[
        'onelogin/aws-assume-role'
    ],
    package_dir={
        '': 'src',
    },
    install_requires=[
        'boto3==1.7.84',
        'onelogin==1.5.0'
    ],
    test_suite='tests',
    extras_require={
        'test': (
            'coverage==3.7.1',
            'pylint==1.3.1',
            'pep8==1.5.7',
            'pyflakes==0.8.1',
            'coveralls==0.4.4',
        ),
    },
    keywords='onelogin aws-assume-role',)
