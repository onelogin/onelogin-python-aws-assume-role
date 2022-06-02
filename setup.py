
#! /usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, OneLogin, Inc.
# All rights reserved.

from setuptools import setup


version = {}
with open("src/aws_assume_role/version.py") as fp:
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
    url='https://github.com/onelogin/onelogin-python-aws-assume-role',
    packages=[
        'aws_assume_role'
    ],
    package_dir={
        '': 'src',
    },
    package_data={'': ['accounts.yaml','onelogin.sdk.json']},
    install_requires=[
        'boto3>=1.7.84',
        'onelogin>=2.0.3',
        'pyyaml>=5.1.2',
        'lxml'
    ],
    entry_points={
        'console_scripts': ['onelogin-aws-assume-role=aws_assume_role.aws_assume_role:main']
    },
    test_suite='tests',
    extras_require={
        'test': (
            'coverage>=3,<6',
            'pylint>=1,<3',
            'pep8>=1,<2',
            'pyflakes>=1,<3',
        ),
    },
    keywords='onelogin aws-assume-role',)
