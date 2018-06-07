onelogin-python-aws-assume-role
===============================

Assume an AWS Role and get temporary credentials using Onelogin.

Users will be able to choose from among multiple AWS roles in multiple AWS accounts when they sign in using OneLogin in order to assume an AWS Role and obtain temporary AWS acccess credentials.

This is really useful for customers that run complex environments with multiple AWS accounts, roles and many different people that need periodic access as it saves manually generating and managing AWS credentials.

This repository contains a python script at [src/onelogin/aws-assume-role/aws-assume-role.py](https://github.com/onelogin/onelogin-python-aws-assume-role/blob/master/src/onelogin/aws-assume-role/aws-assume-role.py) that you can execute in order to retrieve the AWS credentials.

## AWS and OneLogin prerequisites

The "[Configuring SAML for Amazon Web Services (AWS) with Multiple Accounts and Roles](https://support.onelogin.com/hc/en-us/articles/212802926-Configuring-SAML-for-Amazon-Web-Services-AWS-with-Multiple-Accounts-and-Roles)" guide explains how to:
 - Add the AWS Multi Account app to OneLogin
 - Configure OneLogin as an Identity Provider for each AWS account
 - Add or update AWS Roles to use OneLogin as the SAML provider
 - Add external roles to give OneLogin access to your AWS accounts
 - Complete your AWS Multi Account configuration in OneLogin

## Installation
### Hosting

#### Github

The project is hosted at github. You can download it from:
* Lastest release: https://github.com/onelogin/onelogin-python-aws-assume-role/releases/latest
* Master repo: https://github.com/onelogin/onelogin-python-aws-assume-role/tree/master

#### Pypi

The toolkit is hosted in pypi, you can find the python-saml package at [https://pypi.python.org/pypi/onelogin-aws-assume-role](https://pypi.python.org/pypi/onelogin-aws-assume-role)

### Dependencies

It works with python2 and python3.

* boto3  AWS Python SDK
* onelogin  OneLogin Python SDK
* optparse-pretty  Pretty print the python script helper

## Getting started

### Virtualenv

The use of a virtualenv is highly recommended.

Virtualenv helps isolating the python enviroment used to run the toolkit. You can find more details and an installation guide in the [official documentation](http://virtualenv.readthedocs.org/en/latest/).

Once you have your virtualenv ready and loaded, then you can install the toolkit on it in development mode executing this:

```
python setup.py develop
```

Using this method of deployment the toolkit files will be linked instead of copied, so if you make changes on them you won't need to reinstall the toolkit.

If you want install it in a normal mode, execute:

```
python setup.py install
```

### Settings

The python script uses a settings file, where [OneLogin SDK properties](https://github.com/onelogin/onelogin-python-sdk#getting-started) are placed.

Is a json file named onelogin.sdk.json as follows
```json
{
	"client_id": "",
	"client_secret": "",
	"region": ""
}
```

Where:

 * client_id  Onelogin OAuth2 client ID
 * client_secret  Onelogin OAuth2 client secret
 * region  Indicates where the instance is hosted. Possible values: 'us' or 'eu'.

 Place that file in the same path where the python script is invoked.


### How the process works

#### Step 1. Provide OneLogin data.

- Provide OneLogin's username/mail and password to authenticate the user
- Provide the OneLogin's App ID to identify the AWS app
- Provide the domain of your OneLogin's instance.

_Note: If you're bored typing your
username (`--onelogin-username`),
App ID (`--onelogin-app-id`),
subdomain (`--onelogin-subdomain`) or
AWS region (`--aws-region`)
every time, you can specify these parameters as command-line arguments and
the tool won't ask for them any more._

With that data, a SAMLResponse is retrieved. And possible AWS Role are retrieved.

#### Step 2. Select AWS Role to be assumed.

- Provide the desired AWS Role to be assumed.
- Provide the AWS Region instance (required in order to execute the AWS API call).

#### Step 3. AWS Credentials retrieved.

A temporal AWS AccessKey and secretKey are retrieved in addition to a sessionToken.
Those data can be used to generate an AWS BasicSessionCredentials to be used in any AWS API SDK.


## Quick Start using the python scrypt

### Prepare the environment

After checking out the repository, let's use a [virtual environment](https://virtualenv.pypa.io)
```
cd <repository>
virtualenv venv
```

Activate then the environment

```sh
> source venv/bin/activate
```

Then run 

```sh
> pip setup install
```

or

```sh
> setup.py develop
```

to install dependencies.

### Usage

Assuming you have your AWS Multi Account app set up correctly and you’re using valid OneLogin API credentials stored on the onelogin.sdk.json placed at the root of the repository, using this tool is as simple as following the prompts.

```sh
> python src/onelogin/aws-assume-role/aws-assume-role.py
```

Or alternately save them to your AWS credentials file to enable faster access from any terminal.

```sh
> python src/onelogin/aws-assume-role/aws-assume-role.py --profile profilename
```

By default, the credentials only last for 1 hour, but you can [edit that restriction on AWS and set a max of 12h session duration](https://aws.amazon.com/es/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/).

You can also make it regenerate and update the credentials file by using the `--loop` option to specify the number of iterations, and --time to specify the minutes between iterations.

For more info execute:

```sh
> python src/onelogin/aws-assume-role/aws-assume-role.py --help
```

## Test your credentials with AWS CLI

AWS provide a CLI tool that makes remote access and management of resources super easy. If you don’t have it already then read more about it and install it from here.

For convenience you can simply copy and paste the temporary AWS access credentials generated above to set them as environment variables. This enables you to instantly use AWS CLI commands as the environment variables will take precedence over any credentials you may have in your *~/.aws* directory.

Assuming that:

 * you have the AWS CLI installed
 * you have set the OneLogin generated temporary AWS credentials as environment variables
 * the role you selected has access to list EC2 instances

You should find success with the following AWS CLI command.

```
aws ec2 describe-instances
```

## Development

After checking out the repo, run `pip setup install` or `python setup.py develop` to install dependencies.

To release a new version, update the version number in `src/onelogin/api/version.py` and commit it, then you will be able to update it to pypy.
with `python setup.py sdist upload` and `python setup.py bdist_wheel upload`.
Create also a relase tag on github.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/onelogin/onelogin-python-aws-assume-role. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the OneLogin Assume AWS Role project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/onelogin/onelogin-python-aws-assume-role/blob/master/CODE_OF_CONDUCT.md).
