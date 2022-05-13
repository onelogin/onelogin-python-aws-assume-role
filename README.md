onelogin-python-aws-assume-role
===============================

Assume an AWS Role and get temporary credentials using Onelogin.

Users will be able to choose from among multiple AWS roles in multiple AWS accounts when they sign in using OneLogin in order to assume an AWS Role and obtain temporary AWS access credentials.

This is really useful for customers that run complex environments with multiple AWS accounts, roles and many different people that need periodic access as it saves manually generating and managing AWS credentials.

This repository contains a python script at [src/aws_assume_role/aws_assume_role.py](https://github.com/onelogin/onelogin-python-aws-assume-role/blob/master/src/aws_assume_role/aws_assume_role.py) that you can execute using `onelogin-aws-assume-role` in order to retrieve the AWS credentials.

OneLogin's Smart MFA cannot be enforced with OneLogin's AWS CLI utility


## AWS and OneLogin prerequisites

The "[Configuring SAML for Amazon Web Services (AWS) with Multiple Accounts and Roles](https://onelogin.service-now.com/support?id=kb_article&sys_id=66a91d03db109700d5505eea4b9619a5)" guide explains how to:
 - Add the AWS Multi Account app to OneLogin
 - Configure OneLogin as an Identity Provider for each AWS account
 - Add or update AWS Roles to use OneLogin as the SAML provider
 - Add external roles to give OneLogin access to your AWS accounts
 - Complete your AWS Multi Account configuration in OneLogin

## Installation

### Hosting

#### Github

The project is hosted at github. You can download it from:
* Latest release: https://github.com/onelogin/onelogin-python-aws-assume-role/releases/latest
* Master repo: https://github.com/onelogin/onelogin-python-aws-assume-role/tree/master

#### Pypi

The toolkit is hosted in pypi, you can find the python-saml package at [https://pypi.python.org/pypi/onelogin-aws-assume-role](https://pypi.python.org/pypi/onelogin-aws-assume-role)

### Dependencies

It works with python2 and python3.

* boto3  AWS Python SDK
* onelogin  OneLogin Python SDK
* pyyaml  YAML parser
* lxml  XML and HTML processor

## Getting started

### Virtualenv

The use of a virtualenv is highly recommended.

Virtualenv helps isolating the python environment used to run the toolkit. You can find more details and an installation guide in the [official documentation](http://virtualenv.readthedocs.org/en/latest/).

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

Is a json file named `onelogin.sdk.json` as follows:

```json
{
  "client_id": "",
  "client_secret": "",
  "region": "",
  "ip": ""
}
```

Where:

 * client_id  Onelogin OAuth2 client ID
 * client_secret  Onelogin OAuth2 client secret
 * region  Indicates where the instance is hosted. Possible values: 'us' or 'eu'.
 * ip  Indicates the IP to be used on the method to retrieve the SAMLResponse in order to bypass MFA if that IP was previously whitelisted.

For security reasons, IP only can be provided in `onelogin.sdk.json`.
On a shared machine where multiple users has access, That file should only be readable by the root of the machine that also controls the
client_id / client_secret, and not by an end user, to prevent him manipulate the IP value.

Place the file in the `~/.onelogin` directory or in the same path where the python script is invoked or provide the path with the -c option.


There is an optional file `onelogin.aws.json`, that can be used if you plan to execute the script with some fixed values and avoid providing it on the command line each time.

```json
{
  "app_id": "123456",
  "subdomain": "myolsubdomain",
  "username": "user.name",
  "profile": "profile-1",
  "duration": 3600,
  "aws_region": "us-west-2",
  "aws_account_id": "",
  "aws_role_name": "",
  "profiles": {
    "profile-1": {
      "aws_account_id": "",
      "aws_role_name": "",
      "aws_region": "",
      "app_id": ""
    },
    "profile-2": {
      "aws_account_id": ""
    }
  }
}
```

Where:

 * app_id Onelogin AWS integration app id
 * subdomain Needs to be set to the correct subdomain for your AWS integration
 * username The email address that is used to authenticate against Onelogin
 * profile The AWS profile to use in ~/.aws/credentials
 * duration Desired AWS Credential Duration in seconds. Default: 3600, Min: 900, Max: 43200
 * aws_region AWS region to use
 * aws_account_id AWS account id to be used
 * aws_role_name AWS role name to select
 * profiles Contains a list of profile->account id, and optionally role name mappings. If this attribute is populated `aws_account_id`, `aws_role_name`, `aws_region`, and `app_id` will be set based on the `profile` provided when running the script.

**Note**: The values provided on the command line will take precedence over the values defined on this file and, values defined at the _global_ scope in the file, will take precedence over values defined at the `profiles` level. IN addition, each attribute is treating individually, so be aware that this may lead to somewhat strange behaviour when overriding a subset of parameters, when others are defined at a _lower level_ and not overridden. For example, if you had a `onelogin.aws.json` config file as follows:

```json
{
  ...
  "aws_region": "eu-east-1",
  "profiles": {
    "my-account": {
      "aws_account_id": "11111111",
      "aws_role_name": "Administrator"
    }
  }
}
````

And, you you subsequently ran the application with the command line arguments `--profile my-account --aws-account-id 22222222` then the application would ultimately attempt to log in with the role `Administrator` on account `22222222`, with region set to `eu-east-1` and, if successful, save the credentials to profile `my-account`.

In addition, there is another optional file that can be created to give more human readable names to the account list, named `accounts.yaml`, which should be placed in the same path where the python script is invoked:

```yaml
accounts:
  "987654321012": Prod account
  "123456789012": Dev Account
```

This isn't needed for the script to function but it provides a better user experience.

### Docker installation method

* `git clone git@github.com:onelogin/onelogin-python-aws-assume-role.git`
* `cd onelogin-python-aws-assume-role`
* Enter your credentials in the `onelogin.sdk.json` file as explained above
* Save the `onelogin.sdk.json` file in the root directory of the repo
* `docker build . -t awsaccess:latest`
* `docker run -it -v ~/.aws:/root/.aws awsaccess:latest onelogin-aws-assume-role --onelogin-username {user_email} --onelogin-subdomain {subdomain} --onelogin-app-id {app_id} --aws-region {aws region} --profile default`

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

You can specify 
OTP Code (`--otp`)
and the cli will use this otp only for the first interaction
requiring a manual OTP Code

_Note: Specifying your password directly with `--onelogin-password` is bad practice,
you should use that flag together with password managers, eg. with the OSX Keychain:
`--onelogin-password $(security find-generic-password -a $USER -s onelogin -w)`,
so your password won't be saved in you command line history.
Please note that your password **will** be visible in your process list,
if you use this flag (as the expanded command line arguments are part of the name of the process)._

With that data, a SAMLResponse is retrieved. And possible AWS Role are retrieved.

#### Step 2. Select AWS Role to be assumed.

- Provide the desired AWS Role to be assumed.
- Provide the AWS Region instance (required in order to execute the AWS API call).

#### Step 3. AWS Credentials retrieved.

A temporal AWS AccessKey and secretKey are retrieved in addition to a sessionToken.
Those data can be used to generate an AWS BasicSessionCredentials to be used in any AWS API SDK.


## Quick Start using the python script

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
> python setup.py install
```

or

```sh
> python setup.py develop
```

to install dependencies.

### Usage

Assuming you have your AWS Multi Account app set up correctly and you’re using valid OneLogin API credentials stored on the `onelogin.sdk.json` placed at the root of the repository, using this tool is as simple as following the prompts.

```sh
> onelogin-aws-assume-role
```

Or alternately save them to your AWS credentials file to enable faster access from any terminal.

```sh
> onelogin-aws-assume-role --profile profilename
```

By default, the credentials only last for 1 hour, but you can [edit that restriction on AWS and set a max of 12h session duration](https://aws.amazon.com/es/blogs/security/enable-federated-api-access-to-your-aws-resources-for-up-to-12-hours-using-iam-roles/).

Then set the `-z` or `duration` with the desired credentials session duration. The possible value to be used is limited by the AWS Role. Read more at https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session

You can also make it regenerate and update the credentials file by using the `--loop` option to specify the number of iterations, and `--time` to specify the minutes between iterations. If you specified a duration, be sure the value you set for the duration session of the credential is bigger than the value you set for the time, so your credentials will be renewed before expiration.

You can provide an specific path where locate the settings file by providing the `-c` or `--config-file-path` option.

You can also make it interactive, with the `-x` or `--interactive` option, and at the end of the iteration, you will be asked if want to generate new credentials for a new user or a new role.

The selection of the AWS account and Role can be also be done with the `--aws-account-id` and `--aws-role-name` parameters. If both parameters are set then both will be matched against the list of available accounts and roles. If only `--aws-account-id` is specified and you only have one available role in that account, then that role will be chosen by default. If you have more than one role in the given account then you will need to select the appropriate one as per normal.

If you plan to execute the script several times over different Accounts/Roles of the user and you want to cache the SAMLResponse, set the `--cache-saml` option

By default in order to select Account/Role, the list will be ordered by account ids. Enable the `--role_order` option to list by role name instead.

For more info execute:

```sh
> onelogin-aws-assume-role --help
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

To release a new version, update the version number in `src/onelogin/api/version.py` and commit it, then you will be able to update it to pypi.
with `python setup.py sdist upload` and `python setup.py bdist_wheel upload`.
Create also a release tag on github.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/onelogin/onelogin-python-aws-assume-role. This project is intended to be a safe, welcoming space for collaboration, and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).

## Code of Conduct

Everyone interacting in the OneLogin Assume AWS Role project’s codebases, issue trackers, chat rooms and mailing lists is expected to follow the [code of conduct](https://github.com/onelogin/onelogin-python-aws-assume-role/blob/master/CODE_OF_CONDUCT.md).
