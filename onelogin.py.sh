#!/usr/bin/env bash

# This script will setup and execute the onelogin-aws-assume-role tool.
# It will create a virtual environment in the repo directory and install the tool.
# It will also create a config directory in ~/.onelogin and create the config files.


ADDED_ARGS="--role_order"

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
CONFIG_DIR=~/.onelogin
CONFIG_ENVS_FILE="${CONFIG_DIR}"/envs.sh
ONELOGIN_AWS_JSON="${CONFIG_DIR}"/onelogin.aws.json
ONELOGIN_SDK_JSON="${CONFIG_DIR}"/onelogin.sdk.json
ACCOUNTS_YAML="${CONFIG_DIR}"/accounts.yaml

if [ ! -d "${CONFIG_DIR}" ]; then
    echo "Directory ${CONFIG_DIR} does not exist, creating it."
    mkdir -p "${CONFIG_DIR}"
fi

if [ ! -f "$CONFIG_ENVS_FILE" ]; then
    echo "File $CONFIG_ENVS_FILE does not exist, creating it."
    touch "${CONFIG_ENVS_FILE}"
fi

source "${CONFIG_ENVS_FILE}"

if [ "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}" == "" ]; then
    echo "ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR is not set in ${CONFIG_ENVS_FILE}"
    echo "Checking $SCRIPT_DIR for the repo."
    if [ -d "${SCRIPT_DIR}/src/aws_assume_role" ]; then
        ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR="${SCRIPT_DIR}"
    fi
fi

if [ "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}" == "" ]; then
    echo 'What is the path of the "onelogin-python-aws-assume-role" repo?'
    read -r -p "Enter the directory: " ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR
    export ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR
fi

# NOTE: The usage of python here for this one-liner is absolutely shameful.  BUT...
#       I can not get `realpath` or `readlink` to work on MacOS.
#       I have tried.
#       I have failed.
ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR=$(python3 -c 'import os, sys; print(os.path.realpath(os.path.expanduser(sys.argv[1])))' "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}")

if [ ! -d "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}"/src/aws_assume_role ]; then
    echo "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR} does not appear to be the correct repo."
    echo "You may need to clone the repo from https://github.com/onelogin/onelogin-python-aws-assume-role"
    echo
    echo '    #cd <where ever you want to clone the repo>'
    echo "    git clone git@github.com:onelogin/onelogin-python-aws-assume-role.git"
    echo
    echo "If ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR is incorrectly set in ${CONFIG_ENVS_FILE} you will need to correct it."
    echo "Exiting."
    exit 1
fi

grep 'ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR' "${CONFIG_ENVS_FILE}" || echo "export ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR=${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}" >> "${CONFIG_ENVS_FILE}"

pushd "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}"

if [ ! -d "${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}"/venv ]; then
    echo "Creating virtual environment in ${ONELOGIN_PYTHON_AWS_ASSUME_ROLE_DIR}/venv"
    python3 -m venv ./venv
fi

# NOTE: This sets ${VIRTUAL_ENV}
source ./venv/bin/activate

if [ ! -f "${VIRTUAL_ENV}"/bin/onelogin-aws-assume-role ]; then
    echo "Installing onelogin-aws-assume-role"
    python3 setup.py install
fi

echo "Setting up config dir ${CONFIG_DIR}"

CREATED_CONFIG_FILES=N

if [ ! -f "$ONELOGIN_AWS_JSON" ]; then
    echo "File $ONELOGIN_AWS_JSON does not exist, creating it."
    CREATED_CONFIG_FILES=Y
    cat >> "${ONELOGIN_AWS_JSON}" << 'END'
{
    "app_id": "",
    "subdomain": "",
    "username": "",
    "duration": 43199,
    "aws_region": ""
}
END
fi

if [ ! -f "$ONELOGIN_SDK_JSON" ]; then
    echo "File $ONELOGIN_SDK_JSON does not exist, creating it."
    CREATED_CONFIG_FILES=Y
    cat >> "${ONELOGIN_SDK_JSON}" << 'END'
{
    "client_id": "",
    "client_secret": "",
    "region": "",
    "ip": ""
}
END
fi

if [ ! -f "$ACCOUNTS_YAML" ]; then
    CREATED_CONFIG_FILES=Y
    echo "File $ACCOUNTS_YAML does not exist, creating it."
    cp ./accounts.yaml.template "${ACCOUNTS_YAML}"
fi

if [ "${CREATED_CONFIG_FILES}" == "Y" ]; then
    echo "You will need to edit the files in ${CONFIG_DIR} to add your info.  Check with a team member for the correct values."
    echo "Exiting."
    exit 1
fi

AWS_PROFILE=${1:-${AWS_PROFILE}}
if [ -z "${AWS_PROFILE}" ]; then
    echo "You could have specified and AWS_PROFILE fy exporting the variable 'AWS_PROFILE' or by passing it as the first argument to this script."
    read -r -p "Enter the profile name: " AWS_PROFILE
    export AWS_PROFILE
fi
ADDED_ARGS="${ADDED_ARGS} --profile=${AWS_PROFILE}"

####################################
# Actually run the onelogin script #
####################################
CMD="${VIRTUAL_ENV}"/bin/onelogin-aws-assume-role ${ADDED_ARGS}
echo "Running: ${CMD}"
${CMD}

# Cleanup
deactivate
popd
