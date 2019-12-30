#
# Display Account Aliases
#
# Handles displaying a 'pretty' AWS account alias based on yaml config file provided by the user
# Currently the onelogin saml does not support pulling the acct alias dynamically with the role names

import yaml
import os

def identify_known_accounts(data):
    """
    Given a known list of account IDs from yaml config, append note about their account if they're known to us.
    :return: Account description
    """
    # If the accounts custom aliases yaml file does not exist just default to normal behavior
    try:
        if os.path.isfile('accounts.yaml'):
            accountsfile = open('onelogin.sdk.json').read()
            contents = yaml.load(accountsfile, Loader=yaml.FullLoader)
            accounts = contents["accounts"]
            for acct in accounts.keys():
                if acct in data:
                    return accounts[acct]
            return "Unidentified"

    except FileNotFoundError:
        return ""
    except yaml.YAMLError:
        print("ERROR: Your YAML configuration for the 'accounts.yaml' seems to be formatted incorrectly. \
                             Please double check.  Defaulting to not display account aliases.")
        return ""


def pretty_choices(index, role_name, account_id):
    """
    Formats the output of the account option
    :return: formatted print
    """
    account_alias = identify_known_accounts(account_id)
    if account_alias:
        print(f" {index} | {account_alias} - {role_name} (Account: {account_id})")
    else:
        print(" %s | %s (Account %s)" % (index, role_name, account_id))
