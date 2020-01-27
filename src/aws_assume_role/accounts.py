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
    if os.path.isfile('accounts.yaml'):
        accountsfile = open('accounts.yaml').read()
        contents = yaml.load(accountsfile, Loader=yaml.FullLoader)
        if 'accounts' in contents.keys():
            accounts = contents["accounts"]
            for acct in accounts.keys():
                if acct == data:
                    return accounts[acct]
        return "Unidentified"
    else:
        return ""

def pretty_choices(index, role_name, account_id):
    """
    Formats the output of the account option
    :return: formatted print
    """
    account_alias = identify_known_accounts(account_id)
    if account_alias:
        print(" %s | %s (Account: %s - %s)"  % (index, role_name, account_id, account_alias))
    else:
        print(" %s | %s (Account %s)" % (index, role_name, account_id))
