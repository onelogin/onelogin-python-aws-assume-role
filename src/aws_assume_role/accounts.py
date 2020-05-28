#
# Display Account Aliases
#
# Handles displaying a 'pretty' AWS account alias based on yaml config file provided by the user
# Currently the onelogin saml does not support pulling the acct alias dynamically with the role names

import yaml
import os

def get_account_aliases_info():
    account_aliases = []
    if os.path.isfile('accounts.yaml'):
        accountsfile = open('accounts.yaml').read()
        account_aliases = yaml.load(accountsfile, Loader=yaml.FullLoader)
    return account_aliases


def identify_known_accounts(account_aliases, account_id):
    """
    Given a known list of account IDs from yaml config, append note about their account if they're known to us.
    :return: Account description
    """
    # If the accounts custom aliases yaml file does not exist just default to normal behavior
    if account_aliases:
        if 'accounts' in account_aliases.keys():
            accounts = account_aliases["accounts"]
            for acct in accounts.keys():
                if acct == account_id:
                    return accounts[acct]
        return "Unidentified"
    else:
        return ""


def pretty_choices(index, role_name, account_id, account_aliases=[]):
    """
    Formats the output of the account option
    :return: formatted print
    """
    account_alias = identify_known_accounts(account_aliases, account_id)
    if account_alias:
        print(" %s | %s (Account: %s - %s)" % (index, role_name, account_id, account_alias))
    else:
        print(" %s | %s (Account %s)" % (index, role_name, account_id))

def process_account_and_role_choices(roles_by_account):
    new_roles_by_account = {}
    index = 0
    if roles_by_account:
        account_aliases = get_account_aliases_info()
        for account_id, role_names in sorted(roles_by_account.items()):
            new_roles_by_account[account_id] = []
            for role_name in sorted(role_names):
                new_roles_by_account[account_id].append((index, role_name))
                pretty_choices(index, role_name, account_id, account_aliases)
                index = index + 1
    return new_roles_by_account

    