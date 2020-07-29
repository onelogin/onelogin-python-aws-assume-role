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


def pretty_choices(index, role_name, account_id, account_aliases=[], mark=""):
    """
    Formats the output of the account option
    :return: formatted print
    """
    account_alias = identify_known_accounts(account_aliases, account_id)
    if account_alias:
        print(" %s | %s (Account: %s - %s)%s" % (index, role_name, account_id, account_alias, mark))
    else:
        print(" %s | %s (Account %s)%s" % (index, role_name, account_id, mark))

def process_account_and_role_choices(info_indexed_by_account, info_indexed_by_roles, options):
    role_option = None
    selection_info = []
    index = 0
    if info_indexed_by_account:
        account_aliases = get_account_aliases_info()
        # Order by role name
        if len(info_indexed_by_roles) > 0:
            for role_name, account_ids in sorted(info_indexed_by_roles.items()):                
                for account_id, role_string in sorted(account_ids.items()):
                    selection_info.append(role_string)
                    mark, found = check_info(account_id, role_name, options.aws_account_id, options.aws_role_name)
                    if found:
                        role_option = index
                    pretty_choices(index, role_name, account_id, account_aliases, mark)
                    index = index + 1
        else:
            for account_id, role_names in sorted(info_indexed_by_account.items()):
                for role_name, role_string in sorted(role_names.items()):
                    selection_info.append(role_string)
                    mark, found = check_info(account_id, role_name, options.aws_account_id, options.aws_role_name)
                    if found:
                        role_option = index
                    pretty_choices(index, role_name, account_id, account_aliases, mark)
                    index = index + 1

    return selection_info, role_option

def check_info(account_id, role_name, config_account_id, config_role_name):
    mark = ""
    found = False
    if account_id == config_account_id and role_name == config_role_name:
        mark = " **"
        found = True
    elif account_id == config_account_id:
            mark = " *"
    elif role_name == config_role_name:
            mark = " *"
    return mark, found



    