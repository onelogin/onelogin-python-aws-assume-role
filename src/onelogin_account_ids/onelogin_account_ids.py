from prettytable import PrettyTable

from aws_assume_role.aws_assume_role import get_options, get_client


def generate_apps_table(apps):
    """
    Given a list of OneLoginApps(s) an indexed PrettyTable is generated
    with the index, ID and OneLogin app name
    Args:
        apps: list of OneLoginApp(s)

    Returns:
        PrettyTable of format: index, ID, app name

    """
    apps_table = PrettyTable()
    apps_table.field_names = ["No.", "ID", "App Name", "Is Compatible"]
    for index, app in enumerate(apps):
        apps_table.add_row([index, app.id, app.name, app.is_compatible])
    return apps_table


def is_aws_account(detailed_app_info):
    """
    Identifies whether a one login app is an AWS account
    Args:
        detailed_app_info: OneLoginApp - returned from client.get_app(app.id) call,
        which returns more fields than when the list of apps is called

    Returns:
        boolean - True if OneLogin app is identified as an AWS App, False if not indicators,
        that this is an AWS app.
    """
    is_aws = False
    is_compatible = True
    if detailed_app_info.parameters:
        if saml_user_name := detailed_app_info.parameters.get("saml_username", {}).get("label"):
            if saml_user_name == "Amazon Username":
                is_aws = True
    if detailed_app_info.configuration:
        if app_config_audience := detailed_app_info.configuration.get("audience", ""):
            if "signin.aws.amazon.com" in app_config_audience:
                is_aws = True
                is_compatible = False
    return {"is_aws": is_aws, "is_compatible": is_compatible}


def get_aws_apps(apps, client):
    """
    Given a list of OneLoginApps(s) and client
    a list of AWS apps is returned and whether they are compatible with the tool
    Args:
        apps: list of OneLoginApp(s)
        client:  OneLoginClient object

    Returns:
        List of OneLoginApp(s) with additional "is_compatible" field included on the object
    """
    aws_only_apps = []
    for app in apps:
        detailed_app_info = client.get_app(app.id)  # Gets configuration settings of an app
        is_aws = is_aws_account(detailed_app_info)
        if is_aws["is_aws"]:
            """
            Control tower accounts are not compatible - 
            No authentication method from SSO that returns you a list of accounts / roles (like a SAML 
            auth request done to a vanilla AWS account). Work around is to add the underlying account 
            to Control Tower
            """
            app.is_compatible = is_aws["is_compatible"]
            aws_only_apps.append(app)
    return aws_only_apps


def main():
    """
    Prints out a list of all AWS account (apps) within OneLogin
    Returns:

    """
    print("============================================================================")
    print("OneLogin - Log In Tool")
    print("Non compatible (column 4) AWS accounts can not be logged in from this tool\n")
    print("============================================================================")

    options = get_options()
    client = get_client(options)
    client.get_access_token()  # verifies provided credentials are OK

    print("All OneLogin App IDs:")
    apps = client.get_apps()  # Gets all apps in OneLogin account (without configuration)
    if apps is not None:
        aws_only_apps = get_aws_apps(apps, client)
        app_table = generate_apps_table(aws_only_apps)
        print(app_table)
    else:
        print("There are no apps or your permissions are preventing access")


if __name__ == '__main__':
    main()
