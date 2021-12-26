"""Library that contains shared authentication/authorization for Lambda function"""
from cloudx_sls_authorization import token_validation
from cloudx_sls_authorization import group_membership


def authorize_lambda_request(event: dict, tenant_id: str, app_id: [], allowed_roles: [],
                             ldap_server: str, ldap_username: str, ldap_password: str,
                             ldap_search_base: str, object_class: str, group_names: [],
                             lookup_attribute: str):
    """
    Verifies token signature and returns token information.

    Params:
        alb_event: the Lambda event from an ALB
        tenant_id: Azure AD tenant ID
        app_id: App ID that issued token
        allowed_roles: Roles required ot be present in OAuth token
        ldap_server: the ldap server, e.g., abc.def.com:1234
        ldap_username: the ldap user to query permissions
        ldap_password: the password for ldap_username
        ldap_search_base: the location of the user in LDAP
        object_class: the LDAP object class of the user
        group_names: the list of group names to check for user membership
        lookup_attribute: the attribute used to lookup the object

    Returns:
        bool: is request allowed
    """
    # Validate token
    if "Authorization" in event['headers'].keys():
        auth_token = event['headers']['Authorization']
    elif "authorization" in event['headers'].keys():
        auth_token = event['headers']['authorization']
    else:
        raise Exception("Authorization header not found")
    token = token_validation.verify_azure_ad_token(auth_token,
                                                   tenant_id,
                                                   app_id)
    # Isolate unique name or app ID from token
    unique_name = token.get('unique_name', None)
    # If unique_name is present, authorize LDAP group membership of token
    if unique_name:
        # Perform Group lookup
        if not group_membership.verify_group_membership(ldap_server, ldap_username,
                                                        ldap_password, ldap_search_base,
                                                        unique_name, object_class,
                                                        group_names, lookup_attribute):
            raise Exception("Invalid group membership")
        return True
    # If roles are present, check against valid roles
    elif token.get('roles', None):
        if not token_validation.verify_token_roles(token, allowed_roles):
            raise Exception('Client does not have appropriate role.')
        return True
    # If neither unique_name nor roles are present, fail this request
    else:
        raise Exception("Token does not belong to a user or allowed client")


def authorize_lambda_request_v2(
        event: dict, tenant_id: str, app_id: [], allowed_roles: [],
        azure_auth_client_id: str, azure_auth_client_secret: str, allowed_groups: []
):
    """
    Verifies token signature and Authorize request token from Azure AD.

    Params:
        event: the Lambda request event.
        tenant_id: Azure AD tenant ID.
        app_id: App ID/URL that issued token.
        allowed_roles: App roles required to be present in OAuth2 token.
        allowed_groups: Azure AD group names to check for user membership.
        azure_auth_client_id: Client ID of Azure Auth App Registration.
        azure_auth_client_secret: Client Secret of Azure Auth App Registration.

    Returns:
        bool: is request allowed
    """
    # Validate token
    if "Authorization" in event['headers'].keys():
        auth_token = event['headers']['Authorization']
    elif "authorization" in event['headers'].keys():
        auth_token = event['headers']['authorization']
    else:
        raise Exception("Authorization header not found")
    token = token_validation.verify_azure_ad_token(auth_token,
                                                   tenant_id,
                                                   app_id)
    # Isolate unique name or app ID from token
    unique_name = token.get('unique_name', None)
    # If unique_name is present, authorize Azure AD group membership of token
    if unique_name:
        user_groups = group_membership.get_azure_ad_user_groups(
            client_id=azure_auth_client_id,
            client_secret=azure_auth_client_secret,
            unique_name=unique_name
        )
        for grp in allowed_groups:
            if grp.lower() in user_groups:
                break
        else:
            raise Exception("Invalid group membership.")
        return token
    # If roles are present, check against valid roles
    elif token.get('roles', None):
        if not token_validation.verify_token_roles(token, allowed_roles):
            raise Exception('Client does not have appropriate role.')
        return token
    # If neither unique_name nor roles are present, fail this request
    else:
        raise Exception("Token does not belong to a user or allowed client")
