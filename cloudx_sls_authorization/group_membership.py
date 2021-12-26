"""Library to verify LDAP group membership"""
import logging
import ldap3
import json
import requests
from cloudx_sls_authorization.create_token import get_bearer_token, oauth2_token_url


graph_api_scope = "https://graph.microsoft.com/.default"
graph_api_v1_endpoint = "https://graph.microsoft.com/v1.0"


def verify_group_membership(ldap_server: str, ldap_username: str, ldap_password: str,
                            ldap_search_base: str, username: str, object_class: str,
                            group_names: [], lookup_attribute: str) -> bool:
    """
    Verifies a member is part of a group.

    Params:
        ldap_server: the ldap server, e.g., abc.def.com:1234
        ldap_username: the ldap user to query permissions
        ldap_password: the password for ldap_username
        ldap_search_base: the location of the user in LDAP
        username: the user to search for group membership
        object_class: the LDAP object class of the user
        group_names: the list of group names to check for user membership
        lookup_attribute: the attribute used to lookup the object

    Returns:
        bool: indicates whether the user is or is not a member
            of the group
    """

    user_groups = get_user_groups(ldap_server, ldap_username, ldap_password,
                            ldap_search_base, username, object_class, lookup_attribute)
    # Iterate over user groups
    for group in user_groups:
        # Isolate group properties to search for CN
        for group_component in group.split(','):
            # Iterate over allowed groups from input
            for group_name in group_names:
                if group_component.upper() == "CN={}".format(group_name.upper()):
                    return True
    return False

def get_user_groups(ldap_server: str, ldap_username: str, ldap_password: str,
                            ldap_search_base: str, username: str, object_class: str,
                            lookup_attribute: str) -> bool:
    """
    Returns the member groups.

    Params:
        ldap_server: the ldap server, e.g., abc.def.com:1234
        ldap_username: the ldap user to query permissions
        ldap_password: the password for ldap_username
        ldap_search_base: the location of the user in LDAP
        username: the user to search for group membership
        object_class: the LDAP object class of the user
        lookup_attribute: the attribute used to lookup the object

    Returns:
        list: Member groups
    """
    # Declare search filter
    ldap_search_filter = "(&({}={})(objectclass={}))".format(lookup_attribute, username, object_class)
    # Connect to LDAP server
    conn = ldap3.Connection(ldap_server, ldap_username, ldap_password, auto_bind=True)
    # Search for group
    conn.search(search_base=ldap_search_base, search_filter=ldap_search_filter, attributes=['*'])
    # Verify only one result found
    if len(conn.entries) != 1:
        raise InvalidUserMatchError(conn.entries)
    else:
        # Isolate matched LDAP user
        user = json.loads(conn.entries[0].entry_to_json())
        user_groups = user["attributes"]["memberOf"]
        return user_groups


class InvalidUserMatchError(Exception):
    """
    Exception raised when a single user is not found.

    Attributes:
        users: Users found
        message: Description of this error
    """

    def __init__(self, users, message="No single user found."):
        self.users = users
        self.message = message
        super().__init__(self.message)


def get_azure_ad_user_groups(client_id: str, client_secret: str, unique_name: str):
    """
    Get User Group Memberships from Azure AD

    Arguments:
        client_id: Azure Auth App Client ID.
        client_secret: Azure Auth App Client Secret.
        unique_name: Azure Ad User Unique Name.

    Returns:
        list: Name of Group attached to User
    """
    get_user_groups_url = (
        f"{graph_api_v1_endpoint}/users/{unique_name}/memberOf?$select=displayName&$top=999"
    )
    auth_token = get_bearer_token(
        client_key=client_id,
        client_secret=client_secret,
        token_url=oauth2_token_url,
        scope=graph_api_scope
    )
    headers = {
        "Authorization": (
            ''.join(("Bearer ", auth_token))
            if not str(auth_token).startswith("Bearer ")
            else auth_token
        )
    }
    user_groups = []
    response = requests.get(get_user_groups_url, json={}, headers=headers)
    res = json.loads(response.text)
    if response.status_code == 200:
        for group in res.get("value", []):
            user_groups.append(group.get("displayName", "").lower())
    elif (
            response.status_code == 404
            and res.get("error", {}).get("code", "")
            == "Request_ResourceNotFound"
    ):
        logging.error(
            f"No User Found. Details - {str(res.get('error', {}).get('message', ''))}"
        )
        raise Exception("User not found in Tenant 'its.test-org.com'.")
    else:
        logging.error(
            f"Get user groups API Failed. Details - {str(res)}"
        )
        raise Exception(
            "Failed to determine user group membership. "
            f"Details - {str(res.get('error', {}).get('message', ''))}"
        )
    return user_groups
