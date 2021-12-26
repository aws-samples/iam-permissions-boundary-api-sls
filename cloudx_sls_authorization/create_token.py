# pylint:disable=no-member,logging-fstring-interpolation

"""
Module for generating azr oauth2 tokens
"""
import json
import requests


oauth2_token_url = "https://login.microsoftonline.com/its.test-org.com/oauth2/v2.0/token"


def get_bearer_token(client_key, client_secret, token_url, scope):
    """
    This method returns a bearer token, which is to be used
    as value for the authorization header
    when making http calls against azure resource manager service.
    Args:
        scope: Scope of the application that would be invoked with the token generated
        token_url: OAuth url that returns the token
        client_secret: Secret of the application that would supply the token generated
        client_key: App Id of the application that would supply the token generated
    :return:
        token
    """
    try:
        payload = {'grant_type': 'client_credentials',
                   'client_id': client_key,
                   'client_secret': client_secret,
                   'scope': scope}
        response = requests.post(token_url, data=payload)
        if response.ok:
            return json.loads(response.text)["access_token"]
        else:
            raise Exception(f"error in retrieving token response - received {response.text}")
    except Exception as ex:
        raise ex
