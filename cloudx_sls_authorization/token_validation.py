"""Library to verify JWT signature using public keys"""
import jwt
import requests
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend

AZURE_AD_WELL_KNOWN_OIDC_ENDPOINT = 'https://login.microsoftonline.com/{}/v2.0/.well-known/openid-configuration'


def verify_azure_ad_token(token: str, tenant_id: str, app_id: []):
    """
    Verifies token signature and returns token information.

    Params:
        token: the JWT issued by Azure AD
        tenant_id: Azure AD tenant ID
        app_id: App ID that issued token

    Returns:
        dict: decoded access token
    """
    # Trim "Bearer ", if present
    token = token.replace("Bearer ", "")
    # Extract JWT token header (and key id and algorithm)
    token_header = jwt.get_unverified_header(token)
    kid = token_header['kid']
    alg = token_header['alg']
    # Retrieve OIDC configs
    oidc_configs = requests.get(AZURE_AD_WELL_KNOWN_OIDC_ENDPOINT.format(tenant_id)).json()
    # Retrieve JSON Web Key Sets
    jwk_keys = requests.get(oidc_configs['jwks_uri']).json()
    # Find matching key ID
    matching_jwk = None
    for jwk in jwk_keys['keys']:
        if jwk.get('kid', None) == kid:
            matching_jwk = jwk
            break
    # Validate matching key ID was found
    if not matching_jwk:
        raise NoKeyFoundError()
    # Load public key from JWK
    cert = ''.join([
        '-----BEGIN CERTIFICATE-----\n',
        matching_jwk['x5c'][0],
        '\n-----END CERTIFICATE-----\n',
    ])
    public_key = load_pem_x509_certificate(cert.encode(), default_backend()).public_key()
    # Return decoded token
    return jwt.decode(
        token,
        public_key,
        algorithms=alg,
        audience=app_id
    )


def verify_token_roles(token: dict, roles: []):
    """
    Check if a token is a member of allowed roles.
    
    Params:
        token: decoded token
        roles: allowed groups
    
    Returns:
        bool: indicates whether token is present in allowed roles
    """
    if 'roles' not in token:
        return False
    else:
        for token_role in token['roles']:
            if token_role.upper() in (role.upper() for role in roles):
                return True
    return False


class NoKeyFoundError(Exception):
    """
    Exception raised when key used to sign request cannot be found.

    Attributes:
        message: Description of this error
    """

    def __init__(self, message="No key found."):
        self.message = message
        super().__init__(self.message)