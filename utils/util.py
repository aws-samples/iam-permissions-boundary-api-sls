"""Module contains utility functions for Serverless Package"""
# pylint: disable=line-too-long,import-error,broad-except,wrong-import-order,unused-argument,logging-fstring-interpolation,no-else-return
import os
import re
import json
import requests
import boto3
import logging
from retry.api import retry
from cloudx_sls_authorization.create_token import get_bearer_token

HTTP_GET = 'get'
HTTP_PUT = 'put'
HTTP_POST = 'post'
HTTP_DELETE = 'delete'

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def generate_azure_oauth2_token(scope: str):
    """
    Generate Azure AD Oauth2.0 token for Accessing other APIs

    Args:
        scope: Azure AD Application Scope.
    """
    try:
        client_id = os.environ.get("APP_CLIENT_ID")
        client_secret = os.environ.get('APP_CLIENT_SECRET')
        token_url = os.environ.get("MSFT_OAUTH2_TOKEN_URL")
        access_token = str(get_bearer_token(
            client_key=client_id,
            client_secret=client_secret,
            token_url=token_url,
            scope=scope
        ))
        logger.info(f"Access Token - {str(access_token)}")
        return (
            access_token if access_token.startswith('Bearer ')
            else ''.join(('Bearer ', access_token))
        )
    except Exception as e:
        msg = (
            f"Failed to generate access token for scope '{scope}'. "
            f"Details - '{str(e)}'."
        )
        logger.error(msg)
        raise Exception(msg)


def execute_request(
        url: str, method: str, scope: str = None,
        additional_headers: dict = None,
        additional_payload: dict = None,
        requests_lib: requests = requests
):
    """
    Make a Http request to the provided url

    Args:
        url (str): API URL.
        method (str): Http method. Values = 'get'
        scope (str): AWSAPI Microservice scope for registered Azure App.
        additional_headers (dict): Additional request headers.
        additional_payload (dict): Additional request payload.
        requests_lib: Requests library.

    Returns:
        Response: Response object of Http Request
    """
    try:
        headers = {
            "Content-Type": "application/json"
        }
        if "Authorization" not in additional_headers.keys():
            if not scope:
                scope = os.environ.get("CREDS_API_SCOPE")
            headers["Authorization"] = generate_azure_oauth2_token(
                scope=scope
            )
        if additional_headers:
            headers.update(additional_headers)
        kwargs = {
            "verify": False,
            "headers": headers
        }
        payload = {}
        if additional_payload:
            payload.update(additional_payload)
        if method in [HTTP_PUT, HTTP_POST, HTTP_DELETE]:
            kwargs["json"] = payload
        elif method in [HTTP_GET]:
            kwargs["params"] = payload
        else:
            raise Exception(f"Http Method type {method} not Supported")
        logger.info(
            f"Making {method.upper()} call - "
            "{"
            f"'url': '{url}', 'payload': {payload}"
            "}"
        )
        return requests_lib.request(method, url, timeout=300, **kwargs)
    except Exception as ex:
        logger.error(
            f"execute_request - Request to url '{url}' failed."
            f" Error Details - {str(ex)}."
        )
        raise ex


class CredsApiCallFailedException(Exception):
    """Thrown for Retry in creds api call"""


@retry(exceptions=CredsApiCallFailedException, tries=5, delay=3, backoff=1.5)
def get_temp_creds(project_id: str):
    """
    Get temporary credentials for AWS Project

    Args:
        project_id: AWS Project ID.

    Returns:
        dict: temporary credentials
    """
    try:
        url = os.environ.get("CREDS_API_VPCE_ENDPOINT").replace('<ACCOUNT_ALIAS>', project_id)
        additional_headers = {
            'Host': os.environ.get('CREDS_API_HOSTNAME')
        }
        additional_payload = {
            'duration': '3600'
        }
        resp = execute_request(
            url=url,
            method='get',
            scope=os.environ.get('CREDS_API_SCOPE'),
            additional_headers=additional_headers,
            additional_payload=additional_payload
        )
        # when invalid project id is passed
        if resp.status_code == 200:
            return json.loads(resp.text).get('credentials')
        elif 'Invalid account' in str(resp.text) or resp.status_code == 401:
            raise Exception(str(resp.text))
        else:
            raise CredsApiCallFailedException(f"Call to Creds API failed. Details - {str(resp.text)}")
    except Exception as ex:
        logger.error(f"Error while getting creds. Details - {str(ex)}")
        raise ex


def connect_service(service: str, credentials: dict = None, aws_region: str = None):
    """
    Get Boto3 Service Client

    Args:
        service: AWS Service.
        credentials: AWS Account credentials.
        aws_region: AWS Region.

    Returns:
        boto3: Boto3 Client Object
    """
    if aws_region is None:
        aws_region = os.environ.get('REGION', 'us-east-1')
    if credentials:
        kwargs = {
            "service_name": service,
            "region_name": aws_region,
            "aws_access_key_id": credentials.get('AccessKeyId'),
            "aws_secret_access_key": credentials.get('SecretAccessKey'),
            "aws_session_token": credentials.get('SessionToken')
        }
    else:
        kwargs = {
            "service_name": service,
            "region_name": aws_region
        }
    return boto3.client(**kwargs)


def get_secret(secret_name: str, version: str = None, boto_client=None):
    """
    Get Secret Value from Secret Manager

    Args:
         secret_name: Secret Name.
         version: Secret Version Stage.
         boto_client: boto3 client Object.

    Returns:
         str: Secret Value
    """
    try:
        logger.info(
            f"Getting value for Secret '{secret_name}'"
        )
        if boto_client is None:
            region = os.environ.get('REGION', 'us-east-1')
            boto_client = boto3.client('secretsmanager', region_name=region)
        params = {
            "SecretId": secret_name
        }
        if version:
            params["VersionStage"] = version
        secretobj = boto_client.get_secret_value(
            **params
        )
        secret_value = secretobj.get('SecretString')
        logger.info(f"Found value for secret '{str(secret_name)}'")
        return secret_value
    except Exception as ex:
        msg = (
            f"get_secret: Failed to load secret. Details - {str(ex)}"
        )
        logger.exception(msg)
        if type(ex).__name__ == "ClientError":
            ex.response["Error"]["Message"] = msg
            raise ex.__class__(
                ex.response, ex.operation_name
            )
        else:
            raise ex


def execute_gql(query: str, variables: str, endpoint: str, key: str):
    """
    execute gql queries and return results

    Args:
        query: GQL Query.
        variables: GQL Query Variables.
        endpoint: APP Sync Endpoint.
        key: APP Sync Key.
    """
    headers = {
        'Content-Type': "application/json",
        'x-api-key': key,
        "Authorization": key,
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Expose-Headers': '*',
    }
    response = execute_request(
        url=endpoint,
        method="post",
        additional_payload={'query': query, 'variables': variables},
        additional_headers=headers
    )
    if response.status_code == 200:
        return json.loads(response.text)
    raise Exception(
        f"Query failed to run by returning code of '{str(response.status_code)}'. "
        f"Details - '{str(response.text)}'"
    )


def get_account_by_project_id_gql(project_id: str) -> dict:
    """
    Get VPCx Accounts by Project ID GQL

    Args:
        project_id: AWS Project ID.
    """
    query = '''
       query GetAccountByProjectId($ProjectId:String){
          GetAccountByProjectId(project_id: $ProjectId){
            items{
              id
              project_id
              pb_exceptions
              aws_number
              ec2_security_groups
              regions
              services
            }
          }
        }
       '''
    try:
        appsync_config = json.loads(
            get_secret(secret_name=os.environ.get("APPSYNC_INFO_SECRET_NAME"))
        )
        response = execute_gql(
            query=query,
            variables='{"ProjectId": "' + project_id + '"}',
            endpoint=appsync_config.get("url"),
            key=appsync_config.get("key")
        )
        accounts = response.get("data").get("GetAccountByProjectId").get("items", [])
        logger.info(
            f"get_account_pb_exceptions_gql - Accounts: '{str(accounts)}'"
        )
        if not accounts:
            return {}
        else:
            return accounts[0]
    except Exception as e:
        logger.error(
            f"Failed to Get Account from Graph QL query. Details - '{str(e)}'"
        )
        raise e


def update_account_pb_exception_gql(rec_id: str, pb_exceptions: list):
    """
    Update AWS Account pb_exceptions record

    Args:
        rec_id: DynamoDB Record ID.
        pb_exceptions: pb_exceptions list.
    """
    query = '''
        mutation updateAccount($RecordId: ID!,$PbExceptions: [String]){
            updateAccount(input: {
                id: $RecordId, 
                pb_exceptions: $PbExceptions
            }){
                id
                project_id
                pb_exceptions
            }
        }
       '''
    try:
        appsync_config = json.loads(
            get_secret(secret_name=os.environ.get("APPSYNC_INFO_SECRET_NAME"))
        )
        response = execute_gql(
            query=query,
            variables=json.dumps({"RecordId": rec_id, "PbExceptions": pb_exceptions}),
            endpoint=appsync_config.get("url"),
            key=appsync_config.get("key")
        )
        logger.info(f"Update Account Query Response - {str(response)}")
    except Exception as e:
        msg = (
            "Failed to Update Account PB Exceptions from Graph QL"
            f" query. Details - '{str(e)}'"
        )
        logger.error(msg)
        raise Exception(msg)


def get_account_pb(project_id: str, account_number: str):
    """
    Get Account Permission Boundary actions

    Args:
        project_id: AWS Project ID.
        account_number: AWS Account Number.
    """
    try:
        pb_policy_arn = os.environ["PB_POLICY_ARN_TPL"].replace("<ACCOUNT_NUM>", account_number)
        creds = get_temp_creds(project_id=project_id)
        iam_client = connect_service(
            service="iam",
            credentials=creds
        )
        response = iam_client.get_policy(
            PolicyArn=pb_policy_arn
        ).get("Policy", {})
        logger.info(f"Policy: '{str(response)}'")
        default_version = response.get("DefaultVersionId")
        policy_version = iam_client.get_policy_version(
            PolicyArn=pb_policy_arn,
            VersionId=default_version
        ).get("PolicyVersion", {})
        doc = policy_version.get("Document", "{}")
        return json.loads(doc) if type(doc) == str else doc
    except Exception as e:
        msg = f"Failed to get account pb. Details - {str(e)}"
        logger.error(msg)
        raise Exception(msg)


def get_aws_service_map():
    """Get a Map of AWS Services and their respective actions"""
    data = requests.get('https://awspolicygen.s3.amazonaws.com/js/policies.js')
    return json.loads(data.text[len("app.PolicyEditorConfig="):]).get("serviceMap")


def validate_action_format(action: str):
    regex = re.compile(r"^[a-z0-9]+-*[a-z0-9]+:([a-zA-Z]+|\*)$")
    if ":" not in action:
        return False
    elif not regex.match(action):
        return False
    else:
        return True


def update_account_pb(
        project_id: str, regions: list, services: list,
        pb_exceptions: list, ec2_sgs: list
):
    """
    Updates permissions boundary for account

    Args:
        project_id: AWS Project ID.
        regions: AWS Account regions.
        services: AWS Account enabled services.
        pb_exceptions: Service exceptions.
        ec2_sgs: Account EC2 Security Groups.
    """
    try:
        token = generate_azure_oauth2_token(
            scope=os.environ.get("UPDATE_PB_API_SCOPE")
        )
        headers = {
            'Authorization': token,
            'Content-Type': "application/json"
        }
        payload = {
            "project_id": project_id,
            "regions": regions,
            "existing_services": services,
            "PolicyExceptionActions": pb_exceptions,
            "ec2_security_groups": ec2_sgs,
            "Authorization": token
        }
        response = execute_request(
            url=os.environ.get("UPDATE_PB_API_URL"),
            method="post",
            additional_payload=payload,
            additional_headers=headers
        )
        if response.status_code != 200:
            msg = (
                "Update Permission Boundary URL failed with status "
                f"code '{str(response.status_code)}'. Response - '{str(response.text)}'"
            )
            raise Exception(msg)
    except Exception as e:
        msg = (
            f"Failed to update account pb. Details - '{str(e)}'"
        )
        logger.error(msg)
        raise Exception(msg)
