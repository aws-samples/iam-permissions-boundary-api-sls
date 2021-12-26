"""Module Contains handler for Trigger RDS Maintenance Report Lambda Function"""
# pylint: disable=line-too-long,import-error,broad-except,wrong-import-order,unused-argument,logging-fstring-interpolation,no-else-return
import os
import json
import traceback
import logging
from cloudx_sls_authorization.lambda_auth import authorize_lambda_request
from utils.util import (
    get_secret, get_account_by_project_id_gql,
    update_account_pb_exception_gql, update_account_pb
)

# Init Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Load Constants
LDAP_SERVER = os.environ['LDAP_SERVER']
LDAP_USERNAME = os.environ['LDAP_USERNAME']
LDAP_PASSWORD_SECRET_NAME = os.environ['LDAP_PASSWORD_SECRET_NAME']
LDAP_PASSWORD = json.loads(get_secret(LDAP_PASSWORD_SECRET_NAME))['PASSWORD']
LDAP_SEARCH_BASE = os.environ['LDAP_SEARCH_BASE']
LDAP_OBJECT_CLASS = os.environ['LDAP_OBJECT_CLASS']
LDAP_GROUP_NAME = os.environ['LDAP_GROUP_NAME'].split(',')
LDAP_USER_LOOKUP_ATTRIBUTE = os.environ['LDAP_USER_LOOKUP_ATTRIBUTE']
MSFT_IDP_TENANT_ID = os.environ['MSFT_IDP_TENANT_ID']
MSFT_IDP_APP_ID = os.environ['MSFT_IDP_APP_ID'].split(',')
MSFT_IDP_CLIENT_ROLES = os.environ['MSFT_IDP_CLIENT_ROLES'].split(',')
APP_SECRET_NAME = os.environ['APP_SECRET_NAME']
try:
    app_secrets = json.loads(get_secret(secret_name=APP_SECRET_NAME))
    logger.info(f"Loaded Secret Keys - {str(list(app_secrets.keys()))}")
    os.environ['APP_CLIENT_SECRET'] = app_secrets['exceptions_client_secret']
except Exception as ex:
    logger.error(f"Failed to load App Secrets. Details - {str(ex)}")
    raise ex


def handler(event, context):
    """Lambda Handler"""
    logger.info(f"Incoming Event: '{str(event)}'")
    try:
        authorize_lambda_request(
            event=event,
            tenant_id=MSFT_IDP_TENANT_ID,
            app_id=MSFT_IDP_APP_ID,
            allowed_roles=MSFT_IDP_CLIENT_ROLES,
            ldap_server=LDAP_SERVER,
            ldap_username=LDAP_USERNAME,
            ldap_password=LDAP_PASSWORD,
            ldap_search_base=LDAP_SEARCH_BASE,
            object_class=LDAP_OBJECT_CLASS,
            group_names=LDAP_GROUP_NAME,
            lookup_attribute=LDAP_USER_LOOKUP_ATTRIBUTE
        )
    except Exception as ex:
        logger.error(ex)
        traceback.print_exc()
        return {
            "statusCode": 401,
            "isBase64Encoded": False,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "error": {
                    "code": "UnAuthorized",
                    "message": str(ex)
                }
            })
        }
    try:
        payload = json.loads(event['body']) if event.get("body", "{}") else {}
        if not payload.get("project_id", ""):
            logger.info("Invalid Payload: 400")
            return {
                "statusCode": 400,
                "isBase64Encoded": False,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "message": (
                        "Invalid payload. Request missing "
                        "required field 'project_id' of type <string>."
                    )
                })
            }
        else:
            project_id = payload.get("project_id", "")
            logger.info(f"Processing account: '{str(project_id)}'.")
        if not payload.get("exception_actions", []):
            logger.info("Invalid Payload: 400")
            return {
                "statusCode": 400,
                "isBase64Encoded": False,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "message": (
                        "Invalid payload. Request missing "
                        "required field 'exception_actions' of type <list>."
                    )
                })
            }
        else:
            exception_actions = payload.get("exception_actions", [])
            logger.info(f"Exception Actions: '{str(exception_actions)}'")
        account_details = get_account_by_project_id_gql(project_id=project_id)
        if account_details:
            pb_exceptions = account_details.get("pb_exceptions") if account_details.get("pb_exceptions") else []
            record_id = account_details.get("id")
            ec2_security_groups = (
                account_details.get("ec2_security_groups", []) if account_details.get("ec2_security_groups") else []
            )
            regions = (
                account_details.get("regions", []) if account_details.get("regions") else []
            )
            services = (
                account_details.get("services", []) if account_details.get("services") else []
            )
            if not pb_exceptions:
                pb_exceptions = []
            for action in exception_actions:
                if action in pb_exceptions:
                    logger.info(f"Removing action '{action}' from account 'pb_exceptions'.")
                    pb_exceptions.remove(action)
            update_account_pb_exception_gql(
                rec_id=record_id,
                pb_exceptions=pb_exceptions
            )
            update_account_pb(
                project_id=project_id,
                regions=regions,
                services=services,
                pb_exceptions=pb_exceptions,
                ec2_sgs=ec2_security_groups
            )
            return {
                "statusCode": 200,
                "isBase64Encoded": False,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "message": (
                        "Successfully updated 'pb_exceptions' "
                        f"for account '{str(project_id)}'"
                    )
                })
            }
        else:
            return {
                "statusCode": 404,
                "isBase64Encoded": False,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "message": "Invalid AWS Account."
                })
            }
    except Exception as ex:
        msg = f"Lambda execution failed. Details - {str(ex)}"
        logger.error(msg)
        traceback.print_exc()
        return {
            "statusCode": 500,
            "isBase64Encoded": False,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "message": msg
            })
        }
