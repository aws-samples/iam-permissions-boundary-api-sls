"""Behave Environment File"""
# pylint: skip-file
import os
import sys
import json
import logging

# Init Logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

sys.path.append(
    os.path.normpath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "..", ".."))
)

with open('config/config.{}.json'.format(os.environ.get('ENV', 'dev')), "r") as env_config_file:
    env_configs = json.load(env_config_file)
    os.environ['CREDS_API_VPCE_ENDPOINT'] = env_configs["ENVIRONMENT"]["VPCX"]["CREDS_API_VPCE_ENDPOINT"]
    os.environ['CREDS_API_HOSTNAME'] = env_configs["ENVIRONMENT"]["VPCX"]["CREDS_API_HOSTNAME"]
    os.environ['CREDS_API_SCOPE'] = env_configs["ENVIRONMENT"]["VPCX"]["CREDS_API_SCOPE"]
    os.environ['APPSYNC_INFO_SECRET_NAME'] = env_configs["ENVIRONMENT"]["VPCX"]["APPSYNC_INFO_SECRET_NAME"]
    os.environ['APP_CLIENT_ID'] = env_configs["ENVIRONMENT"]["APP_VARS"]["APP_CLIENT_ID"]
with open('config/config.common.json', "r") as common_config_file:
    common_configs = json.load(common_config_file)
    os.environ['MSFT_OAUTH2_TOKEN_URL'] = common_configs["ENVIRONMENT"]["OAUTH"]["MSFT_OAUTH2_TOKEN_URL"]
    os.environ['PB_POLICY_ARN_TPL'] = common_configs["ENVIRONMENT"]["APP_VARS"]["PB_POLICY_ARN_TPL"]

from utils.util import get_secret, execute_request


def before_all(context):
    """
    Prepare BDD testing environment

    Args:
        context: behave framework default args
    """
    context.logger = logger

    context.env_config = env_configs
    context.project_id = env_configs["TESTING"]["TEST_ACCOUNT"]
    context.account_num = env_configs["TESTING"]["TEST_ACCOUNT_NUMBER"]
    app_secret_name = env_configs["ENVIRONMENT"]["APP_VARS"]["APP_SECRETS_NAME"]
    context.api_endpoint = env_configs["TESTING"]["API_ENDPOINT"]
    context.app_default_scope = ''.join((
        env_configs["ENVIRONMENT"]["OAUTH"]["MSFT_IDP_APP_ID"], '/.default'
    ))
    context.common_config = common_configs
    context.oauth2_token_url = common_configs["ENVIRONMENT"]["OAUTH"]["MSFT_OAUTH2_TOKEN_URL"]

    context.execute_request = execute_request
    context.app_client_id = os.environ["APP_CLIENT_ID"]
    app_secrets = json.loads(get_secret(secret_name=app_secret_name))
    context.app_client_secret = app_secrets['exceptions_client_secret']
    os.environ["APP_CLIENT_SECRET"] = context.app_client_secret
