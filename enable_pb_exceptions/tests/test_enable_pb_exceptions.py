"""Module contains unit tests"""
# pylint: skip-file
import os
import json
import pytest
from unittest.mock import patch

MOCK_ENV_VARS = {
    "ENVIRONMENT": "MockITxEnvironment",
    "LDAP_SERVER": "mock",
    "LDAP_USERNAME": "mock",
    "LDAP_PASSWORD_SECRET_NAME": "mock",
    "PASSWORD": "mock",
    "LDAP_SEARCH_BASE": "mock",
    "LDAP_OBJECT_CLASS": "mock",
    "LDAP_GROUP_NAME": "mock",
    "LDAP_USER_LOOKUP_ATTRIBUTE": "mock",
    "MSFT_IDP_TENANT_ID": "mock",
    "MSFT_IDP_APP_ID": "mock",
    "MSFT_IDP_CLIENT_ROLES": "mock",
    "MSFT_OAUTH2_TOKEN_URL": "mock",
    "APP_SECRET_NAME": "mock"
}


@pytest.fixture(autouse=True)
def mock_1_settings_env_vars():
    with patch.dict(os.environ, MOCK_ENV_VARS):
        yield


@pytest.fixture(autouse=True)
def mock_2_secret():
    with patch('utils.util.get_secret') as mock_secret:
        mock_secret.side_effect = [
            json.dumps({
                "PASSWORD": "random",
            }),
            json.dumps({
                "exceptions_client_secret": "random"
            })
        ]
        yield


class MockLambdaEvent:

    def __init__(self, project_id, exception_actions):
        self.project_id = project_id
        self.exception_actions = exception_actions

    def get_event(self):
        return {
            'body': json.dumps({
                "project_id": self.project_id,
                "exception_actions": self.exception_actions
            })
        }


@patch('enable_pb_exceptions.index.update_account_pb_exception_gql')
@patch('enable_pb_exceptions.index.update_account_pb')
@patch('enable_pb_exceptions.index.get_account_by_project_id_gql')
@patch('enable_pb_exceptions.index.validate_action_format')
@patch('enable_pb_exceptions.index.get_aws_service_map')
@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_001_handler_success(
        mock_auth, mock_get_svcmap, mock_validate_action,
        mock_get_account, mock_update_pb, mock_update_pb_exc
):
    mock_auth.return_value = True
    mock_get_svcmap.return_value = {
        "Mock Service": {
            "StringPrefix": "mock",
            "Actions": [
                "Mock"
            ]
        }
    }
    mock_validate_action.return_value = True
    mock_get_account.return_value = {
        "pb_exceptions": None,
        "id": "random",
        "ec2_security_groups": ["sg1"],
        "regions": ["us-east-1"],
        "services": ["Mockx"]
    }
    mock_update_pb.return_value = True
    mock_update_pb_exc.return_value = True
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("itx-000", ["mock:Mock"]).get_event(), None)
    assert result['statusCode'] == 200
    assert "Successfully updated 'pb_exceptions'" in json.loads(result['body'])['message']


@patch('enable_pb_exceptions.index.update_account_pb_exception_gql')
@patch('enable_pb_exceptions.index.update_account_pb')
@patch('enable_pb_exceptions.index.get_account_by_project_id_gql')
@patch('enable_pb_exceptions.index.validate_action_format')
@patch('enable_pb_exceptions.index.get_aws_service_map')
@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_002_handler_success_already_enabled(
        mock_auth, mock_get_svcmap, mock_validate_action,
        mock_get_account, mock_update_pb, mock_update_pb_exc
):
    mock_auth.return_value = True
    mock_get_svcmap.return_value = {
        "Mock Service": {
            "StringPrefix": "mock",
            "Actions": [
                "Mock"
            ]
        }
    }
    mock_validate_action.return_value = True
    mock_get_account.return_value = {
        "pb_exceptions": ["mock:*"],
        "id": "random",
        "ec2_security_groups": ["sg1"],
        "regions": ["us-east-1"],
        "services": ["Mockx"]
    }
    mock_update_pb.return_value = True
    mock_update_pb_exc.return_value = True
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("itx-000", ["mock:*"]).get_event(), None)
    assert result['statusCode'] == 200
    assert "Successfully updated 'pb_exceptions'" in json.loads(result['body'])['message']


@patch('enable_pb_exceptions.index.validate_action_format')
@patch('enable_pb_exceptions.index.get_aws_service_map')
@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_003_handler_fail_invalid_action(
        mock_auth, mock_get_svcmap, mock_validate_action
):
    mock_auth.return_value = True
    mock_get_svcmap.return_value = {
        "Mock Service": {
            "StringPrefix": "mock",
            "Actions": [
                "Mock"
            ]
        }
    }
    mock_validate_action.side_effect = [
        True,
        True,
        False
    ]
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("itx-000", ["mock:MockNew", "nomock:*", "mock@2"]).get_event(), None)
    assert result['statusCode'] == 400
    assert "Invalid Action." in json.loads(result['body'])['message']


@patch('enable_pb_exceptions.index.get_account_by_project_id_gql')
@patch('enable_pb_exceptions.index.validate_action_format')
@patch('enable_pb_exceptions.index.get_aws_service_map')
@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_004_handler_fail_invalid_account(
        mock_auth, mock_get_svcmap, mock_validate_action, mock_get_account
):
    mock_auth.return_value = True
    mock_get_svcmap.return_value = {
        "Mock Service": {
            "StringPrefix": "mock",
            "Actions": [
                "Mock"
            ]
        }
    }
    mock_validate_action.return_value = True
    mock_get_account.return_value = {}
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("itx-000", ["mock:Mock"]).get_event(), None)
    assert result['statusCode'] == 404
    assert "Invalid AWS Account." in json.loads(result['body'])['message']


@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_005_handler_fail_invalid_payload_exception_actions(mock_auth):
    mock_auth.return_value = True
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("itx-000", []).get_event(), None)
    assert result['statusCode'] == 400
    assert "Invalid payload." in json.loads(result['body'])['message']


@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_006_handler_fail_invalid_payload_project_id(mock_auth):
    mock_auth.return_value = True
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("", []).get_event(), None)
    assert result['statusCode'] == 400
    assert "Invalid payload." in json.loads(result['body'])['message']


@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_007_handler_fail_invalid_auth(mock_auth):
    mock_auth.side_effect = Exception("Signature expired")
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("", []).get_event(), None)
    assert result['statusCode'] == 401
    assert "UnAuthorized" in result['body']


@patch('enable_pb_exceptions.index.get_aws_service_map')
@patch('enable_pb_exceptions.index.authorize_lambda_request')
def test_008_handler_fail_exception(mock_auth, mock_get_svcmap):
    mock_auth.return_value = True
    mock_get_svcmap.side_effect = Exception("error")
    from enable_pb_exceptions.index import handler
    # Call method
    result = handler(MockLambdaEvent("itx-000", ["mock:Mock"]).get_event(), None)
    assert result['statusCode'] == 500
    assert "Lambda execution failed." in json.loads(result['body'])['message']
