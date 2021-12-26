"""Module contains unit tests"""
# pylint: skip-file
import os
import json
import pytest
from unittest.mock import patch
from botocore.exceptions import ClientError

MOCK_ENV_VARS = {
    "ENVIRONMENT": "MockITxEnvironment",
    "APP_CLIENT_ID": "mock",
    "APP_CLIENT_SECRET": "mock",
    "MSFT_OAUTH2_TOKEN_URL": "mock",
    "CREDS_API_SCOPE": "mock",
    "CREDS_API_VPCE_ENDPOINT": "10",
    "CREDS_API_HOSTNAME": "mock",
    "APPSYNC_INFO_SECRET_NAME": "mock",
    "PB_POLICY_ARN_TPL": "mock",
    "UPDATE_PB_API_SCOPE": "mock",
    "UPDATE_PB_API_URL": "mock",
}


@pytest.fixture(autouse=True)
def mock_1_settings_env_vars():
    with patch.dict(os.environ, MOCK_ENV_VARS):
        yield


class BotoClient:

    def get_secret_value(self, **kwargs):
        return {
            "SecretString": "mock"
        }

    def get_policy(self, **kwargs):
        return {}

    def get_policy_version(self, **kwargs):
        return {}


class BotoClientException:

    def get_secret_value(self, **kwargs):
        raise ClientError(
            {"Error": {"Code": "InvalidClient", "Message": "Error"}},
            "mock"
        )

    def get_policy(self, **kwargs):
        raise ClientError(
            {"Error": {"Code": "InvalidClient", "Message": "Error"}},
            "mock"
        )

    def get_policy_version(self, **kwargs):
        raise ClientError(
            {"Error": {"Code": "InvalidClient", "Message": "Error"}},
            "mock"
        )


class MockRequestsLib:

    def request(self, method, url, timeout, **kwargs):
        """Request"""
        return True


@patch("utils.util.get_bearer_token")
def test_001_execute_request_fail_not_supported(mock_token):
    mock_token.return_value = "xyz..."
    from utils.util import execute_request
    with pytest.raises(Exception) as ex_info:
        execute_request(
            url="http://mock.com",
            method="random",
            additional_headers={
                "Host": "mock"
            },
            additional_payload={
                "value": "true"
            },
            requests_lib=MockRequestsLib()
        )
    assert "not supported" in ex_info.value.args[0].lower()


@patch("utils.util.get_bearer_token")
def test_002_execute_request_success_get(mock_token):
    mock_token.return_value = "xyz..."
    from utils.util import execute_request
    result = execute_request(
        url="http://mock.com",
        method="get",
        additional_headers={
            "Host": "mock"
        },
        additional_payload={
            "value": "true"
        },
        requests_lib=MockRequestsLib()
    )
    assert result == True


@patch("utils.util.get_bearer_token")
def test_003_execute_request_success_post(mock_token):
    mock_token.return_value = "xyz..."
    from utils.util import execute_request
    result = execute_request(
        url="http://mock.com",
        method="post",
        additional_headers={
            "Host": "mock"
        },
        additional_payload={
            "value": "true"
        },
        requests_lib=MockRequestsLib()
    )
    assert result == True


@patch("utils.util.execute_request")
def test_004_get_temp_creds_fail_invalid_account(mock_request):
    from utils.util import get_temp_creds
    mock_request.return_value = MockResponse(
        status_code=400,
        text="{\"error\":{\"code\": \"Exception\", \"message\": \"Invalid account\"}}"
    )
    with pytest.raises(Exception) as ex_info:
        get_temp_creds(
            project_id="itx-000"
        )
    assert "invalid account" in ex_info.value.args[0].lower()


@patch("utils.util.execute_request")
def test_005_get_temp_creds_success(mock_request):
    from utils.util import get_temp_creds
    mock_request.return_value = MockResponse(
        status_code=200,
        text="{\"credentials\": {\"AccessKey\": \"mock\"}}"
    )
    result = get_temp_creds(
        project_id="itx-000"
    )
    assert result.get("AccessKey") == "mock"


@patch("utils.util.boto3.client")
def test_006_connect_service_success(mock_client):
    from utils.util import connect_service
    mock_client.return_value = True
    result = connect_service(
        service="rds"
    )
    assert result is True


@patch("utils.util.boto3.client")
def test_007_connect_service_success(mock_client):
    from utils.util import connect_service
    mock_client.return_value = True
    result = connect_service(
        service="rds",
        credentials={
            "AccessKey": "mock"
        }
    )
    assert result is True


class MockResponse:

    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


def test_008_get_secret_success():
    from utils.util import get_secret
    result = get_secret(
        secret_name="mock",
        version="mock",
        boto_client=BotoClient()
    )
    assert "mock" == result


def test_009_get_secret_fail_exception():
    from utils.util import get_secret
    with pytest.raises(ClientError) as ex_info:
        get_secret(
            secret_name="mock",
            version="mock",
            boto_client=BotoClientException()
        )
    assert "InvalidClient" in ex_info.value.args[0]


@patch('utils.util.execute_request')
def test_010_execute_gql_success(mock_request):
    from utils.util import execute_gql
    mock_request.return_value = MockResponse(
        status_code=200,
        text=json.dumps({"accounts": []})
    )
    result = execute_gql(
        query="",
        variables="",
        endpoint="",
        key=""
    )
    assert "accounts" in result.keys()


@patch('utils.util.execute_request')
def test_011_execute_gql_fail_invalid_response(mock_request):
    from utils.util import execute_gql
    mock_request.return_value = MockResponse(
        status_code=500,
        text="mock exception"
    )
    with pytest.raises(Exception) as ex_info:
        execute_gql(
            query="",
            variables="",
            endpoint="",
            key=""
        )
    assert "Query failed to run by returning code of" in ex_info.value.args[0]


@patch('utils.util.get_secret')
@patch('utils.util.execute_gql')
def test_012_get_account_by_project_id_gql_success(mock_request, mock_secret):
    from utils.util import get_account_by_project_id_gql
    mock_request.return_value = {
        "data": {
            "GetAccountByProjectId": {
                "items": []
            }
        }
    }
    mock_secret.return_value = json.dumps({
        "url": "",
        "key": ""
    })
    result = get_account_by_project_id_gql(project_id="itx-abc")
    assert result == {}


@patch('utils.util.get_secret')
@patch('utils.util.execute_gql')
def test_013_get_account_by_project_id_gql_fail_exception(mock_request, mock_secret):
    from utils.util import get_account_by_project_id_gql
    mock_request.side_effect = Exception("mock exception")
    mock_secret.return_value = json.dumps({
        "url": "",
        "key": ""
    })
    with pytest.raises(Exception) as ex_info:
        get_account_by_project_id_gql(project_id="itx-abc")
    assert "mock exception" in ex_info.value.args[0]


@patch('utils.util.get_secret')
@patch('utils.util.execute_gql')
def test_014_get_account_by_project_id_gql_success(mock_request, mock_secret):
    from utils.util import get_account_by_project_id_gql
    mock_request.return_value = {
        "data": {
            "GetAccountByProjectId": {
                "items": [{"project_id": "itx-000"}]
            }
        }
    }
    mock_secret.return_value = json.dumps({
        "url": "",
        "key": ""
    })
    result = get_account_by_project_id_gql(project_id="itx-000")
    assert result["project_id"] == "itx-000"


@patch("utils.util.get_bearer_token")
def test_015_generate_azure_oauth2_token_success(mock_token):
    mock_token.return_value = "Bearer xyz..."
    from utils.util import generate_azure_oauth2_token
    result = generate_azure_oauth2_token(scope="")
    assert "Bearer" in result


@patch("utils.util.get_bearer_token")
def test_016_generate_azure_oauth2_token_fail(mock_token):
    mock_token.side_effect = Exception("Invalid client")
    from utils.util import generate_azure_oauth2_token
    with pytest.raises(Exception) as ex_info:
        generate_azure_oauth2_token(scope="")
    assert "invalid client" in ex_info.value.args[0].lower()


@patch('utils.util.get_secret')
@patch('utils.util.execute_gql')
def test_017_update_account_pb_exception_gql_success(mock_request, mock_secret):
    from utils.util import update_account_pb_exception_gql
    mock_request.return_value = True
    mock_secret.return_value = json.dumps({
        "url": "",
        "key": ""
    })
    assert update_account_pb_exception_gql("", []) is None


@patch('utils.util.get_secret')
@patch('utils.util.execute_gql')
def test_018_update_account_pb_exception_gql_fail(mock_request, mock_secret):
    from utils.util import update_account_pb_exception_gql
    mock_request.side_effect = Exception("error")
    mock_secret.return_value = json.dumps({
        "url": "",
        "key": ""
    })
    with pytest.raises(Exception) as ex_info:
        update_account_pb_exception_gql("", [])
    assert "Failed to Update Account PB Exceptions" in ex_info.value.args[0]


@patch('utils.util.get_temp_creds')
@patch('utils.util.connect_service')
def test_019_get_account_pb_success(mock_client, mock_token):
    from utils.util import get_account_pb
    mock_token.return_value = "Bearer xyz......."
    mock_client.return_value = BotoClient()
    assert get_account_pb("", "") == {}


@patch('utils.util.get_temp_creds')
def test_020_get_account_pb_fail(mock_token):
    from utils.util import get_account_pb
    mock_token.side_effect = Exception("error")
    with pytest.raises(Exception) as ex_info:
        get_account_pb("", "")
    assert "Failed to get account pb." in ex_info.value.args[0]


@patch('utils.util.generate_azure_oauth2_token')
@patch('utils.util.execute_request')
def test_021_update_account_pb_success(mock_request, mock_token):
    from utils.util import update_account_pb
    mock_token.return_value = "Bearer xyz......."
    mock_request.return_value = MockResponse(status_code=200, text="{}")
    assert update_account_pb("", [], [], [], []) is None


@patch('utils.util.generate_azure_oauth2_token')
@patch('utils.util.execute_request')
def test_022_update_account_pb_fail(mock_request, mock_token):
    from utils.util import update_account_pb
    mock_token.return_value = "Bearer xyz......."
    mock_request.return_value = MockResponse(status_code=400, text="{}")
    with pytest.raises(Exception) as ex_info:
        update_account_pb("", [], [], [], [])
    assert "Failed to update account pb" in ex_info.value.args[0]


def test_023_get_aws_service_map_success():
    from utils.util import get_aws_service_map
    result = get_aws_service_map()
    assert "Amazon Comprehend" in str(result)


def test_024_validate_action_format_success():
    from utils.util import validate_action_format
    result = validate_action_format(action="random")
    assert result is False


def test_025_validate_action_format_success():
    from utils.util import validate_action_format
    result = validate_action_format(action="EC2:!@Action")
    assert result is False


def test_026_validate_action_format_success():
    from utils.util import validate_action_format
    result = validate_action_format(action="ec2:Action")
    assert result is True
