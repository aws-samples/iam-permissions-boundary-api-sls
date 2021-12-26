"""Module contains steps for behave execution"""
# pylint: skip-file
from behave import given, then
from cloudx_sls_authorization.create_token import get_bearer_token
from utils.util import get_account_by_project_id_gql, get_account_pb, update_account_pb, update_account_pb_exception_gql


@given(u'the api "{url}" exists')
def api_exists(context, url):
    """API exists"""
    context.target_url = url
    context.payload = {}


@given('an {auth_type} user exists')
def auth_token(context, auth_type):
    """Token Auth"""
    if auth_type == "authorized":
        # Context attribute should contain service_scope and api_client.
        context.token = get_bearer_token(
            client_key=context.app_client_id,
            client_secret=context.app_client_secret,
            token_url=context.oauth2_token_url,
            scope=context.app_default_scope
        )
    else:
        context.token = "invalid_token"


@given('payload contains "{action}" for exception {operation}')
def set_payload(context, action, operation):
    context.payload = {
        "exception_actions": [
            action
        ],
        "project_id": context.project_id
    }


@given('the accounts metadata {verb} action "{action_name}" in pb_exceptions')
def update_pb_exceptions(context, verb, action_name):
    account_details = get_account_by_project_id_gql(
        project_id=context.project_id
    )
    pb_exceptions = account_details.get("pb_exceptions") if account_details.get("pb_exceptions") else []
    exc_len = len(pb_exceptions)
    rec_id = account_details.get("id")
    if verb == 'has' and action_name not in pb_exceptions:
        pb_exceptions.append(action_name)
    elif verb == 'does not have' and action_name in pb_exceptions:
        pb_exceptions.remove(action_name)
    if len(pb_exceptions) != exc_len:
        update_account_pb_exception_gql(
            rec_id=rec_id,
            pb_exceptions=pb_exceptions
        )


@given('the permission boundary {verb} action "{action_name}" set')
def update_pb(context, verb, action_name):
    account_details = get_account_by_project_id_gql(
        project_id=context.project_id
    )
    pb_exceptions = account_details.get("pb_exceptions") if account_details.get("pb_exceptions") else []
    ec2_security_groups = (
        account_details.get("ec2_security_groups", []) if account_details.get("ec2_security_groups") else []
    )
    regions = (
        account_details.get("regions", []) if account_details.get("regions") else []
    )
    services = (
        account_details.get("services", []) if account_details.get("services") else []
    )
    if verb == 'has' and action_name not in pb_exceptions:
        pb_exceptions.append(action_name)
    elif verb == 'does not have' and action_name in pb_exceptions:
        pb_exceptions.remove(action_name)
    update_account_pb(
        project_id=context.project_id,
        regions=regions,
        services=services,
        pb_exceptions=pb_exceptions,
        ec2_sgs=ec2_security_groups
    )


@then('api returns a response code of {status_code}')
def validate_status_code(context, status_code):
    assert int(status_code) == context.status_code


@then('response contains a message "{msg}"')
def validate_response_message(context, msg):
    assert msg in context.response_data.get("message")


@then('the accounts metadata {verb} action "{action_name}" in pb_exceptions')
def validate_response(context, verb, action_name):
    account_details = get_account_by_project_id_gql(
        project_id=context.project_id
    )
    if verb == 'has':
        assert action_name in account_details.get("pb_exceptions")
    elif verb == 'does not have':
        assert action_name not in account_details.get("pb_exceptions")
    else:
        assert False


@then('the permission boundary {verb} action "{action_name}" set')
def validate_response(context, verb, action_name):
    pb_document = get_account_pb(
        project_id=context.project_id,
        account_number=context.account_num
    )
    allowed_pb_actions = []
    for statement in pb_document.get("Statement", []):
        if statement.get("Sid", "") == "PermittedServiceActions":
            allowed_pb_actions = statement.get("Action", [])
            break
    if verb == 'has':
        assert action_name in allowed_pb_actions
    elif verb == 'does not have':
        assert action_name not in allowed_pb_actions
    else:
        assert False
