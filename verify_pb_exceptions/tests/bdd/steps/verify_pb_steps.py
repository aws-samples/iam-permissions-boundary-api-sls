"""Module contains steps for behave execution"""
# pylint: skip-file
import json
from behave import when
from utils.bdd_utils import common_steps


@when('verify pb exception api is invoked')
def verify_api(context):
    """verify api"""
    try:
        url = context.target_url
        response = context.execute_request(
            ''.join((context.api_endpoint, url)),
            method='post',
            additional_payload=context.payload,
            additional_headers={
                'Authorization': ''.join(('Bearer ', context.token))
            }
        )
        context.status_code = response.status_code
        context.response_data = json.loads(response.text)
        print(f"Print Response Data - {str(context.response_data)}")
        context.logger.info(f"Response Data - {str(context.response_data)}")
    except Exception as ex:
        context.logger.error(
            f"Failed to Verify PB Exceptions. Error Details - '{str(ex)}'"
        )
        raise ex
