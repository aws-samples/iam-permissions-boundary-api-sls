# Centralized Permissions Boundary API
This Serverless application deploys an API to enable, remove and verify permission boundary exceptions for an AWS account.
* IAM Permission Boundary policies enable/restrict AWS account user permissions to use a particular service in the account.
* IAM Permission Boundary policy is updated as part of a service release/enablement, 
  but some times users require exceptions to use certain services in specific accounts that have not yet been released/enabled. 
* This API automates the enable/remove function of Permission Boundary policies across accounts in a multi-account AWS Organizations implementation.

```
.
├── README.md                              <-- This documentation file
├── config                                 <-- Configurations for each environment
├── disable_pb_exceptions                  <-- Disable Account Permission Boundary Exceptions Lambda
├── docs                                   <-- Documentation
├── enable_pb_exceptions                   <-- Enable Account Permission Boundary Exceptions Lambda
├── utils                                  <-- Functions shared by multiple Lambdas
├── verify_pb_exceptions                   <-- Verify Account Permission Boundary Exceptions Lambda
├── Pipfile                                <-- Python dependencies
├── package.json                           <-- Serverless frameowrk dependencies
└── serverless.yml                         <-- Serverless application definition file
```

## Endpoints

```
Lambda Endpoints:
    Verify Account Permission Boundary Exception:  POST /account/exceptions/pb-exception/verify 
    Enable Account Permission Boundary Exception:  POST /account/exceptions/pb-exception/enable 
    Disable Account Permission Boundary Exception: DELETE /account/exceptions/pb-exception/disable 
```

## Local env setup and configuration

```shell script
# Install Python3.6, Pip3, Nodejs >= v14

# Install python dependencies
pipenv install
pipenv install --dev # Install dev dependencies

# Install Serverless framework
cd iam-permissions-boundary-api-sls
npm i -g serverless

# Install Serverless dependencies
npm i

# Install serverless plugins; python 3.6 should already be installed
serverless plugin install -n serverless-python-requirements
serverless plugin install -n serverless-deployment-bucket

# Configure AWS named profile
aws configure --profile default 

```

## Unit Test
```shell script
# Run unit tests
pytest ./
```

## Deployment
```shell script
# Deploy API
serverless deploy -s dev
```

## Integration Test
```shell script
# Run integration tests
behave enable_pb_exceptions/tests/bdd/
behave disable_pb_exceptions/tests/bdd/
behave verify_pb_exceptions/tests/bdd/
```

## OpenAPI Spec
The OpenAPI spec for the API is located at [docs/openapi.yml](docs/openapi.yml)

## Example Usage
```bash
curl -X GET 
     -H 'Content-Type: application/json' 
     -H 'Authorization: Bearer AMvcMSfZoAHnlXX0cAIhAKsJx8Pp...'
     -d '{"project_id": "itx-016","exception_actions": ["backup:*"]}' 
     https://internal-ServiceEnablerALB-2934.us-east-1.elb.amazonaws.com/account/exceptions/pb-exception/enable
```

## License
This library is licensed under the MIT-0 License. See the LICENSE file.
