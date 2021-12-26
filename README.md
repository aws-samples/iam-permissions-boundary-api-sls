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
├── disable_pb_exceptions                  <-- Disable Account PB Exceptions Lambda
├── docs                                   <-- Documentation
├── enable_pb_exceptions                   <-- Enable Account PB Exceptions Lambda
├── utils                                  <-- Functions shared by multiple Lambdas
├── verify_pb_exceptions                   <-- Verify Account PB Exceptions Lambda
├── Pipfile                                <-- Python dependencies
├── package.json                           <-- Serverless frameowrk dependencies
└── serverless.yml                         <-- Serverless application definition file
```

## Access

### Authentication

Generate Azure AD OAuth2 token with the given details:

```
1. User API Call:
 
    Grant Type: Implicit     
    Auth Url: https://login.microsoftonline.com/its.test-org.com/oauth2/v2.0/authorize
    Callback Url: http://localhost
    Client ID: 
        - Development: 099345f5-eeff2927a47f6b1e
        - QA         : ec875ddf-8706-905a6414cfdb
        - Production : 23eeb67-b7e5-e56b2bafdd78
    Application Scope:
        - Development: https://clx-awsapi-exception-dev.test_org.com/user_impersonation
        - QA         : https://clx-awsapi-exception-qa.test_org.com/user_impersonation
        - Production : https://clx-awsapi-exception-prod.test_org.com/user_impersonation

1. App API Call:
 
    Grant Type: Client Credentials     
    Access Token Url: https://login.microsoftonline.com/its.test-org.com/oauth2/v2.0/token
    Client ID: client id of consumer app.
    Client Secret: client secret of consumer app.
    Application Scope:
        - Development: https://clx-awsapi-exception-dev.test-org.com/.default
        - QA         : https://clx-awsapi-exception-qa.test-org.com/.default
        - Production : https://clx-awsapi-exception-prod.test-org.com/.default

```

### Authorization

#### User
To access the API, user need to be part of at-least one of the following groups:

* ITS-EP-APP-ITxVPCx-ITxAdmins
* ITS-EP-APP-ITxVPCx-ITxMonitors

#### Application
To access the API, consumer application should have 'writer' role access over 'clx-awsapi-exception-{env}' app. 

## Endpoints
```

Lambda Endpoints:
    Verify Account PB Exception:  POST /account/exceptions/pb-exception/verify 
    Enable Account PB Exception:  POST /account/exceptions/pb-exception/enable 
    Disable Account PB Exception: DELETE /account/exceptions/pb-exception/disable 

```

## Example Usage
```bash
curl -X GET 
     -H 'Content-Type: application/json' 
     -H 'Authorization: Bearer AMvcMSfZoAHnlXX0cAIhAKsJx8Pp...'
     -d '{"project_id": "itx-016","exception_actions": ["backup:*"]}' 
     https://internal-ServiceEnablerALB-2934.us-east-1.elb.amazonaws.com/account/exceptions/pb-exception/enable
```

## Local env setup
```
pipenv install # Install main dependencies
pipenv install --dev # Install dev dependencies
```

## Test
```
pytest ./
```

## BDD

```
behave <app>/test/bdd/
```

## Deployment

```
# Install dependencies from package.json
npm i

# Deploy application
serverless deploy -s dev --force
```

## OpenAPI Spec

The OpenAPI spec for the API is located at [docs/openapi.yml](docs/openapi.yml)

## License

This library is licensed under the MIT-0 License. See the LICENSE file.