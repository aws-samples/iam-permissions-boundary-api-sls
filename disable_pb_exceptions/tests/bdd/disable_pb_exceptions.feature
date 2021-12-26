Feature: Disable PB Exceptions API

  Scenario: Positive Scenario - pb exception applied
    Given the api "/account/exceptions/pb-exception/disable" exists
    And an authorized user exists
    And payload contains "aws-portal:ViewAccount" for exception disablement
    And the accounts metadata has action "aws-portal:ViewAccount" in pb_exceptions
    And the permission boundary has action "aws-portal:ViewAccount" set
    When disable pb exception api is invoked
    Then api returns a response code of 200
    And response contains a message "Successfully updated 'pb_exceptions' for account"
    And the accounts metadata does not have action "aws-portal:ViewAccount" in pb_exceptions
    And the permission boundary does not have action "aws-portal:ViewAccount" set

  Scenario: Negative Scenario - unauthorized user
    Given the api "/account/exceptions/pb-exception/disable" exists
    And an unauthorized user exists
    And payload contains "aws-portal:ViewAccount" for exception disablement
    When disable pb exception api is invoked
    Then api returns a response code of 401