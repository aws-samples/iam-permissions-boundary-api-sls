Feature: Enable PB Exceptions API

  Scenario: Positive Scenario - pb exception applied
    Given the api "/account/exceptions/pb-exception/enable" exists
    And an authorized user exists
    And payload contains "aws-portal:ViewAccount" for exception enablement
    And the accounts metadata does not have action "aws-portal:ViewAccount" in pb_exceptions
    And the permission boundary does not have action "aws-portal:ViewAccount" set
    When enable pb exception api is invoked
    Then api returns a response code of 200
    And response contains a message "Successfully updated 'pb_exceptions' for account"
    And the accounts metadata has action "aws-portal:ViewAccount" in pb_exceptions
    And the permission boundary has action "aws-portal:ViewAccount" set

  Scenario: Negative Scenario - invalid action
    Given the api "/account/exceptions/pb-exception/enable" exists
    And an authorized user exists
    And payload contains "random_action" for exception enablement
    And the accounts metadata does not have action "random_action" in pb_exceptions
    And the permission boundary does not have action "random_action" set
    When enable pb exception api is invoked
    Then api returns a response code of 400
    And response contains a message "Invalid Action."
    And the accounts metadata does not have action "random_action" in pb_exceptions
    And the permission boundary does not have action "random_action" set

  Scenario: Negative Scenario - unauthorized user
    Given the api "/account/exceptions/pb-exception/enable" exists
    And an unauthorized user exists
    And payload contains "aws-portal:ViewAccount" for exception enablement
    When enable pb exception api is invoked
    Then api returns a response code of 401