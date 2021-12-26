Feature: Verify PB Exceptions API

  Scenario: Positive Scenario - pb exception is applied
    Given the api "/account/exceptions/pb-exception/verify" exists
    And an authorized user exists
    And payload contains "backup:*" for exception verification
    When verify pb exception api is invoked
    Then api returns a response code of 200
    And response contains a message "'pb_exceptions' applied for actions"
    And the accounts metadata has action "backup:*" in pb_exceptions
    And the permission boundary has action "backup:*" set

  Scenario: Negative Scenario - action not present in account metadata
    Given the api "/account/exceptions/pb-exception/verify" exists
    And an authorized user exists
    And payload contains "random:*" for exception verification
    When verify pb exception api is invoked
    Then api returns a response code of 404
    And response contains a message "Actions '['random:*']' not found in 'pb_exceptions' for account"
    And the accounts metadata does not have action "random:*" in pb_exceptions

  Scenario: Negative Scenario - unauthorized user
    Given the api "/account/exceptions/pb-exception/verify" exists
    And an unauthorized user exists
    And payload contains "backup:*" for exception verification
    When verify pb exception api is invoked
    Then api returns a response code of 401