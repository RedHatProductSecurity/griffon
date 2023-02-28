Feature: product/component-flaws

    Scenario: Retrieve all flaws for a component

    Given running > griffon --format text service component-flaws is-svg should return list of flaws.

    Scenario: Retrieve all flaws for a product

    Given running > griffon --format text service product-flaws ansible_automation_platform-2 should return list of flaws.
