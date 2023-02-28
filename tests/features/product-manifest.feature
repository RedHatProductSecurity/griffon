Feature: product-manifest

    Scenario: Retrieve a product manifest

    Given running > griffon --format json service product-manifest ansible_automation_platform-2.3 should return manifest.
