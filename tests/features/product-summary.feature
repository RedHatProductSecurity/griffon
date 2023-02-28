Feature: product-summary

    Scenario: Retrieve a product summary

    Given running strict search > griffon --format text service product-summary -s rhel-7.6.z should find following product
        | product                                                     |
        | rhel-7.6.z                                                  |

    Given running > griffon --format text service product-summary rhel should find following products
        | product                                                     |
        | convert2rhel-8                                              |
        | rhel-6-els                                                  |
        | rhel-7.4.z                                                  |
        | rhel-7.6.z                                                  |
        | rhel-7.7.z                                                  |
        | rhel-7.9.z                                                  |
        | rhel-8.1.0.z                                                |
        | rhel-9.0.0.z                                                |
        | rhel-9.1.0.z                                                |
        | rhel-br-8.4.0.z                                             |
        | rhel-br-8.6.0.z                                             |
        | rhel-br-9                                                   |
        | rhel-br-9.0.0.z                                             |

    Given running > griffon --format text service product-summary ^convert(\d)rhel-(\d)$ should find following products
        | product                                                     |
        | convert2rhel-8                                              |
