Feature: product-components

    Scenario: Retrieve a product streams latest components

     Given a set of product_streams
        | product_stream                  | count |
        | rhel-9.0.0.z                    | 2047  |
        | ansible_automation_platform-2.2 | 246   |
        | devtools-compilers-2023-2       | 15    |

    Then running > griffon --format json service product-components rhel-9.0.0.z should find following latest components
        | component                                                      |
        | pkg:rpm/redhat/xrestop@0.4-29.el9?arch=src                     |
        | pkg:rpm/redhat/xsane@0.999-42.el9?arch=src                     |
        | pkg:rpm/redhat/xterm@366-8.el9?arch=src                        |
        | pkg:rpm/redhat/xz@5.2.5-8.el9_0?arch=src                       |

    Then running > griffon --format json service product-components ansible_automation_platform-2.2 should find following latest components
        | component                                                      |
        | pkg:rpm/redhat/python3x-rich@12.0.0-1.el8ap?arch=src           |
        | pkg:rpm/redhat/python3x-rq@1.10.1-1.el8ap?arch=src             |
        | pkg:rpm/redhat/python3x-rq-scheduler@0.10.0-1.el8ap?arch=src   |
        | pkg:rpm/redhat/python3x-rsa@4.6-1.el8ap?arch=src               |
        | pkg:rpm/redhat/python3x-ruamel-yaml@0.17.21-1.el8ap?arch=src   |

    Then running > griffon --format json service product-components devtools-compilers-2023-2 should find following latest components
        | component                                                      |
        | pkg:rpm/redhat/go-toolset-1.19@1.19.4-1.el7_9?arch=src         |
        | pkg:rpm/redhat/go-toolset-1.19-delve@1.9.1-1.el7_9?arch=src    |
        | pkg:rpm/redhat/go-toolset-1.19-golang@1.19.4-1.el7_9?arch=src  |
        | pkg:rpm/redhat/llvm-toolset-15.0@15.0.7-1.el7_9?arch=src       |

    Then running > griffon --format text service product-components devtools-compilers-2023-2 should find following latest components
        | component                        |
        | go-toolset-1.19 1.19.4-1.el7_9   |
        | llvm-toolset-15.0-compiler-rt    |
        | rust-toolset-1.66-rust           |

