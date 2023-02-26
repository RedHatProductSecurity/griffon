Feature: Griffon depcli

       Scenario: Retrieve a product streams latest components

     Given a set of product_streams
        | product_stream                  | count |
        | rhel-9.0.0.z                    | 2047  |
        | ansible_automation_platform-2.2 | 246   |
        | devtools-compilers-2023-2       | 15    |

    Then running > griffon --format json service product-components --name rhel-9.0.0.z should find following latest components
        | component                                                      |
        | pkg:rpm/redhat/xrestop@0.4-29.el9?arch=src                     |
        | pkg:rpm/redhat/xsane@0.999-42.el9?arch=src                     |
        | pkg:rpm/redhat/xterm@366-8.el9?arch=src                        |
        | pkg:rpm/redhat/xz@5.2.5-8.el9_0?arch=src                       |

    Then running > griffon --format json service product-components --name ansible_automation_platform-2.2 should find following latest components
        | component                                                      |
        | pkg:rpm/redhat/python3x-rich@12.0.0-1.el8ap?arch=src           |
        | pkg:rpm/redhat/python3x-rq@1.10.1-1.el8ap?arch=src             |
        | pkg:rpm/redhat/python3x-rq-scheduler@0.10.0-1.el8ap?arch=src   |
        | pkg:rpm/redhat/python3x-rsa@4.6-1.el8ap?arch=src               |
        | pkg:rpm/redhat/python3x-ruamel-yaml@0.17.21-1.el8ap?arch=src   |

    Then running > griffon --format json service product-components --name devtools-compilers-2023-2 should find following latest components
        | component                                                      |
        | pkg:rpm/redhat/go-toolset-1.19@1.19.4-1.el7_9?arch=src         |
        | pkg:rpm/redhat/go-toolset-1.19-delve@1.9.1-1.el7_9?arch=src    |
        | pkg:rpm/redhat/go-toolset-1.19-golang@1.19.4-1.el7_9?arch=src  |
        | pkg:rpm/redhat/llvm-toolset-15.0@15.0.7-1.el7_9?arch=src       |

    Then running > griffon --format text service product-components --name devtools-compilers-2023-2 should find following latest components
        | component                        |
        | go-toolset-1.19 1.19.4-1.el7_9   |
        | llvm-toolset-15.0-compiler-rt    |
        | rust-toolset-1.66-rust           |

   Scenario: Determine which product versions a component exists in

    Given a set of product_streams
        | product_stream                  | count |
        | rhel-9.0.0.z                    | 2047  |
        | ansible_automation_platform-2.2 | 246   |
        | devtools-compilers-2023-2       | 15    |

    Then running > griffon --format text service products-contain-component nmap should find following product_versions
        | output            |
        | rhel-6 (nmap)     |
        | rhel-7 (nmap)     |
        | rhel-8 (nmap)     |
        | rhel-9 (nmap)     |

    Then running > griffon --format text service products-contain-component webkitgtk should find following product_versions
        | output                   |
        | rhel-6 (webkitgtk)       |
        | rhel-6 (pywebkitgtk)     |
        | rhel-7 (webkitgtk4)      |
        | rhel-7 (webkitgtk3)      |

    Then running > griffon --format text service products-contain-component ^webkitgtk(\d)$ should find following product_versions
        | output                   |
        | rhel-7 (webkitgtk4)      |
        | rhel-7 (webkitgtk3)      |

    Then running strict search > griffon --format text service products-contain-component -s webkitgtk should find following product_versions
        | output                   |
        | rhel-6 (webkitgtk)       |

    Then running > griffon --format text service products-contain-component grafana-container should find following product_versions
        | output                                                 |
        | ceph-4 (grafana-container)                             |
        | ceph-4 (grafana-container-source)                      |
        | ceph-5 (grafana-container)                             |
        | ceph-5 (grafana-container-source)                      |
        | openshift-4 (grafana-container)                        |
        | openshift-4 (grafana-container-source)                 |
        | openshift-enterprise-3.11 (grafana-container)          |
        | openshift-enterprise-3.11 (grafana-container-source)   |
        | rhacm-2 (acm-grafana-container)                        |
        | rhacm-2 (acm-grafana-container-source)                 |

#    Then running > griffon --format text service products-contain-component github.com/go-redis/redis/v8/internal/hscan should find following product_streams
#        | output                   |
