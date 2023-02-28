Feature: products-contain-component

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
