#!/usr/bin/env bash

# primitive smoke test

# get product summary for ansible_automation_platform-2.2
griffon service queries get-product --name ansible_automation_platform-2.2

# get rhel-8.7.0.z product summary
griffon service queries get-product --ofuri o:redhat:rhel:8.7.0.z

# list all components with name 'curl'
griffon entities components list --name curl

# get specific flaw
griffon entities flaws get --cve-id CVE-2023-25166

# list components affected by specific CVE
griffon service queries components-affected-by-cve --cve-id CVE-2023-25166 --type NPM

# list products affected by specific CVE
griffon service queries products-affected-by-cve --cve-id CVE-2023-25166

# list latest product components
griffon service queries get-product-components --ofuri o:redhat:openshift:4.8.z

# retrieve product manifest for ansible_automation_platform-2.2
griffon service queries get-product-manifest --name ansible_automation_platform-2.2

# return products containing 'is-svg'
griffon service queries get-product-contain-component --name is-svg

# get OCI components from ansible_automation_platform-2.2
griffon entities components list --ofuri o:redhat:ansible_automation_platform:2.2 --type OCI

# generate example report
griffon service reports affects