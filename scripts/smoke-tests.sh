#!/usr/bin/env bash

# primitive smoke test

# service queries
griffon service queries component-manifest  --purl "pkg:oci/ubi8-minimal-container@sha256:7679eaafa608171dd159a91529804d06fa0fbc16a2ea7f046a592a5d8e22c649?repository_url=registry.redhat.io/ubi8-minimal&tag=8.8-315"
griffon service queries components-affected-by-cve --cve-id CVE-2023-25166 --type NPM
griffon service queries components-contain-component --purl "pkg:rpm/redhat/zlib@1.2.11-21.el8_7?arch=x86_64"
griffon service queries product-all-components --name ossm-2.3
griffon service queries product-components --ofuri o:redhat:openshift:4.8.z
griffon service queries product-contain-component --name is-svg
griffon service queries product-manifest --name ansible_automation_platform-2.2
griffon service queries product-manifest --name ansible_automation_platform-2.2
griffon service queries product-summary --ofuri o:redhat:rhel:8.7.0.z
griffon service queries product-summary --name ansible_automation_platform-2.2
griffon service queries products-affected-by-cve --cve-id CVE-2023-25166

# list all components with name 'curl'
griffon entities components list --name curl

# get specific flaw
griffon entities flaws get --cve-id CVE-2023-25166

# get OCI components from ansible_automation_platform-2.2
griffon entities components list --ofuri o:redhat:ansible_automation_platform:2.2 --type OCI

# generate example report
griffon service reports affects