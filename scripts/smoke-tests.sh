#!/usr/bin/env bash

# primitive smoke test

# service queries
griffon service queries component-manifest  --purl "pkg:oci/ubi8-minimal-container@sha256:7679eaafa608171dd159a91529804d06fa0fbc16a2ea7f046a592a5d8e22c649?repository_url=registry.redhat.io/ubi8-minimal&tag=8.8-315"
griffon service queries components-affected-by-cve --cve-id CVE-2023-25166 --type NPM
griffon service queries components-contain-component --purl "pkg:rpm/redhat/zlib@1.2.11-21.el8_7?arch=x86_64"
griffon service queries product-all-components --name ossm-2.3
griffon service queries product-components --ofuri o:redhat:openshift:4.8.z
griffon service queries product-components --name rhel-9.0.0.z
griffon service queries product-contain-component --name is-svg
griffon service queries product-manifest --name ansible_automation_platform-2.2
griffon service queries product-manifest --name ansible_automation_platform-2.2
griffon service queries product-summary --ofuri o:redhat:rhel:8.7.0.z
griffon service queries product-summary --name ansible_automation_platform-2.2
griffon service queries products-affected-by-cve --cve-id CVE-2023-25166

griffon --format text service queries product-contain-component --name is-svg
griffon --format text service queries components-affected-by-cve --cve-id CVE-2023-25166
griffon --format text service queries product-contain-component --name nmap

# reports
griffon service reports affects

# products
griffon entities product-streams get --name pipelines-1.6.2
griffon entities product-streams list --re-name ansible

# components
griffon entities components list --name curl
griffon entities components list --name curl --namespace UPSTREAM
griffon entities components get --purl "pkg:rpm/redhat/vim@8.2.2637-16.el9_0.3?arch=src&epoch=2"
griffon entities components get-manifest --purl "pkg:rpm/curl@7.76.1"
griffon entities components list --ofuri o:redhat:ansible_automation_platform:2.2 --type OCI
griffon --format text entities components list --name curl

# flaws
griffon entities flaws get --cve-id CVE-2023-25166
griffon entities flaws list --state NEW --impact CRITICAL

# affects
griffon entities affects list --affectedness AFFECTED --impact CRITICAL

# trackers
griffon entities trackers list --help

# manage
griffon manage corgi health

# plugins
griffon z_go_vuln get --cve-id CVE-2018-16873
griffon z_osv query-by-commit-hash --commit_hash 6879efc2c1596d11a6a6ad296f80063b558d5e0f
