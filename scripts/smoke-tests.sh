#!/usr/bin/env bash

set -x

# primitive smoke test

# service queries
#griffon service component-manifest --purl "pkg:oci/ubi8-minimal-container@sha256:7679eaafa608171dd159a91529804d06fa0fbc16a2ea7f046a592a5d8e22c649?repository_url=registry.redhat.io/ubi8-minimal&tag=8.8-315"
griffon service components-affected-by-flaw CVE-2023-25166 --type NPM
griffon service components-contain-component --purl "pkg:rpm/redhat/zlib@1.2.11-21.el8_7?arch=x86_64"
griffon service product-components --ofuri o:redhat:openshift:4.8.z
griffon service product-components rhel-9.0.0.z
griffon service products-contain-component is-svg
griffon service product-manifest ansible_automation_platform-2.2
#griffon service product-summary --ofuri o:redhat:rhel:8.7.0.z
griffon service product-summary ansible_automation_platform-2.2
griffon service products-affected-by-flaw CVE-2023-25166

griffon --format text service products-contain-component -r "^webkitgtk(\d)$"
griffon --format text service components-affected-by-flaw CVE-2023-25166
griffon --format text service products-contain-component -s nmap
# should fail
griffon service products-contain-component --purl "pkg:rpm/curl@7.29.0"

griffon service products-contain-component webkitgtk --search-related-url --search-latest --search-all

griffon service component-summary curl

# TODO - RE-ENABLE !
#griffon service products-contain-component --search-community --search-all curl

griffon -vvv service products-contain-component -a libtiff

# reports
griffon service report-affects

# products
griffon entities component-registry product-streams get pipelines-1.6.2
griffon entities component-registry product-streams list ansible
griffon entities component-registry products list --limit 1000
griffon entities community-component-registry products list --limit 1000
griffon entities component-registry product-versions list ansible

# components
# TODO - RE-ENABLE
#griffon entities component-registry components list curl
#griffon entities community-component-registry components list curl
griffon entities component-registry components list curl --namespace UPSTREAM
griffon entities component-registry components get --purl "pkg:rpm/redhat/vim@8.2.2637-16.el9_0.3?arch=src&epoch=2"
griffon entities component-registry components manifest --purl "pkg:rpm/curl@7.76.1"
griffon entities component-registry components list --ofuri o:redhat:ansible_automation_platform:2.2 --type OCI

# flaws
griffon entities osidb flaws get --id CVE-2023-25166
griffon entities osidb flaws list --impact MODERATE --affects--ps-component redis

# affects
griffon entities osidb affects list --affectedness AFFECTED --impact CRITICAL

# trackers
griffon entities osidb trackers list --help

# manage
griffon entities component-registry admin health
griffon entities osidb admin status

# plugins
griffon plugins go_vuln get --cve-id CVE-2018-16873
griffon plugins osv query-by-commit-hash --commit_hash 6879efc2c1596d11a6a6ad296f80063b558d5e0f

# reports
griffon service report-entities
griffon service report-license gitops-1.6.z

# other
griffon service products-contain-component 1to2 --search-upstreams --include-inactive-product-streams
griffon service products-contain-component goutils --search-all -a
griffon service products-contain-component -s zlib -vvv
griffon service product-flaws cost-management --affectedness AFFECTED --affect-resolution FIX
griffon service component-flaws npm
griffon service component-flaws python-marshmallow --affectedness AFFECTED
griffon service products-contain-component --search-all --search-upstreams -s libxml2 -a
griffon service products-contain-component -s grep -v --search-all
griffon service products-contain-component -r 'webkit.tk' -vv
griffon service products-contain-component -r "webkitgtk(3|100)" --search-all
griffon service products-contain-component webkitgtk4-jsc --include-product-streams-excluded-components --include-inactive-product-streams --no-community --no-filter-rh-naming -vv

griffon service products-contain-component -s bind-libs-lite --search-all
griffon service products-contain-component v2v-conversion-host-ansible  -vvv --include-container-roots --include-inactive-product-streams --include-product-streams-excluded-components --no-filter-rh-naming
griffon service products-contain-component 'compat-sap-c++-12'
griffon service products-contain-component -r 'compat-sap-c\+\+-12'
#griffon service products-contain-component -s 'compat-sap-c++-12'
griffon service products-contain-component runc
griffon service products-contain-component github.com/go-redis/redis/v8/internal/hscan      --include-container-roots --include-inactive-product-streams --no-filter-rh-naming --include-product-streams-excluded-components
griffon service products-contain-component pdf-generator -vvv --include-container-roots
griffon service products-contain-component -s wireshark -v
griffon service products-contain-component "hypershift-cloudwatch-loggging" --include-container-roots

time griffon service products-contain-component desktop-file-utils -vv --no-filter-rh-naming --include-container-roots
