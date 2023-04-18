## Tutorial 

Best to first checkout [User guide (quickstart)](https://github.com/RedHatProductSecurity/griffon/tree/main/docs/user_guide.md)

### Configure griffon

To setup _~/.griffonrc_ dotfile and _~/.griffon_ directory run:
> griffon configure setup

The griffon dotfile (_~/.griffonrc_) allows the user to configure operation of griffon

```text
[default]
format = text
history_log = ~/.griffon/history.log
profile = default
verbosity = 0
sfm2_api_url = http://localhost:5600
custom_plugin_dir = ~/.griffon/plugins/
editor = vi
exclude_components = -container-source
	-debuginfo
	-debugsource
	-static
	-common-debuginfo
	-doc

# profile sections (use with --profile {profile} flag)
[cloud]
...
[openshift]
...
[middleware]
...
[latest]
exclude=ansible_automation_platform-1
    cnv-2
    openshift-container-storage-4
    openstack-13
    openstack-16.1
    ossm-2
    ossm-2.1
    rhel-7
    rhscl-3
    rhui-3
    stf-1.3


```
For example, the profile definitions define which Product Versions are excluded from output. In the above, the **latest** profile
(which is the default) would exclude Product Versions such as **openshift-container-storage-4** or **rhel-7** from operation output.
 
To pull the latest version of griffon from pypi.org:
> griffon configure upgrade

### Using griffon

```commandline
> griffon                                   
Usage: griffon [OPTIONS] COMMAND [ARGS]...

  Red Hat Product Security CLI

Options:
  -V, --version                   Display griffon version.
  -d, --debug                     Debug log level.
  -f, --format [json|text|table]  Result format (default is text format).
  -v                              Verbose output, more detailed search
                                  results, can be used multiple times (e.g.
                                  -vvv).
  --no-progress-bar               Disable progress bar.
  --no-color                      Disable output of color ansi esc sequences.
  --profile [default|cloud|openshift|middleware|latest]
                                  Activate profile, defined in .griffonrc.
  --editor / --no-editor          Allow text editor prompt.
  --help                          Show this message and exit.

Commands:
  configure  Configure griffon.
  docs       Links to useful docs.
  entities   Entity operations.
  plugins    3rd party plugins.
  service    Service operations.

```
To activate a specific profile either change .griffonrc default_profile or use --profile flag.

### Service operations

Service operations mediate calls to other services (ex. component registry, vulnerability database) which help answer questions about Products, Components and Flaws.

```commandline
> griffon service                                   
Usage: griffon service [OPTIONS] COMMAND [ARGS]...

  Service operations.

Options:
  --help  Show this message and exit.

Commands:
  component-flaws               List Flaws affecting a Component.
  component-manifest            Get Component manifest.
  component-summary             Get Component summaries.
  components-affected-by-flaw   List Components affected by Flaw.
  components-contain-component  List Components containing Component.
  product-components            List LATEST Root Components of Product.
  product-flaws                 List Flaws affecting a Product.
  product-manifest              Get Product manifest (includes Root...
  product-summary               Get Product summaries.
  products-affected-by-flaw     List Products affected by Flaw.
  products-contain-component    List Products containing Component.
  report-affects                Generate Affects example report.
  report-entities               Generate Entity report (with counts).
  report-license                Generate Product Stream license report.
```

#### Check what Products a Component is shipped in

To find what Products a component exists in  
> griffon service products-contain-component webkitgtk

Use -s flag for stricter search
> griffon service products-contain-component -s webkitgtk

Use regex expressions
> griffon service products-contain-component "^webkitgtk(\d)$"

Use of -v (up to -vvvv) to get more information
```commandline
> griffon service products-contain-component "^webkitgtk(\d)"
> griffon -v service products-contain-component "^webkitgtk(\d)"
> griffon -vv service products-contain-component "^webkitgtk(\d)"
> griffon -vvv service products-contain-component "^webkitgtk(\d)"
> griffon -vvvv service products-contain-component "^webkitgtk(\d)"
```

Find what Products a component exists in, searching both root components and all dependencies
```commandline
> griffon service products-contain-component webkitgtk --search-all
> griffon service products-contain-component github.com/go-redis/redis/v8/internal/hscan --search-all      
```

Find Products that contain Component searching both latest components and related_url
> griffon service products-contain-component webkitgtk --search-latest --search-related-url

Note this is the default setting eg. the following is equivalent.
> griffon service products-contain-component webkitgtk

Find products that contain upstream Components.
> griffon service products-contain-component webkitgtk --search-upstreams

#### Creating and updating affects

To add (missing) affects on a flaw, supply sfm flaw id and set flaw mode to 'add':
> griffon service products-contain-component -s IPMItool --sfm2-flaw-id 2009389 --flaw-mode add
 
To replace affects on a flaw (and overwrite any existing) supply sfm flaw id and set flaw mode to 'replace:
> griffon service products-contain-component -s IPMItool --sfm2-flaw-id 2009389 --flaw-mode replace

#### Retrieving Product and Component manifests

Retrieve a Product latest root Components
> griffon service product-components rhel-9.0.0.z

Retrieve Product manifest containing latest root Components and dependencies
> griffon service product-manifest ansible_automation_platform-2.3 --spdx-json

Retrieve a spdx json formatted Product manifest
> griffon service product-manifest ansible_automation_platform-2.3 --spdx-json

Retrieve a specific component manifest
> griffon service component-manifest --purl "pkg:oci/ubi8-minimal-container@sha256:7679eaafa608171dd159a91529804d06fa0fbc16a2ea7f046a592a5d8e22c649?repository_url=registry.redhat.io/ubi8-minimal&tag=8.8-315" --spdx-json

#### Retrieving Product and Component summaries

Retrieve a Product summary
```commandline
> griffon service product-summary -s rhel-7.6.z
> griffon --format json service product-summary -s rhel-7.6.z
```

Retrieve Component summary
> griffon service component-summary python-marshmallow 

#### Working with flaws

Retrieve a Component flaws
> griffon service component-flaws python-marshmallow 

Retrieve a Product flaws
> griffon service product-flaws ansible_automation_platform-2 --affectedness AFFECTED --affect-resolution FIX

Retrieve Components affected by flaw
> griffon --format text service components-affected-by-flaw CVE-2023-25166

Retrieve Products affected by flaw
> griffon --format text service products-affected-by-flaw CVE-2023-25166

### Entity operations

A set of low level data operations.

```commandline
> griffon entities                
Usage: griffon entities [OPTIONS] COMMAND [ARGS]...

  Entity operations.

Options:
  --open-browser   open browser to service results.
  --limit INTEGER  # of items returned by list operations.
  --help           Show this message and exit.

Commands:
  community-component-registry
  component-registry
  osidb

```

#### Component Registry and Community Component Registry Entities

Currently only provide primitive read only operations.

##### Components

Retrieve a specific component:
```commandline
> griffon entities CORGI components get --purl "pkg:rpm/redhat/curl@7.29.0-19.el7?arch=aarch64" 
```
**Note** - purl are URI and they need to be quoted.

Retrieve a specific Component provides:
```commandline
> griffon entities CORGI components provides --purl "pkg:rpm/redhat/curl@7.29.0-19.el7?arch=aarch64" 
```
Retrieve a specific CORGI Component sources:
```commandline
> griffon entities CORGI components sources --purl "pkg:rpm/redhat/curl@7.29.0-19.el7?arch=aarch64" 
```
Retrieve list of Components by name
```commandline
> griffon entities CORGI components list curl | jq '.results[].purl'
```
Search for Components by regular expression name (and version):
```commandline
> griffon entities CORGI components list --re_name ansible --version 1.1.1
```
##### Product Streams
Retrieve a Product Stream
```commandline
> griffon entities CORGI product-streams get --ofuri o:redhat:openshift:4.11.z
```
List Product Streams
```commandline
> griffon entities CORGI product-streams list rhel
```

Retrieve a Product Stream manifest
```commandline
griffon entities CORGI product-streams get-manifest --name ansible_automation_platform-2.2 
```

#### OSIDB Entities

Low level operations for interacting with OSIDB entities have both read and write functionality.

##### Flaws

Listing flaws

Creating and updating flaw

##### Affects

Listing affects

Creating and updating affects

##### Trackers

Listing trackers

Creating and updating trackers


### Plugin operations

A set of example plugins are provided.
```commandline
> griffon plugins 
Usage: griffon plugins [OPTIONS] COMMAND [ARGS]...

  3rd party plugins.

Options:
  --help  Show this message and exit.

Commands:
  cve_mitre  mitre cve plugin
  cvelib     cvelib plugin
  fcc        FCC plugin
  go_vuln    vuln.go.dev plugin
  osv        OSV plugin
  semgrep    semgrep plugin
```
#### go_vuln

Search go vulnerability database
```commandline
> griffon plugins go_vuln get --id GO-2022-0189
> griffon plugins go_vuln get --cve-id CVE-2018-16873
```

#### osv
Search osv.dev
>griffon plugins osv query-by-commit-hash --commit_hash 6879efc2c1596d11a6a6ad296f80063b558d5e0f
>griffon plugins osv search curl

#### fcc
Search fcc website
> griffon plugins fcc search --fcc-id BCG-E2430A

#### cvelib
Demonstrates how we can integrate existing software libraries like https://github.com/RedHatProductSecurity/cvelib.

### Common questions

Given a CVE ID, what products are affected?
> griffon service products-affected-by-flaw CVE-2023-25166    

Given a CVE ID, what components are affected?
> griffon service components-affected-by-flaw CVE-2023-25166 

What products + version + stream contain a given component (e.g. full
text search)?
```commandline
> griffon service products-contain-component --purl "pkg:rpm/curl@7.15.5"
> griffon service products-contain-component is-svg --search-all
```

Which unfixed CVE are affecting a component ?
> griffon service component-flaws --affectedness AFFECTED webkitgtk

Which unfixed CVE are affecting a product + version + stream ?
> griffon service product-flaws ansible_platform_2

What are the fixed CVE of this a product + version + stream?
> griffon service product-flaws rhel-9 --flaw-state DONE

What are the fixed CVEs for a component?
> griffon service component-flaws webkitgtk --flaw-state DONE

What are the **WONTFIX** CVEs for a component?
> griffon service component-flaws webkitgtk --flaw-resolution WONTFIX

What are the **WONTFIX** CVEs for a product?
> griffon service product-flaws rhel-9 --flaw-resolution WONTFIX

How many CVE’s are filed against a product + version
> griffon service product-flaws rhel-9 | wc -l

How to generate license report for a specific Product Stream ?
> griffon service report-license ansible_automation_platform-2.2

How to generate license report for a specific Component ?
> griffon service report-license --purl "pkg:oci/redhat/ubi9-container@sha256:f6920213ae98d811051a31c80cefc31cd88206ece680f337b7b67f5e4a4fc0fd?arch=aarch64&repository_url=registry.redhat.io/ubi9&tag=9.1.0-1782"
 