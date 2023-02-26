## Tutorial




## Service operations

Read only service operations

```commandline
> griffon service queries

Usage: griffon service queries [OPTIONS] COMMAND [ARGS]...

  Service operations that are read only.

Options:
  --help  Show this message and exit.

Commands:
  exp                             Experimental queries.
  get-product                     Get Product Stream summary (DEP1US7)
  get-product-components          Get Product Stream latest components...
  get-product-contain-component   List products containing component.
  get-product-manifest            Get Product Stream manifest (DEP1US7).
  get-product-shipped-components  (FUTURE DEV) Get Product Stream shipped...

```

To retrieve summary of a product:
```commandline
> griffon service queries get-product --name rhel-9.1.0.z
```
To retrieve a products latest components:
```commandline
> griffon service queries get-product-components --name ansible_automation_platform-2.1 | jq ".results[].purl"
```
Retrieve components affected by a specific CVE (note this is still under development):
```commandline
> griffon service queries exp components-affected-by-cve --cve-id CVE-2022-43404
```
List products a component exists in use the _get-product-contain-component_, for example for **is-svg** component
```commandline
> griffon service queries get-product-contain-component --name is-svg | jq '.results[].name' | sort | uniq
```
Another example retrieving product ofuris for **nmap**:
```commandline
> griffon service queries get-product-contain-component --name nmap | jq ".results[].ofuri" 
```
List products a specific component exists in, supply its purl:
```commandline
> griffon service queries get-product-contain-component --purl "pkg:npm/is-svg@2.1.0" | jq ".product_streams[].name" | sort | uniq 
```

Retrieve CVEs affecting a product version (note this is still under development):
```commandline
> griffon service queries exp cves-for-product-version --name ansible_automation_platform-2 --affectedness AFFECTED --flaw-state NEW
```

Service operations that update entities.

```commandline
> griffon service process

Usage: griffon service process [OPTIONS] COMMAND [ARGS]...

  Mutation operations.

Options:
  --help  Show this message and exit.

Commands:
  generate_affects_for_component  Generate affects for component.

```
TBD


## Entity operations

Low level (ex. list, get, CRUD) entity operations.

```commandline
> griffon entities
Usage: griffon entities [OPTIONS] COMMAND [ARGS]...

  List and retrieve entities operations.

Options:
  --help  Show this message and exit.

Commands:
  affects          https://<OSIDB_API_URL>/osidb/api/v1/affects
  components       https://<CORGI_API_URL>/api/v1/components
  flaws            https://<CORGI_API_URL>/osidb/api/v1/flaws
  product-streams  ...
  trackers         https://<CORGI_API_URL>/osidb/api/v1/trackers

```

Entity operations return full blooded data entities ... 

#### Flaws (CVEs)
Retrieve a CVE
```commandline
> griffon entities flaws get --cve-id CVE-2023-0229
```
Retrieve a list of CVEs
```commandline
>griffon entities flaws list --state NEW --impact CRITICAL | jq ".results[].cve_id"
```
#### Affects

Retrieve a list of affects:
```commandline
> griffon entities affects list --affectedness AFFECTED --type NEW
```

#### Trackers

#### Components

Retrieve a specific component:
```commandline
> griffon entities components get --purl "pkg:rpm/redhat/curl@7.29.0-19.el7?arch=aarch64" 
```
**Note** - purl are URI and they need to be quoted.

Retrieve list of components by name
```commandline
> griffon entities components list --name curl | jq '.results[].purl'
```
Search for components by regular expression name (and version):
```commandline
> griffon entities components list --re_name ansible --version 1.1.1
```
#### Product Streams
Retrieve a product
```commandline
> griffon entities product-streams get --ofuri o:redhat:openshift:4.11.z
```
Retrieve a product manifest
```commandline
griffon entities product-streams get-manifest --name ansible_automation_platform-2.2 
```

## Notes

#### Some Useful questions to answer

* Which unfixed CVE are affecting a component?
* Which unfixed CVE are affecting a product + version + stream?
* Given a CVE ID, what products are affected?
* Given a CVE ID, what components are affected?
* What products + version + stream contain a given component (e.g. full text search)? 
* What are the fixed CVEs for a product + version + stream?
* What are the fixed CVEs for a component?
* What are the won’t fix CVEs for a component?
* What are the won’t fix CVEs for a product?
* How many CVE’s are filed against a product + version

