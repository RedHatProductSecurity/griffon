# ![](docs/image/griffon.jpg) Ǥriffon

**WARNING- NOT PROD (yet), no releases, if you use this you are running with scissors ...**  

Red Hat Product Security CLI providing:

* Set of core entity operations on flaws, affects, components, products, etc... for 
searching, listing and retrieving entities.
* Set of read only query service operations answering 'canned' product security related queries
* Set of process service operations (mutation) automating away manual 'drudgery'
* Dynamic, extensible set of custom plugin operations for interacting with external services 

The CLI provides a simple 'facade' over coarse grained security related data services allowing 
for easier aggregation and narrowing of information providing a good security 'signal' 
for end users.


```commandline
Usage: griffon [OPTIONS] COMMAND [ARGS]...

  Red Hat Product Security CLI

Options:
  --debug
  --help   Show this message and exit.

Commands:
  docs           Links to useful docs.
  entities       List and retrieve entities operations.
  manage         Manage operations.
  process        Process operations.
  queries        Query operations.
  z_fcc          FCC plugin
  z_osv          OSV plugin


```

[User guide (quickstart)](docs/user_guide.md)

[Tutorial](docs/tutorial.md)

[Developer guide](docs/developer_guide.md)


## Entity operations

Low level (ex. list, get) entity operations.

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

## Query operations

Read only service operations

```commandline
Usage: griffon queries [OPTIONS] COMMAND [ARGS]...

  Query operations.

Options:
  --help  Show this message and exit.

Commands:
  component_cves                  List CVEs affecting a component.
  components_affected_by_cve      List components affected by CVE.
  components_in_product_stream    List components of product version.
  cves_for_product_version        List CVEs of a product version.
  product_versions_affected_by_cve
                                  List product versions affected by a CVE.

```

## Process operations

Service operations that update entities.

```commandline
Usage: griffon process [OPTIONS] COMMAND [ARGS]...

  Mutation operations.

Options:
  --help  Show this message and exit.

Commands:
  generate_affects_for_component  Generate affects for component.

```

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
