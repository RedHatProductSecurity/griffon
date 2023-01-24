# 1. CLI design

Date: 2023-01-06

## Status

Draft

## Context

Red Hat Product Security provides tooling supporting users security related queries - 
relaying information on security related entities such as vulnerabilities (CVEs/weaknesses)
and affected products and components.

The CLI that integrates with security related data services will provide:

* Set of core entity operations on flaws, affects, components, products, etc... for 
searching, listing and retrieving entities.
* Set of read only query operations answering 'canned' product security related queries
* Set of process operations (mutation) automating away manual 'drudgery'
* Dynamic, extensible set of custom plugin operations for interacting with external services 
* Separate area for management operations of underlying prodsec services (ex. OSIDB, CORGI) 

The CLI provides a simple 'facade' over coarse grained security related data services allowing 
for easier aggregation and narrowing of information providing a good security 'signal' 
for end users.

## CLI Interface Design

The command line interface is navigated as a hierarchichal tree:

```commandline
griffon/
├─ docs/
├─ entities/
│  ├─ flaws
│  ├─ affects
│  ├─ trackers
│  ├─ components
│  ├─ product_versions
│  ├─ product_streams
│  ├─ channels
│  ├─ **TBD**
├─ manage/
│  ├─ osidb
│  ├─ corgi
├─ queries/
│  ├─ component_cves
│  ├─ components_affected_by_cve
│  ├─ components_in_product_stream
│  ├─ cves_for_product_version
│  ├─ product_versions_affected_by_cve
│  ├─ **TBD**
├─ process/
│  ├─ generate_affects_for_component
│  ├─ **TBD**
```
where:

* **docs**      Links to useful docs. 
* **entities**  List and retrieve entities operations. 
* **manage**    Manage operations. 
* **queries**   Service operations that are read only.
* **process**   Service operations which perform mutations/write. 

Running the top level command

```commandline
> griffon
```

will emit available options and sub commands

```commandline
Usage: griffon [OPTIONS] COMMAND [ARGS]...

  Red Hat Product Security CLI

Options:
  --debug
  --help   Show this message and exit.

Commands:
  docs      Links to useful docs.
  entities  List and retrieve entities operations.
  manage    Manage operations.
  process   Service operations that perform mutations/write.
  queries   Service operations that are read only.
  z_fcc     FCC plugin
  z_osv     OSV plugin
```

selecting the **entities** command the user is presented with more sub commands

```**commandline
> griffon entities
```
and more context sensitive help:
```commandline
Usage: griffon entities [OPTIONS] COMMAND [ARGS]...

  List and retrieve entities operations.

Options:
  --open-browser
  --limit INTEGER
  --help           Show this message and exit.

Commands:
  affects          https://osidb.prodsec.redhat.com/osidb/api/v1/affects
  components       https://corgi-stage.prodsec.redhat.com/api/v1/components
  flaws            https://osidb.prodsec.redhat.com/osidb/api/v1/flaws
  product-streams  ...
  trackers         https://osidb.prodsec.redhat.com/osidb/api/v1/trackers
```

and finally we are able to execute an operation, in this case returning all components with the name=component.
```commandline
> griffon entities components list --name curl 
```

Enabling [auto complete](https://click.palletsprojects.com/en/8.1.x/shell-completion/) lets the user easily discover 
options and how to use commands/data.

### Entity operations

Each entity should minimally support:
* list - list a set of entities
* get - retrieving a specific entity 

Some examples with components:

```commandline
griffon entities components list --name curl
```

```commandline
griffon entities components get --uuid
griffon entities components get --nvr
griffon entities components get --purl
```

```commandline
griffon entities flaws list 
```

```commandline
griffon entities flaws get --cve_id 
griffon entities flaws get --uuid 
```

### Service operations

Modules for process/queries operations are explicitly isolated to enable reuse in other applications.

We achieve isolation by enforcing interfaces (python Protocol) which constrain definition
 ensuring the python modules can be easily used in future contexts.

#### Query operations

Perform read only cross service queries answering useful questions, some examples being:

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

For example, to get a list of cves affecting a specific component:
```commandline
> griffon queries component_cves --purl "pkg:rpm/redhat/curl@7.29.0-19.el7?arch=aarch64" --affectedness AFFECTED 
 ```

A set of 'canned' queries masks the complexity of calling up individual services and synthesizing results manually.

#### Process operations

A **process** represents business logic typically resulting in an update of state on service entities.

### Manage operations
A separate entrypoint for management operations is provided as convenience.

In the short term, this area is meant for internal usage for managing core data services.

```commandline
> griffon manage osidb status 
> griffon manage corgi status
```

### Plugins

We **MAY** develop an extensible set of plugins to external services as an 'incubation' area for 
integrating with third party services. This gives the CLI a good 'swiss army knife' utility as
well as help identify integrations with more query/processes leveraging 3rd party services.

A few example plugins are provided, for example, an example plugin integrating with https://osv.dev:

```commandline
> griffon z_osv query-by-commit-hash --commit_hash 6879efc2c1596d11a6a6ad296f80063b558d5e0f

```
Plugins are dynamically 'registered' once they are copied into the griffon/commands/plugins folder
allowing individual end users to develop their own customisations.

## Autocompletion

The python click module [provides](https://click.palletsprojects.com/en/8.1.x/shell-completion/) provides custom shell completion.

We **MAY** enable live autocompletion of data such as CVE-ids, product stream names/ofuris making it easier to use
griffon.

This can be achieved by generation of python module containing static values (ex. griffon/autocomplete/product_stream.py)
or enhancing data services to provide autocompletion endpoints.

## Process flow

A lightweight process flow is defined as follows:

1. CLI validate options/input
2. invoke operation
3. transform and emit output

## Enhance services

Some considerations for enhancing service bindings:

* 'bake in' concurrent service requests (using threads or asyncio)
* component-registry bindings need to be deployed on github and published to PyPI
* component-registry bindings components.retrieve_list needs to support **ofuri**
* retrieve a batch set of components with a list of {uuid|nvr|purl}
* exception handling in bindings
* implement next() in both bindings

In addition, OSIDB needs to implement a 2nd affect type for mapping a single purl 
to a CVE. It is unclear if this 2nd affect type accepts an array of purls or if we desire
a one to one mapping ... impl detail left to the project.

## Logging and Exception handling

Fine grained logging is enabled using --debug flag
```commandline
griffon --debug entities components list --name curl
```

Most expected exceptions revolve around issues with http requests to services.

## Optimising service calls

parallel http requests using thread/asyncio

## Decision(s)

Develop a CLI (provisionally codenamed 'griffon') specifically integrating
with security related entities useful for answering 'day to day' questions as 
well and help automate some manual processes.

Develop open source on github, using github actions for CI, with releases pushed
to PyPI.

Develop CLI using the [click python module](https://click.palletsprojects.com/en/8.1.x/) as main framework.

Ensure process/query services are developed in standalone modules so that their
'business logic' can be easily reused in other contexts to support future tooling.

CLI implementation should employ a 'scripting' approach for developing operations eg
we should leave most of the internal data models to the related bindings eg. we 
should identify gaps and issues with existing service bindings and raise as tasks in 
those respective projects.

Initial set of defined operations will be mostly 'read only' queries with maybe 1-2 write
process automations.

Comprehensive development of management operations are not in scope. It maybe that
this CLI is not the right long term repository for management operations - for now
(modulo manage ops) we are in discovery 'mode'.

A set of high quality training materials (docs + video) will be developed to assist
adoption of the tool.

Engage with end users as quickly as possible so we can start incremental development. It
will be considered a success if we can get our end users to contribute to the development
of this CLI.

## Consequences

Developing on github and releasing CLI as open source without core data services
being accessible for external (public) end users limits its utility (and rationale 
for releasing via PyPI) - eg. for now there is no concrete expectation on 
building community.

Alternately we might consider developing a more robust internal application model in
the CLI though this would incur maintenance cost and increase complexity of the 
CLI application itself - we explicitly have chosen operation implementation to be tactical and 'scripty' 
in nature as this CLI is not targeting heavy duty automation/integration eg. that kind of usage
is addressed by service bindings themselves. Having a separate set of python modules developed for query/process
automation (that is cross service in nature) should address reuse of service operations outside of the cli.

We could consider using https://github.com/click-contrib/click-plugins enabling development
and dynamic registration of 3rd party plugins ... current approach is simple though we could
consider a change at any time in the future.

