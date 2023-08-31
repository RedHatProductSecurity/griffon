# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## [0.3.5] - 2023-08-31
### Changed
* process all product version upon generating affects

## [0.3.4] - 2023-08-31
### Changed
* ensure we select released components

## [0.3.3] - 2023-08-31
### Changed
* minor perf enhancements

## [0.3.2] - 2023-08-29
### Added
* added back parallism for resolving sub resources (sources & upstreams)
* added back upstream retrieval when performing --search-all

## [0.3.1] - 2023-08-28
### Changed
* minor perf enhancement when retrieving sources/upstreams

## [0.3.0] - 2023-08-28
### Changed
* operations now use binding async methods
* replace manual count internals to use binding count methods
* added limits on returned items (to be removed in the future)
* prep for component registry service release

## [0.2.23] - 2023-08-22
### Changed
* minor text output fix to properly emit source component names

## [0.2.22] - 2023-08-21
### Changed
* minor affects fix

## [0.2.21] - 2023-08-16
### Changed
* enhanced http debug logging with --debug
* enhanced status bar
* ensure we search latest community components with --search-latest

## [0.2.20] - 2023-08-11
### Changed
* make 'new' default for -a (when generating affects)
### Added
* --no-upstream-affects which will exclude upstream components when generating affects

## [0.2.19] - 2023-08-10
### Changed
* ensure we handle upstreams with component name containing special chars (as in regex special chars)

## [0.2.18] - 2023-08-10
### Changed
* enable searching community upstreams using --search-upstreams

## [0.2.17] - 2023-08-09
### Changed
* ensure verbosity is always set
* exclude products can now use regexes

## [0.2.16] - 2023-08-08
### Changed
* exclude components (defined in .griffonrc or product definitions) now support regex patterns

## [0.2.15] - 2023-07-18
### Added
* --output-type-filter which filter on component type

## [0.2.14] - 2023-07-14
### Changed
* griffon will now use product stream exclude_components by default
* added --include-product-stream-exclude-components flag to disable exclude_components

## [0.2.13] - 2023-06-30
### Changed
* ensure affects respect active product stream configuration

## [0.2.12] - 2023-06-30
### Changed
* ensured use of regexes with verbose settings do not interact **everywhere**!

## [0.2.11] - 2023-06-30
### Changed
* fixed -v output with components-affected-by-flaw
* ensured use of regexes with verbose settings do not interact

## [0.2.10] - 2023-06-30
### Changed
* return components in active product streams for products-contains-component operation
### Added
* --include-inactive-product-streams option for products-contains-component operation
* 
## [0.2.9] - 2023-06-29
### Changed
* pin osidb-bindings 3.3.0
* update crypto python module
* fix generation of affects 

## [0.2.8] - 2023-06-28
### Added
- CRUD operations for OSIDB entities Flaw Comment (create, retreive, list),
  Flaw Reference (create, retrieve, list, update, delete)
## [0.2.7] - 2023-06-14
### Changed
- ensure we choose latest version of component using products-contains-component
- update user docs (include krb5_config as required dependency)

## [0.2.6] - 2023-05-29
### Added
- add terminal --width flag
### Changed
- bumped python requests module in tests, dev and lint requirements to address vuln

## [0.2.5] - 2023-05-26
### Added
- minimal middleware support to products-contains-component, requires Requires GRIFFON_MIDDLEWARE_CLI to be set.
 
### Changed
- bumped python requests module to address vuln
- fixed products-contains-component when used with --purl

## [0.2.4] - 2023-05-25
### Added
- add --no-wrap flag
### Changed
- enhanced error handling when retrieving product streams and manifests
- fixed regex display 

## [0.2.3] - 2023-05-24
### Changed
- fixed summary counts

## [0.2.2] - 2023-05-24
### Changed
- fix --search-upstreams 
- add summary count of sources
### Added
- bugzilla bzowner plugin

## [0.2.1] - 2023-05-23
### Changed
- cleaner and more memory efficient text output

## [0.2.0] - 2023-05-10
### Added
- first GA release

## [0.1.29] - 2023-05-05
### Changed
- bump component-registry-bindings == 1.3.4 to enable accessing latest corgi
- fix various incompatibilities with latest component registry prod

## [0.1.28] - 2023-04-27
### Changed
- bump osidb-bindings == 3.1.0 to enable accessing latest osidb

## [0.1.27] - 2023-04-26
### Changed
- allow -v at the end of CLI invoke
- prefer nvr for component name in text output
### Added
- added entities component-registry components tree which displays dependency tree

## [0.1.26] - 2023-04-21
### Changed
- when products-contain-components has no switches enable --search-latest by default

## [0.1.25] - 2023-04-21
### Changed
- narrowed products-contain-component text output
- fixed community flag which was incorrectly enabling --search-related-url switch

## [0.1.24] - 2023-04-20
### Changed
- deactivate progress bar when performing entity CRUD
- enabled community searching when using --search-all
### Added
- added --search-redhat

## [0.1.23] - 2023-04-18
### Changed
- fixed json format output

## [0.1.22] - 2023-04-18
### Changed
- added exclude_component logic when generating affects with -a

## [0.1.21] - 2023-04-18
### Changed
- refined exclude_components
- added some more component exclude patterns to default .griffonrc
- removed spurious logging statement

## [0.1.20] - 2023-04-17
### Added
- added exclude_components to .griffonrc which controls which components should be excluded from text output

## [0.1.19] - 2023-04-14
### Changed
- ensure griffon service product-manifest is fast and correct

## [0.1.18] - 2023-04-13
### Changed
- refactored service flaw related operations to take advantage of faster filters

## [0.1.17] - 2023-04-11
### Added
- enable griffon service products-contains-component --search-community
- enable griffon entities community-component-registry

## [0.1.16] - 2023-04-11
### Changed
- speed up griffon service products-contain-component with --search-related-urls

## [0.1.15] - 2023-04-11
### Changed
- fix griffon service products-contain-component with --search-upstreams

## [0.1.14] - 2023-04-06
### Changed
- enhanced griffon service report-license

## [0.1.13] - 2023-04-06
### Added
- simple griffon plugins semgrep
- products, product-versions, product-variants, channels to corgi entities
### Changed
- minor plugin enhancements
- minor docs updates
- refactored low level entities with nested entrypoint
- moved manage to entities
- expose more flags on product-components
- add license_concluded to license report when available
- rename upstream_url to download_url in license report
- include upstream_url / download_url on more component types in license report

## [0.1.12] - 2023-04-03
### Changed
- enable OSIDB local development instances to be used with Griffon
- added editor option to .griffonrc
### Added
- CRUD operations for OSIDB entitites. Flaws (create, update, get, list),
  Affects (create, update, delete, get, list), Trackers (get, list)

## [0.1.11] - 2023-04-03
### Changed
- removed old code paths in core-queries

### Changed
## [0.1.10] - 2023-03-31
### Changed
- tweaked service components-contain-component text output

## [0.1.9] - 2023-03-31
### Changed
- refine product-components text output

## [0.1.8] - 2023-03-31
### Changed
- shortern sha256 versions in service product-components
### Added
- added type,latest and download_url to service component-summary operation

## [0.1.7] - 2023-03-31
### Changed
- fixed --search-upstreams to reflect changes on component-registry REST API
- updated dependency component-registry-bindings v.1.3.2
- pegged component-registry-bindings==1.3.1 and osidb-bindings=3.0.0

### Added
- added service report-license operation
- added custom_plugin_dir to .griffonrc which defines a custom directory for user plugins


## [0.1.6] - 2023-03-23
### Changed
- fix imports of Flaw/Affect resolution from osidb-bindings

## [0.1.5] - 2023-03-23
### Added
- added --all to service product-summary to return all products

### Changed
- fixed --search-all when it encounters a Bad Gateway

## [0.1.4] - 2023-03-21
### Changed
- fixed logging which was emitting double statements
- handling short version name processing on empty version

## [0.1.3] - 2023-03-20
### Added
- refactored profiles (changed 'all' to match 'default' section) and added verbosity and default setting in .griffonrc
- minor text output formatting (shortern sha256 version names)
- new draft tutorial

## [0.1.2] - 2023-03-17
### Changed
- use pkg_resources to access static resources

## [0.1.1] - 2023-03-17
### Changed
- changed .griffonrc file path to the correct path

## [0.1.0] - 2023-03-17
### Added
- Initial official release to the PyPI
