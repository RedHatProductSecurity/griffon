# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
### Added
- CRUD operations for OSIDB entitites. Flaws (create, update, get, list),
  Affects (create, update, delete, get, list), Trackers (get, list)

### Changed
- enable OSIDB local development instances to be used with Griffon
- added editor option to .griffonrc

## [0.1.11] - 2023-04-03
### Changed
- removed old code paths in core-queries
- significantly enhanced osidb entity operations

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
