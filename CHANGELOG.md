# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased
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
