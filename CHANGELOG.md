# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Load offline profile
- Adding support for opera
- Adding support for internet explorer
- Extract saved passwords
- File download query filters
    - Time range
    - Total visit
- HTML export
    - download

## [1.4] - 2019-04-30
### Added
- File download query filters
    - File extension
    - Domain / TLD
    - IP ( Lan / Specific IP )
    - Protocol
    - Port
    - File types
    - Regex
    - Localfile
- History query filters
    - Localfile

## [1.3] - 2019-04-29
### Added
- added history HTML export
- added history page title to export file
- added time filter to safari

## [1.2] - 2019-04-27
### Added
- Filter history queries
    - Time range
    - Total visit

## [1.1] - 2019-04-21
### Added
- CSV output
### Removed
- Third-party dependencies

## [1.0] - 2019-04-19
### Added
- Added windows support

### Bug Fixes
- Fixed windows related datetime problem
- Fixed windows safari module crash problem

## [0.5] - 2019-04-18
### Added
- Filter browser history by
    - File extension
    - Domain / TLD
    - IP ( Lan / Specific IP )
    - Protocol
    - Port
    - File types
    - Admin panels
    - Wordpress
    - Regex
- Detect web attacks from browser history
    - Sql injection
    - XSS
    - LFI

## [0.4] - 2019-04-17
### Added
- Add profile export parameter
### Bug Fixes
- Fix filtering error

## [0.3] - 2019-04-14
### Added
- Start using changelog
- Add profiles fingerprint parameter ( MD5, Sha1, Sha256 )