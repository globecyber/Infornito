# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Import profiles
- Add support for opera
- Collect all profiles to infornito database
- Extract saved passwords
- Filter history queries
    - Time range
    - Total visit
- Filter file download queries
    - Time range
    - Total visit
    - File extension
    - Domain / TLD
    - IP ( Lan / Specific IP )
    - Protocol
    - Port
    - File types
    - Regex

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