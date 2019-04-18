# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Import profiles
- Add support for opera
- Collect all profiles to infornito database
- Extract saved passwords
- Detect web attacks
    - Sql injection (✅)
    - XSS (✅)
    - LFI (✅)
- Filter queries 
    - Time range (✅)
    - File extension (✅)
    - Domain / TLD (✅)
    - IP ( Lan / Specific IP ) (✅)
    - Protocols (✅)
    - Port (✅) 
    - File types (✅)
    - Admin panels (✅)
    - Wordpress (✅)
    - Regex (✅)

## [0.4] - 2019-04-17
### Added
- Add profile export parameter
### Bug Fixes
- Fix filtering error

## [0.3] - 2019-04-14
### Added
- Start using changelog
- Add profiles fingerprint parameter ( MD5, Sha1, Sha256 )