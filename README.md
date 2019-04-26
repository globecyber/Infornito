<p align="center">
  <a href="https://globecyber.com"><img src="repo/infornito.png" ><br></a>
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20MacOS%20%7C%20Linux-brightgreen.svg">
  <a href="https://www.python.org/downloads/">
  <img src="https://img.shields.io/badge/Python-3.*-blue.svg"></a>
  <a href="https://github.com/globecyber/Infornito/blob/master/LICENSE">
  <img src="https://img.shields.io/github/license/GlobeCyber/Infornito.svg"></a>
  <a href="https://github.com/globecyber/Infornito/releases"><img src="https://img.shields.io/github/release-pre/GlobeCyber/Infornito.svg"></a>
  <a href="https://github.com/globecyber/Infornito/issues">
  <img src="https://img.shields.io/github/issues-raw/GlobeCyber/Infornito.svg"></a>
</p>

# Infornito 
Infornito developed in Python 3.x and has as purpose extract all forensic interesting information of Chrome, Firefox, Safari browsers to be analyzed. Due to its Python 3.x developement, might not work properly in old Python versions, mainly with certain characters. Works under Unix and Windows 32/64 bits systems. Works in command line interface, so information dumps could be redirected by pipes with tools such as grep, awk, cut, sed... Infornito allows to visualize following sections, search customization and extract certain content.

## Table of Contents

- [Installation](#installation)
	- [Requirements](#requirements)
- [Usage](#usage)
  - [Profiles](#profiles)
  - [History](#history)
  - [Downloads](#downloads)
  - [Fingerprint](#fingerprint)
  - [Export](#export)
- [Contributing](#contributing)
- [Change Log](https://github.com/globecyber/Infornito/blob/master/CHANGELOG.md)
- [License](#license)


## Installation
```bash
git clone https://github.com/GlobeCyber/Infornito
```
### Requirements
- [Python 3](https://www.python.org/downloads/)

## Usage
```
  _______     __       _____     __
 / ___/ /__  / /  ___ / ___/_ __/ /  ___ ____
/ (_ / / _ \/ _ \/ -_) /__/ // / _ \/ -_) __/
\___/_/\___/_.__/\__/\___/\_, /_.__/\__/_/
                         /___/
            < Infornito v1.1 >

usage: infornito.py [-h] {profiles,history,downloads,fingerprint} ...

Browser forensic tool

positional arguments:
  {profiles,history,downloads,fingerprint}

optional arguments:
  -h, --help            show this help message and exit
```
### [Profiles](#profiles)

list browsers (Chrome, Firefox, Safari) profiles.
```bash
python infornito.py profiles
```
```
1 => Firefox (21a6irx65.default)
2 => Firefox (je9q4srv.dev-edition-default)
3 => Chrome (Profile 1)
4 => Chrome (Default)
5 => Safari (Default)
```
### [History](#history)
Show Profile url visit history.
```bash
python infornito.py history --profile 2
```
```
[18] https://www.google.com/ ( 2019-03-27 11:15:18 )
[19] https://yahoo.com/# ( 2018-10-31 12:23:25 )
[22] https://instagram.com/ ( 2018-11-07 17:06:48 )
[27] http://facebook.com/home.php ( 2018-10-24 13:45:21 )

[Total visit] URL ( Last Visit )
----------------- Summary ----------------
Total url : 4
```
You can filter outputs by --filter argument to find something you looking for, for example :
```bash
python infornito.py history --profile 2 --filter domain=target.com --filter filetype=pdf --filter protocols=https --filter port=4880
```
```
[12] https://www.target.com:4880/documents/secret.pdf ( 2019-03-27 11:15:18 )
```
### Filter histories
- Domain : filter domain name (--filter domain=target.com)
- Port : filter port number (--filter port=4880,3329)
- File Type : filter file extension (--filter filetype=exe,pdf)
- TLD : filter domain tld (--filter tld=com,us)
- IP
  - filter ip urls (--filter ip)
  - filter lan ip address range (--filter ip=lan)
  - filter specific ip address (--filter ip=10.10.20.240)
- Protocol : filter urls with specific protocol (--filter protocol=https)
- Admin Panel : filter all urls related to admin area (--filter adminpanel)
- Wordpress : filter wordpress websites (--filter wordpress)
- Regex : filter urls by regular expression (--filter "regex=yahoo\.*")
- Attack filters :
  - Sql injection : filter urls with sql injection attack pattern (--filter sqli)
  - LFI : filter urls with local file inclusion attack pattern (--filter lfi)
  - XSS : filter urls with cross site scripting attack pattern (--filter xss)
- Total Visit : only urls visited more than specific time (--filter total_visit=25)
- Date filters :
  - from_date : only urls visited after specific date (--filter from_date=2019/04/20)
  - to_date : only urls visited before specific date (--filter to_date=2019/04/20)
### Export histories
Export histories to csv file.
```bash
python infornito.py history --profile 2 --export csv --to ~/Desktop/export
```
### [Downloads](#downloads)
Show Profile downloaded files.
```bash
python infornito.py downloads --profile 2
```
```
[+] http://www.yahoo.com/img/logo.png -> /Users/myuser/Desktop/logo.png ( 2019-03-24 21:33:26 )
[+] http://facebook.com/.databases/db.zip -> /Users/myuser/Desktop/db.zip ( 2019-03-14 10:58:07 )

[Total visit] URL ( Last Visit )
----------------- Summary ----------------
Total url : 4
```
### [Fingerprint](#fingerprint)
Generate browsers MD5, Sha1, Sha256 of profiles databases.
```bash
python infornito.py fingerprint --profile 2
```
```
Profile path : /Users/osx/Library/Application Support/Google/Chrome/Default

[+] History
        md5 : 6ae30770ae0ba886065286e729395gd2
        sha1 : 1988f687376e60afa5d87cf90a05e14461cfbq01
        sha256 : x26c07579f3c229d0bdcdeecb4e8da2efffa8d44a123b8ea4309edfcc5f9239r
[+] Login Data
        md5 : 7ce30770ae5ba886065286e729395g7d
        sha1 : 67c8f687376e60afa5d87cf90a05e14461cfbc25
        sha256 : g64c07579f3c229d0bdcdeecb4e8da2eggsa8d44a123b8ea4309edfcc5f92rc7
[+] Cookies
        md5 : cx730770ae0ba886065286e729395a24
        sha1 : 2748f687376e60afa5d87cf90a05e14461cfbc56
        sha256 : ac3c07579f3c229d0bdcdeecb4e8da2efffa8d44a123b8ea4309edfcc5f92523
[+] Web Data
        md5 : qc330770ae0ba886065286e729395cx4
        sha1 : 6428f687376e60afa5c23cf90a05e14461cfbvr2
        sha256 : 235c07579f3c229d0bdcdeecb4e8da2efffa8d44a123b8ea4309edfcc5f92gx4
```

### [Export](#export)
Export browser profiles to destination path.
```
python3 infornito.py export --profile 7 --to ~/Desktop/export
```
```
==== [5] Chrome (Default) ====
[~] Profile path : /Users/osx/Library/Application Support/Google/Chrome/Default
[~] Destination path : /Users/osx/Desktop/export/Chrome/Default/2019-04-16 19-35-04
[~] Start exporting profile files ...
	[+] Exporting History : Successful
	[+] Exporting Login Data : Successful
	[+] Exporting Cookies : Successful
	[+] Exporting Web Data : Successful
	[+] Creating infornito.json : Successful
```
## Contributing

Feel free to dive in! [Open an issue](https://github.com/globecyber/Infornito/issues/new) or submit PRs.

### Contributors

This project exists thanks to all the people who contribute.

## License

[GPL](LICENSE) © [GlobeCyber](https://globecyber.com)