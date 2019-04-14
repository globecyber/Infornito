<p align="center">
<img src="repo/infornito.png" ><br>
<img src="https://img.shields.io/badge/Python-3.*-blue.svg">
<img src="https://img.shields.io/github/license/GlobeCyber/Infornito.svg">
<img src="https://img.shields.io/github/release-pre/GlobeCyber/Infornito.svg"> 
<img src="https://img.shields.io/github/issues-raw/GlobeCyber/Infornito.svg">
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
- [Contributing](#contributing)
- [License](#license)


## Installation
```bash
git clone https://github.com/GlobeCyber/Infornito
```
### Requirements
- Python 3
- Tabulate

```bash
pip install -r requirements.txt
```
## Usage
```
  _______     __       _____     __
 / ___/ /__  / /  ___ / ___/_ __/ /  ___ ____
/ (_ / / _ \/ _ \/ -_) /__/ // / _ \/ -_) __/
\___/_/\___/_.__/\__/\___/\_, /_.__/\__/_/
                         /___/
            < Infornito v0.3 >

usage: infornito.py [-h] {profiles,history,downloads,fingerprints} ...

Simple browser forensic tool

positional arguments:
  {profiles,history,downloads,fingerprints}

optional arguments:
  -h, --help            show this help message and exit
```
### Profiles
list browsers (Chrome, Firefox, Safari) profiles.
```bash
python infornito.py profiles
```
```
  ID  Path                          Browser Type
----  ----------------------------  --------------
   1  21a6irx65.default             Firefox
   2  je9q4srv.dev-edition-default  Firefox
   3  Profile 1                     Chrome
   4  Default                       Chrome
   5  Default                       Safari
```
### History
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

### Downloads
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
### Fingerprints
Generate MD5, Sha1, Sha256 of profile database.
```bash
python infornito.py fingerprints --profile 2
```
```
Profile path : /Users/osx/Library/Application Support/Google/Chrome/Default

[+] History
        md5 : 6ae30770ae0ba886065286e729395gd2
        sha1 : 1988f687376e60afa5d87cf90a05e14461cfbq01
        sha256 : x26c07579f3c229d0bdcdeecb4e8da2efffa8d44a123b8ea4309edfcc5f9239r
```
## Contributing

Feel free to dive in! [Open an issue](https://github.com/globecyber/Infornito/issues/new) or submit PRs.

### Contributors

This project exists thanks to all the people who contribute.

## License

[GPL](LICENSE) © GlobeCyber