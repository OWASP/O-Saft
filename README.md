
----
|   |
|:--|
| Any use of this project's code by GitHub Copilot,  past or present, is done without our permission. We do not consent to GitHub's use of this project's code in Copilot. |
|   |
----

# [ O-Saft - OWASP SSL advanced forensic tool](https://owasp.org/www-project-o-saft/)

**Download [Version 24.01.24](https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz)**

## QUICK START

```
  o-saft.pl --help
  o-saft.pl +check  your.tld
  o-saft.pl +info   your.tld
  o-saft.pl +quick  your.tld
  o-saft.pl +cipher your.tld
  o-saft.pl --help=commands

  o-saft.tcl      # (simple GUI; requires Tcl/Tk 8.5 or newer)

  o-saft-docker   # (simple wrapper to call o-saft.pl in docker image)

  o-saft          # (simple wrapper to call o-saft.pl or o-saft.tcl or o-saft-docker)
```

## DESCRIPTION

This tools lists  information about remote target's  SSL  certificate
and tests the remote target according given list of ciphers.

## UNIQUE FEATURES

* working in closed environments, i.e. without internet connection
* checking availability of ciphers independent of installed library
* checking for all possible ciphers (up to 65535 per SSL protocol)
* needs just perl without modules for checking ciphers and protocols
* mainly same results on all platforms

## WHY?

Why a new tool for checking SSL  when there already exist a dozens or
more good tools in 2012? Some (but not all) reasons are:

* lack of tests of unusual ciphers
* different results returned for the same check on same target
* missing functionality (checks) according modern SSL/TLS
* lack of tests of unusual (SSL, certificate) configurations
* (mainly) missing feasability to add own tests

For more details, please use:

```
  o-saft.pl --help
```
or read the source ;-)

## TARGET AUDIENCE

* penetration testers
* administrators

## INSTALLATION

`o-saft.pl` requires following Perl modules:

| Module               | Version |
|:---------------------|:--------|
| `Net::SSLeay`        | (prefered >= 1.51, recommended 1.94)     |
| `IO::Socket::SSL`    | (prefered >= 1.37, recommended 2.081)    |
| `IO::Socket::INET`   | (prefered >= 2.49)  |
| `Net::DNS`           | (prefered >= 1.36, for --mx option only) |

It can be executed from within the unpacked or cloned directory,
installation is not necessary. However, a  `INSTALL.sh`  script will be
provided, which can be called as follows:

Own modules are all installed in  `./lib` .

```
  INSTALL.sh /path/to/install
  INSTALL.sh --check
```
For more details on installation, please see:
```
  INSTALL.sh --help
```

There're no dependencies to other Perl modules for `checkAllCiphers.pl`
so the test of all ciphers will work with it.

Following files are optional:

| File / Tool              | Description |
|:-------------------------|:------------|
| `.o-saft.pl`             | (private user configuration) |
| `.o-saft.tcl`            | (private user configuration for GUI) |
| `lib/OTrace.pm`          | (functions for debugging) |
| `lib/OMan.pm`            | (documentation and generation functions) |
| `doc/o-saft.pod`         | (documentation in POD format) |
| `lib/o-saft-img.tcl`     | (images for buttons in GUI) |
| `usr/checkAllCiphers.pl` | (simple script for checking all ciphers) |
| `usr/*`                  | (additional programs and tools) |

## Sources 
* Project home is https://www.owasp.org/index.php/O-Saft
* Project repo is https://github.com/OWASP/O-Saft
* Historic Project home https://www.owasp.org/index.php/Projects/O-Saft
<!--
* Project roadmap https://www.owasp.org/index.php/Projects/O-Saft/Roadmap
-->

Get a Copy (latest stable release)
```
  wget https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz
```

Get a Copy (development version)
```
  git clone https://github.com/OWASP/O-Saft.git
  git clone git@github.com:OWASP/O-Saft.git
```

Get Docker Image (latest stable release)
```
  docker pull owasp/o-saft
```

## VERSION

**24.09.24**

The version of the tarball `o-saft.tgz` represents the version listed on top
herein. All other files in the repository may be ahead of this tarball version.

SHA256 checksum of [o-saft.tgz](https://github.com/OWASP/O-Saft/raw/master/o-saft.tgz)
```
3f3eb35982717931cd23f384b378c77c07b0ce75fa5341ede574a3e153c9b48d
```

[//]: # (above checksum for version 24.06.24)
<!--
# comment not rendered in HTML
-->

SHA256 checksum of docker image owasp/o-saft:latest and owasp/o-saft:18.11.18
```
b85423d142c186c1cf10494aa0e993f6f2030ab769977aca9584d7d650421697
```

NOTE that the checksums listed here are the previous versions if this
file is from  o-saft.tgz  itself, or inside the docker image.

### Changes

A detailled list of changes can be found in 
   [CHANGES](https://github.com/OWASP/O-Saft/blob/master/CHANGES).
It will be updated with each new version (release).

### Older version

If older versions should be used, please get the correspondig `o-saft.tgz`
from github's releases, see:
   [https://github.com/OWASP/O-Saft/releases](https://github.com/OWASP/O-Saft/releases) (as of September 2024).
