# dep-vuln-checker

Check a project for known vulnerabilities in its dependencies.
Supported package managers:
* npm
* pnpm
* Yarn
* Composer
* Gradle

In the background this script calls: 
* `npm audit / pnpm audit / yarn audit` for nodejs repos
* `local-php-security-checker` (https://github.com/fabpot/local-php-security-checker) for PHP repos
* `org.owasp:dependency-check-gradle` for Gradle repos

The output is a json file with info about the vulnerable packages.

Note: there's no guarantee that the script or tools called by this script will not modify the target repo (eg. gradle init file needs to be created/modified for gradle dependency check). Recommended to operate on copies of repos.

## Usage
```
usage: dep-vuln-checker.py [-h] [-g GH_APIKEY_FILE] [-n NVD_APIKEY_FILE]
                           [-a APPLOG] [-l VULNLOG] [-i INVPATH]
                           [-c REQCACHETYPE] [-cp REQCACHEPATH]
                           [-rh REDISHOST] [-rp REDISPORT] [-r GHSAREPOPATH]
                           [-s] [-t NVD_DOWNLOAD_TMPDIR] [-I]
                           dirlist [dirlist ...]

positional arguments:
  dirlist               location of newline separated file which contains the project dir paths to check
                        OR a single directory path
                        OR multiple directory paths

optional arguments:
  -h, --help            show this help message and exit
  -g GH_APIKEY_FILE     GitHub apikey location (default: /etc/dep-vuln- checker/gh-apikey)
  -n NVD_APIKEY_FILE    NVD apikey location (default: /etc/dep-vuln- checker/nvd-apikey)
  -a APPLOG             app log location (default: /var/log/dep-vuln- checker/app.log)
  -l VULNLOG            vulnerability log location (default: /var/log/dep- vuln-checker/vulns.log)
  -i INVPATH            Inventory database location or "none" (default: /var/lib/dep-vuln-checker/inventory.db)
  -c REQCACHETYPE       request cache type. Allowed values: redis, sqlite (no request cache used if omitted)
  -cp REQCACHEPATH      reqest cache database path when using sqlite cache type (default: /var/lib/dep-vuln-checker/reqcache.db
  -rh REDISHOST         redis host for request cache and/or severity cache (default: 127.0.0.1)
  -rp REDISPORT         redis port for request cache and/or severity cache (default: 6379)
  -r GHSAREPOPATH       directory to clone GitHub Advisory Database to
  -s                    silent mode - no output
  -t NVD_DOWNLOAD_TMPDIR temp directory to download NVD JSON files (default: /tmp)
  -I                    initialize local NVD + GHSA cache and exit
```

## Dependencies
* npm >= 6
* pnpm
* yarn
* local-php-security-checker 
