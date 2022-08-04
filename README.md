# dep-vuln-checker

Check a repo for known vulnerabilities in its dependencies.
Supported package managers:
* npm
* Composer
* Gradle

In the background this script calls: 
* `npm audit` for nodejs repos
* `local-php-security-checker` (https://github.com/fabpot/local-php-security-checker) for PHP repos
* `org.owasp:dependency-check-gradle` for Gradle repos

The output is a json file with info about the vulnerable packages.

## Usage
```
dep-vuln-checker.py [-h] [-g GH_APIKEY_FILE] [-n NVD_APIKEY_FILE] [-a APPLOG] [-l VULNLOG] [-i INVDB] repolist_file
```
* repolist\_file: path to a newline-separated file containing the directories to check OR a single directory to check
* GH\_APIKEY\_FILE: path to file containing GitHub API key (default: /etc/dep-vuln-checker/gh-apikey)
* NVD\_APIKEY\_FILE: path to file containing NVD API key (default: /etc/dep-vuln-checker/nvd-apikey)
* APPLOG: log path for app messages  (default: stdout)
* VULNLOG: log path for vulnerabilities (default: stdout)
* INVDB: store vulnerability information in a file so they won't be logged on the next run. Set to 'none' if you don't want to use an inventory and want to always log all vulnerable dependencies. (default: /var/lib/dep-vuln-checker/inventory.db)

## Dependencies
* npm >= 6
* local-php-security-checker 
