# dep-vuln-checker

Check a repo for known vulnerabilities in its dependencies.
Supported package managers:
* npm
* Composer

In the background this script calls `npm audit` for nodejs repos and `local-php-security-checker` (https://github.com/fabpot/local-php-security-checker) for PHP repos.

## Usage
```
dep-vuln-checker.py [-h] [-g GH_APIKEY_FILE] [-n NVD_APIKEY_FILE] [-a APPLOG] [-l VULNLOG] repolist_file
```
* repolist\_file: path to a newline-separated file containing the directories to check
* GH\_APIKEY\_FILE: path to file containing GitHub API key (default: /etc/dep-vuln-checker/gh-apikey)
* NVD\_APIKEY\_FILE: path to file containing NVD API key (default: /etc/dep-vuln-checker/nvd-apikey)
* APPLOG: log path for app messages  (default: stdout)
* VULNLOG log path for vulnerabilities (default: stdout)

## Dependencies
* npm >= 6
* local-php-security-checker 
