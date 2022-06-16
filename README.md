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
where repolist\_file is a newline-separated file which contains the directories to check.
GH\_APIKEY\_FILE and NVD\_APIKEY\_FILE need to contain GitHub and NVD API keys.
If the keyfile arguments are omitted, /etc/dep-vuln-checker/{gh,nvd}-apikey files ares used by default.
APPLOG is the log path for app messages and VULNLOG for the vulnerabilities ("stdout" can be used for both of them, which is the default).

## Dependencies
* npm >= 6
* local-php-security-checker 
