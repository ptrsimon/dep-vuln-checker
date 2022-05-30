# dep-vuln-checker

Check a repo for known vulnerabilities in its dependencies.
Supported package managers:
* npm
* Composer

In the background this script calls `npm audit` for nodejs repos and `local-php-security-checker` (https://github.com/fabpot/local-php-security-checker) for PHP repos.

## Usage
```
dep-vuln-checker.py REPOLIST
```
where REPOLIST is a newline-separated file which contains the directories to check.
