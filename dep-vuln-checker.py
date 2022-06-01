#!/usr/bin/python3
#
# dep-vuln-checker.py - check dependencies for known vulnerabilities 
#

import sys
import subprocess
import os.path
import json
import time

def check_args(argv):
    if len(sys.argv) != 2:
        print("USAGE: dep-vuln-checker.py REPOLIST")
        sys.exit(1)

def check_deps():
    try:
        res = subprocess.run(["local-php-security-checker", "-help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        print("local-php-security-checker not available: " + str(e))
        sys.exit(1)

    try:
        res = subprocess.run(["npm", "audit", "-h"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        print("npm audit not available: " + str(e))
        sys.exit(1)
        
def read_repolist(path: str):
    repolist = []
    try:
        with open(path, 'r') as fh:
            repolist = filter(None, fh.read().split('\n'))
    except Exception as e:
        print(e)
        sys.exit(1)
    return repolist

def determine_checker(repopath: str):
    if os.path.isfile(repopath + "/package.json"):
        return "npm"
    elif os.path.isfile(repopath + "/composer.lock"):
        return "composer"
    else:
        return None

def get_vulns(checker: str, repopath: str):
    vulns = []

    if checker == "composer":
        res = subprocess.run(["local-php-security-checker",
            "-path=" + repopath,
            "-format", "json"],
            stdout=subprocess.PIPE)
        for k, v in json.loads(res.stdout).items():
            for i in v["advisories"]:
                vulns.append({
                    "repo": repopath,
                    "package": k,
                    "cve": i["cve"]})
    elif checker == "npm":
        res = subprocess.run(["npm", "audit",
            "--registry=https://registry.npmjs.org",
            "--json"],
            stdout=subprocess.PIPE,
            cwd=repopath)
        for i in json.loads(res.stdout)['advisories'].values():
            for j in i["findings"]:
                for k in j["paths"]:
                    for l in i["cves"]:
                        vulns.append({
                            "repo": repopath,
                            "package": k,
                            "cve": l})
    else:
        print("Unsupported checker: " + checker)
        sys.exit(1)

    return vulns

def print_vulns(vulns):
    for i in vulns:
        print(','.join([
            str(time.time()),
            i["repo"],
            i["package"],
            i["cve"]]))

def main():
    check_args(sys.argv)
    check_deps()
    repos = read_repolist(sys.argv[1])

    allvulns = []
    for i in repos:
        checker = determine_checker(i)
        if checker is not None:
            allvulns += get_vulns(checker, i)

    print_vulns(allvulns)

if __name__ == '__main__':
    main()
