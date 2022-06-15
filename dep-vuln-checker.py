#!/usr/bin/python3
#
# dep-vuln-checker.py - check dependencies for known vulnerabilities 
#

import sys
import subprocess
import os.path
import json
import time
import requests
import glob
import datetime

def check_args(argv):
    if len(sys.argv) != 2 and len(sys.argv) != 3 and len(sys.argv) != 4:
        print("USAGE: dep-vuln-checker.py REPOLIST [GH_APIKEY_FILE] [NVD_APIKEY_FILE]")
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

def check_npm_report_format():
    res = subprocess.run(["npm", "-v"],
            stdout=subprocess.PIPE)
    npmver = res.stdout.decode("utf-8").split('.')[0]
    if int(npmver) >= 7:
        return 2
    else:
        return 1
        
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
    if os.path.isfile(repopath + "/package.json") and os.path.isfile(repopath + "/package-lock.json"):
        return "npm"
    elif os.path.isfile(repopath + "/composer.lock"):
        return "composer"
    else:
        return None

def get_severity_from_nvd(cve_id: str, apikey: str):
    severity = ""

    headers = {"Authorization": "Bearer " + apikey}

    r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id)

    try:
        severity = json.loads(r.text)["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
    except Exception:
        pass # worst case severity will be empty

    return severity


def get_cveid_from_ghsa(ghsa_id: str, apikey: str):
    cveid = ""

    headers = {"Authorization": "Bearer " + apikey}
    query = {"query": "query {securityAdvisory(ghsaId:\"" + ghsa_id + "\") { identifiers {type value}}}"}

    r = requests.post('https://api.github.com/graphql', json=query, headers=headers)

    for i in json.loads(r.text)["data"]["securityAdvisory"]["identifiers"]:
        if i["type"] == "CVE":
            cveid = i["value"]

    return cveid

def get_vulns(checker: str, repopath: str, npm_report_format: int, 
        gh_apikey: str, nvd_apikey: str):
    vulns = []

    if checker == "composer":
        res = subprocess.run(["local-php-security-checker",
            "-path=" + repopath,
            "-format", "json"],
            stdout=subprocess.PIPE)
        for k, v in json.loads(res.stdout).items():
            for i in v["advisories"]:
                vulns.append({
                    "timestamp": datetime.datetime.now().isoformat(),
                    "repo": repopath,
                    "package": k,
                    "severity": get_severity_from_nvd(i["cve"], nvd_apikey),
                    "ghsa": "",
                    "cve": i["cve"]})
    elif checker == "npm":
        res = subprocess.run(["npm", "audit",
            "--registry=https://registry.npmjs.org",
            "--json"],
            stdout=subprocess.PIPE,
            cwd=repopath)
        if npm_report_format == 1:
            for i in json.loads(res.stdout)['advisories'].values():
                for j in i["findings"]:
                    for k in j["paths"]:
                        for l in i["cves"]:
                            vulns.append({
                                "timestamp": datetime.datetime.now().isoformat(),
                                "repo": repopath,
                                "package": k,
                                "severity": i["severity"],
                                "ghsa": i["url"].rsplit('/', 1)[1],
                                "cve": l})
        elif npm_report_format == 2:
            for i in json.loads(res.stdout)["vulnerabilities"].values():
                for j in i["via"]:
                    if "url" in j and type(j) is dict:
                        newvuln = {
                                "timestamp": datetime.datetime.now().isoformat(),
                                "repo": repopath,
                                "package": i["name"],
                                "severity": j["severity"],
                                "ghsa": j["url"].rsplit('/', 1)[1],
                                "cve": get_cveid_from_ghsa(j["url"].rsplit('/', 1)[1],
                                    gh_apikey),
                                }
                        if not newvuln in vulns:
                            vulns.append(newvuln)
    else:
        print("Unsupported checker: " + checker)
        sys.exit(1)

    return vulns

def read_apikey(file: str):
    try:
        with open(file, 'r') as fh:
            return fh.read().rstrip('\n')
    except Exception:
        print("Unable to read apikey from " + file)
        sys.exit(1)

def to_ecs(vuln):
    ecsvuln = {}
    
    ecsvuln["timestamp"] = vuln["timestamp"]
    ecsvuln["service"] = {"name": "dep-vuln-checker"}
    ecsvuln["vulnerability"] = {"id": vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"]}
    ecsvuln["package"] = {"name": vuln["package"] }
    ecsvuln["vulnerability"] = {"severity": vuln["severity"]}
    ecsvuln["file"] = {"directory": vuln["repo"]}

    return ecsvuln

def print_vulns(vulns):
    for i in vulns:
        print(','.join([
            str(time.time()),
            i["repo"],
            i["package"],
            i["severity"],
            i["ghsa"],
            i["cve"]]))

def print_vulns_json(vulns):
    for i in vulns:
        print(json.dumps(to_ecs(i)))

def main():
    check_args(sys.argv)
    check_deps()
    repos = read_repolist(sys.argv[1])
    gh_apikey = read_apikey("/etc/dep-vuln-checker/gh-apikey"
            if len(sys.argv) < 3 else sys.argv[2])
    nvd_apikey = read_apikey("/etc/dep-vuln-checker/nvd-apikey"
            if len(sys.argv) < 4 else sys.argv[3])

    allvulns = []
    for i in repos:
        checker = determine_checker(i)
        if checker is not None:
            allvulns += get_vulns(checker, i, check_npm_report_format(), gh_apikey, nvd_apikey)

    print_vulns_json(allvulns)

if __name__ == '__main__':
    main()
