#!/usr/bin/python3
#
# dep-vuln-checker.py - check repository dependencies for known vulnerabilities 
#

import sys
import subprocess
import os.path
import json
import time
import requests
import glob
import datetime
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Check repository dependencies for known vulnerabilities')

    parser.add_argument('-g', dest="gh_apikey_file", type=str, help="GitHub apikey location", 
            default="/etc/dep-vuln-checker/gh-apikey")
    parser.add_argument('-n', dest="nvd_apikey_file", type=str, help="NVD apikey location",
            default="/etc/dep-vuln-checker/nvd-apikey")
    parser.add_argument('-a', dest="applog", type=str, help="app log location or \"stdout\"",
            default="stdout")
    parser.add_argument('-l', dest="vulnlog", type=str, help="Vulnerability log location or \"stdout\"",
            default="stdout")
    parser.add_argument('repolist_file', help="location of newline separated file which contains the repo paths to check")

    return parser.parse_args()
    
def log_msg(msg: str, logfile: str, level: str):
    if logfile == "stdout":
        print(msg)
        return

    try:
        fh = open(logfile, 'a')
    except OSError:
        print("Failed to open logfile: " + logfile)
        sys.exit(1)

    with fh:
        fh.write("{} {} {}".format(
            datetime.datetime.now().isoformat(),
            level,
            msg))

def log_vuln(vuln, logfile):
    pass

def check_deps(applog: str):
    try:
        res = subprocess.run(["local-php-security-checker", "-help"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        log_msg("local-php-security-checker not available: " + str(e), applog, "ERROR")
        sys.exit(1)

    try:
        res = subprocess.run(["npm", "audit", "-h"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        log_msg("npm audit not available: " + str(e), applog, "ERROR")
        sys.exit(1)

def check_npm_report_format():
    res = subprocess.run(["npm", "-v"],
            stdout=subprocess.PIPE)
    npmver = res.stdout.decode("utf-8").split('.')[0]
    if int(npmver) >= 7:
        return 2
    else:
        return 1
        
def read_repolist(path: str, applog: str):
    repolist = []
    try:
        with open(path, 'r') as fh:
            repolist = filter(None, fh.read().split('\n'))
    except Exception as e:
        log_msg("Unable to read repolist: " +  str(e), applog, "ERROR")
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
        gh_apikey: str, nvd_apikey: str, applog: str):
    vulns = []

    if checker == "composer":
        try:
            res = subprocess.run(["local-php-security-checker",
                "-path=" + repopath,
                "-format", "json"],
                stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            log_msg("local-php-security-checker failed for " +
                    repopath + ". retcode: " + str(e.returncode), applog, "ERROR")
            return []

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
            stderr=subprocess.PIPE,
            cwd=repopath)
        if res.stderr.decode("utf-8") != "":
            log_msg("npm audit failed for " + repopath + 
                    ". stderr: \n" + res.stderr.decode("utf-8"), applog, "ERROR")
            return []

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
        log_msg("Unsupported checker: " + checker, applog, "ERROR")
        sys.exit(1)

    return vulns

def read_apikey(file: str):
    try:
        with open(file, 'r') as fh:
            return fh.read().rstrip('\n')
    except Exception:
        log_msg("Unable to read apikey from " + file, applog, "ERROR")
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

def write_vulns_json(vulns, applog:str, vulnlog: str):
    if vulnlog != "stdout":
        try:
            fh = open(vulnlog, "a")
        except OSError:
            log_msg("Failed to open " + vulnlog, applog)
            sys.exit(1)

    if vulnlog != "stdout":
        with fh:
            for i in vulns:
                fh.write(json.dumps(to_ecs(i)) + "\n")
    else:
        for i in vulns:
            print(json.dumps(to_ecs(i)))

def main():
    args = parse_args()
    check_deps(args.applog)

    allvulns = []
    for i in read_repolist(args.repolist_file, args.applog):
        checker = determine_checker(i)
        if checker is not None:
            allvulns += get_vulns(checker, i, check_npm_report_format(), 
                    read_apikey(args.gh_apikey_file), read_apikey(args.nvd_apikey_file), args.applog)

    write_vulns_json(allvulns, args.applog, args.vulnlog)

if __name__ == '__main__':
    main()
