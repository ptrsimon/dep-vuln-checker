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
import sqlite3


def parse_args():
    parser = argparse.ArgumentParser(description='Check repository dependencies for known vulnerabilities')

    parser.add_argument('-g', dest="gh_apikey_file", type=str,
                        help="GitHub apikey location (default: /etc/dep-vuln-checker/nvd-apikey)",
                        default="/etc/dep-vuln-checker/gh-apikey")
    parser.add_argument('-n', dest="nvd_apikey_file", type=str,
                        help="NVD apikey location (default: /etc/dep-vuln-checker/nvd-apikey)",
                        default="/etc/dep-vuln-checker/nvd-apikey")
    parser.add_argument('-a', dest="applog", type=str,
                        help="app log location (default: /var/log/dep-vuln-checker/app.log)",
                        default="/var/log/dep-vuln-checker/app.log")
    parser.add_argument('-l', dest="vulnlog", type=str,
                        help="vulnerability log location (default: /var/log/dep-vuln-checker/vulns.log)",
                        default="/var/log/dep-vuln-checker/vulns.log")
    parser.add_argument('-i', dest="invpath", type=str,
                        help="Inventory database location or \"none\" (default: /var/lib/dep-vuln-checker/inventory.db)",
                        default="/var/lib/dep-vuln-checker/inventory.db")
    parser.add_argument("-s", action="store_true",
                        help="silent mode - no output")
    parser.add_argument('repolist_file',
                        help="location of newline separated file which contains the repo paths to check")

    return parser.parse_args()


def log_msg(msg: str, logfile: str, level: str, silent: bool):
    if not silent:
        print(msg)

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


def inv_connect(path: str, applog: str, silent: bool):
    try:
        conn = sqlite3.connect(path)
    except Exception as e:
        log_msg("Failed to create SQLite database at " + path + ": " + str(e),
                applog, "ERROR", silent)
        sys.exit(1)

    return conn


def create_inventory(path: str, applog: str, silent: bool):
    conn = inv_connect(path, applog, silent)
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                    (directory TEXT, package_name TEXT, vulnerability_id TEXT)''')
        conn.commit()
    except Exception as e:
        log_msg("Failed to create table in inventory at {}: {}"
                .format(path, str(e)), applog, "ERROR", silent)
        sys.exit(1)
    finally:
        conn.close()


def store_vuln(vuln, invpath: str, applog: str, silent: bool):
    if invpath == "none":
        return

    vulnid = (vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"])

    conn = inv_connect(invpath, applog, silent)
    cur = conn.cursor()
    try:
        cur.execute('''INSERT INTO vulnerabilities(directory, package_name, vulnerability_id)
                    VALUES(?,?,?)''', (vuln["repo"], vuln["package"], vulnid))
        conn.commit()
    except Exception as e:
        log_msg("Failed to insert vulnerability {};{};{} into inventory at {}: {}"
                .format(vuln["repo"], vuln["package"], vulnid, invpath, str(e)),
                applog, "ERROR", silent)
        sys.exit(1)
    finally:
        conn.close()


def in_inventory(vuln, invpath: str, applog: str, silent: bool):
    if invpath == "none":
        return False

    vulnid = (vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"])

    conn = inv_connect(invpath, applog, silent)
    cur = conn.cursor()
    res = []
    try:
        cur.execute('''SELECT * FROM vulnerabilities WHERE 
                    directory="{}" AND package_name="{}" AND vulnerability_id="{}"'''.format(
            vuln["repo"], vuln["package"], vulnid))
        res = cur.fetchall()
    except Exception as e:
        log_msg("Failed to check if vulnerability {},{},{} is in inventory at {}: {}"
                .format(vuln["repo"], vuln["package"], vulnid, invpath, str(e)),
                applog, "ERROR", silent)
        sys.exit(1)
    finally:
        conn.close()

    if len(res) < 1:
        return False
    else:
        return True

def check_deps(applog: str, silent: bool):
    try:
        res = subprocess.run(["local-php-security-checker", "-help"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        log_msg("local-php-security-checker not available: " + str(e), applog, "ERROR", silent)
        sys.exit(1)

    try:
        res = subprocess.run(["npm", "audit", "-h"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        log_msg("npm audit not available: " + str(e), applog, "ERROR", silent)
        sys.exit(1)


def check_npm_report_format():
    res = subprocess.run(["npm", "-v"],
                         stdout=subprocess.PIPE)
    npmver = res.stdout.decode("utf-8").split('.')[0]
    if int(npmver) >= 7:
        return 2
    else:
        return 1


def read_repolist(path: str, applog: str, silent: bool):
    repolist = []
    try:
        with open(path, 'r') as fh:
            repolist = filter(None, fh.read().split('\n'))
    except Exception as e:
        log_msg("Unable to read repolist: " + str(e), applog, "ERROR", silent)
        sys.exit(1)
    return repolist


def determine_checkers(repopath: str):
    checkers = []

    if os.path.isfile(repopath + "/package.json") and os.path.isfile(repopath + "/package-lock.json"):
        checkers.append("npm")
    if os.path.isfile(repopath + "/composer.lock"):
        checkers.append("composer")
    if os.path.isfile(repopath + "/yarn.lock"):
        checkers.append("yarn")
    if os.path.isdir(repopath + "/gradle"):
        checkers.append("gradle")

    return checkers


def get_severity_from_nvd(cve_id: str, apikey: str):
    severity = ""

    headers = {"Authorization": "Bearer " + apikey}

    r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id)

    try:
        severity = json.loads(r.text)["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
    except Exception:
        pass  # worst case severity will be empty

    return severity


def get_details_from_ghsa(ghsa_id: str, apikey: str):
    cveid = ""

    headers = {"Authorization": "Bearer " + apikey}
    query = {"query": "query {securityAdvisory(ghsaId:\"" + ghsa_id + "\") { summary identifiers {type value}}}"}

    r = requests.post('https://api.github.com/graphql', json=query, headers=headers)

    rdict = json.loads(r.text)
    for i in rdict["data"]["securityAdvisory"]["identifiers"]:
        if i["type"] == "CVE":
            cveid = i["value"]

    return cveid, rdict["data"]["securityAdvisory"]["summary"]


def get_vulns_composer(repopath: str, nvd_apikey: str, invpath: str, applog: str, silent: bool):
    vulns = []

    try:
        res = subprocess.run(["local-php-security-checker",
                              "-path=" + repopath,
                              "-format", "json"],
                             stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        log_msg("local-php-security-checker failed for " +
                repopath + ". retcode: " + str(e.returncode), applog, "ERROR", silent)
        return []
    
    for k, v in json.loads(res.stdout).items():
        for i in v["advisories"]:
            newvuln = {
                "timestamp": datetime.datetime.now().isoformat(),
                "repo": repopath,
                "package": k,
                "severity": get_severity_from_nvd(i["cve"], nvd_apikey),
                "ghsa": "",
                "cve": i["cve"],
                "description": i["title"]}
            if not in_inventory(newvuln, invpath, applog, silent):
                vulns.append(newvuln)
                store_vuln(newvuln, invpath, applog, silent)

    return vulns


def get_vulns_yarn(repopath: str, nvd_apikey: str, invpath: str, applog: str, silent: bool):
    vulns = []

    try:
        res = subprocess.run(["yarn", "audit", "--json"],
                             cwd=repopath,
                             stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        log_msg("yarn audit failed for " +
                repopath + ". retcode: " + str(e.returncode), applog, "ERROR", silent)
        return []

    for i in res.stdout.splitlines():
        vulndata = json.loads(i)
        if vulndata["type"] == "auditAdvisory":
            for j in vulndata["data"]["advisory"]["cves"]:
                newvuln = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "repo": repopath,
                    "package": vulndata["data"]["advisory"]["module_name"],
                    "severity": vulndata["data"]["advisory"]["severity"],
                    "ghsa": "",
                    "cve": j,
                    "description": vulndata["data"]["advisory"]["overview"]}
                if not in_inventory(newvuln, invpath, applog, silent):
                    vulns.append(newvuln)
                    store_vuln(newvuln, invpath, applog, silent)

    return vulns


def get_vulns_npm(repopath: str, gh_apikey: str, invpath: str, npm_report_format: int,
        applog: str, silent: bool):
    vulns = []

    res = subprocess.run(["npm", "audit",
                          "--registry=https://registry.npmjs.org",
                          "--json"],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         cwd=repopath)

    if res.stderr.decode("utf-8") != "":
        log_msg("npm audit failed for " + repopath +
                ". stderr: \n" + res.stderr.decode("utf-8"), applog, "ERROR", silent)
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
                    cveid, description = get_details_from_ghsa(j["url"].rsplit('/', 1)[1], gh_apikey)
                    newvuln = {
                        "timestamp": datetime.datetime.now().isoformat(),
                        "repo": repopath,
                        "package": i["name"],
                        "severity": j["severity"],
                        "ghsa": j["url"].rsplit('/', 1)[1],
                        "cve": cveid,
                        "description": description
                    }
                    if not newvuln in vulns and not in_inventory(newvuln, invpath, applog, silent):
                        vulns.append(newvuln)
                        store_vuln(newvuln, invpath, applog, silent)

    return vulns

def get_vulns_gradle(repopath: str, nvd_apikey: str, invpath: str, applog: str, silent: bool):
    vulns = []

    gradle_init="""
allprojects {
    buildscript {
        repositories {
            maven {
                url "https://plugins.gradle.org/m2/"
            }
        }
        dependencies {
            classpath "org.owasp:dependency-check-gradle:7.1.1"
        }
    }


    afterEvaluate { project ->
        project.apply plugin: 'org.owasp.dependencycheck'
            dependencyCheck {
                format="json"
            }
    }
}
"""

    try:
        with open(repopath + "/depcheck-init.gradle", 'w') as fh:
            fh.write(gradle_init)
    except Exception as e:
        log_msg("Unable to create " + repopath + "/depcheck-init.gradle: " + str(e),
                applog, "ERROR", silent)
        return []

    try:
        res = subprocess.run(["gradle", "--init-script", "depcheck-init.gradle", "dependencyCheckAnalyze"],
                             cwd=repopath,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
    except Exception as e:
        log_msg("Failed to run gradle dependency check on " + repopath + ": " + str(e), 
                applog, "ERROR", silent)
        return []

    for i in glob.glob(repopath + "/**/build/reports/dependency-check-report.json"):
        with open(i, 'r') as fh:
            report = json.load(fh)
            for j in report["dependencies"]:
                if "vulnerabilities" in j.keys():
                    for k in j["vulnerabilities"]:
                        newvuln = {
                            "timestamp": datetime.datetime.now().isoformat(),
                            "repo": repopath,
                            "package": j["packages"][0]["id"].split(':')[1],
                            "severity": get_severity_from_nvd(k["name"], nvd_apikey),
                            "cve": k["name"],
                            "description": k["description"]
                        }

                        if not newvuln in vulns and not in_inventory(newvuln, invpath, applog, silent):
                            vulns.append(newvuln)
                            store_vuln(newvuln, invpath, applog, silent)

    return vulns


def get_vulns(checker: str, repopath: str, npm_report_format: int,
              gh_apikey: str, nvd_apikey: str, invpath: str, applog: str, silent: bool):
    vulns = []

    if checker == "composer":
        vulns += get_vulns_composer(repopath, nvd_apikey, invpath, applog, silent)
    elif checker == "yarn":
        vulns += get_vulns_yarn(repopath, nvd_apikey, invpath, applog, silent)
    elif checker == "npm":
        vulns += get_vulns_npm(repopath, gh_apikey, invpath, npm_report_format, applog, silent)
    elif checker == "gradle":
        vulns += get_vulns_gradle(repopath, nvd_apikey, invpath, applog, silent)
    else:
        log_msg("Unsupported checker: " + checker, applog, "ERROR", silent)
        sys.exit(1)

    return vulns


def read_apikey(file: str, applog: str, silent: bool):
    try:
        with open(file, 'r') as fh:
            return fh.read().rstrip('\n')
    except Exception:
        log_msg("Unable to read apikey from " + file, applog, "ERROR", silent)
        sys.exit(1)


def to_ecs(vuln):
    ecsvuln = {}

    ecsvuln["timestamp"] = vuln["timestamp"]
    ecsvuln["service"] = {"name": "dep-vuln-checker"}
    ecsvuln["vulnerability"] = {
        "id": vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"],
        "severity": vuln["severity"],
        "description": vuln["description"]
    }
    ecsvuln["package"] = {"name": vuln["package"]}
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


def write_vulns_json(vulns, applog: str, vulnlog: str, silent: bool):
    if vulnlog != "stdout":
        try:
            fh = open(vulnlog, "a")
        except OSError:
            log_msg("Failed to open " + vulnlog, "ERROR", applog, silent)
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
    log_msg("Started", "INFO", args.applog, args.s)
    check_deps(args.applog, args.s)

    if args.invpath != "none":
        create_inventory(args.invpath, args.applog, args.s)

    allvulns = []
    for i in read_repolist(args.repolist_file, args.applog, args.s):
        checkers = determine_checkers(i)
        if len(checkers) > 0:
            for j in checkers:
                log_msg("Getting vulnerabilities for repo=" + i + ",checker=" + j, "INFO", args.applog, args.s)
                newvulns = get_vulns(j, i, check_npm_report_format(),
                                      read_apikey(args.gh_apikey_file, args.applog, args.s),
                                      read_apikey(args.nvd_apikey_file, args.applog, args.s),
                                      args.invpath, args.applog, args.s)
                allvulns += newvulns
                log_msg(str(len(newvulns)) + " new vulnerabilities found for repo=" + i + ",checker=" + j, "INFO", args.applog, args.s)

    write_vulns_json(allvulns, args.applog, args.vulnlog, args.s)
    log_msg("Done", "INFO", args.applog, args.s)


if __name__ == '__main__':
    main()
