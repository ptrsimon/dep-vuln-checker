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
        return True

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


def get_vulns(checker: str, repopath: str, npm_report_format: int,
              gh_apikey: str, nvd_apikey: str, invpath: str, applog: str, silent: bool):
    vulns = []

    if checker == "composer":
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

    elif checker == "npm":
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
            log_msg("Failed to open " + vulnlog, applog, silent)
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
    check_deps(args.applog, args.s)

    if args.invpath != "none":
        create_inventory(args.invpath, args.applog, args.s)

    allvulns = []
    for i in read_repolist(args.repolist_file, args.applog, args.s):
        checker = determine_checker(i)
        if checker is not None:
            allvulns += get_vulns(checker, i, check_npm_report_format(),
                                  read_apikey(args.gh_apikey_file, args.applog, args.s),
                                  read_apikey(args.nvd_apikey_file, args.applog, args.s),
                                  args.invpath, args.applog, args.s)

    write_vulns_json(allvulns, args.applog, args.vulnlog, args.s)


if __name__ == '__main__':
    main()
