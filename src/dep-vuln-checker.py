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
import requests_cache
from ratelimit import limits, sleep_and_retry
import glob
import datetime
import argparse
import sqlite3
import LogHandler


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
    parser.add_argument('-c', dest="cachetype", type=str,
                        help="cache type. Allowed values: redis (no cache used if omitted)",
                        default=None)
    parser.add_argument('-rh', dest="redishost", type=str,
                        help="redis host for cache (default: 127.0.0.1)",
                        default="127.0.0.1")
    parser.add_argument('-rp', dest="redisport", type=int,
                        help="redis port for cache (default: 6379)",
                        default=6379)
    parser.add_argument("-s", action="store_true",
                        help="silent mode - no output")
    parser.add_argument('repolist',
                        help="location of newline separated file which contains the repo paths to check OR a single path if only one repo needs to be checked")

    return parser.parse_args()


def inv_connect(path: str, lh: LogHandler):
    try:
        conn = sqlite3.connect(path)
    except Exception as e:
        lh.log_msg("Failed to create SQLite database at " + path + ": " + str(e), "ERROR")
        sys.exit(1)

    return conn


def create_inventory(path: str, lh: LogHandler):
    conn = inv_connect(path, lh)
    cur = conn.cursor()
    try:
        cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                    (directory TEXT, package_name TEXT, vulnerability_id TEXT)''')
        conn.commit()
    except Exception as e:
        lh.log_msg("Failed to create table in inventory at {}: {}".format(path, str(e)), "ERROR")
        sys.exit(1)
    finally:
        conn.close()


def store_vuln(vuln, invpath: str, lh: LogHandler):
    if invpath == "none":
        return

    vulnid = (vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"])

    conn = inv_connect(invpath, lh)
    cur = conn.cursor()
    try:
        cur.execute('''INSERT INTO vulnerabilities(directory, package_name, vulnerability_id)
                    VALUES(?,?,?)''', (vuln["repo"], vuln["package"], vulnid))
        conn.commit()
    except Exception as e:
        lh.log_msg("Failed to insert vulnerability {};{};{} into inventory at {}: {}"
                   .format(vuln["repo"], vuln["package"], vulnid, invpath, str(e)), "ERROR")
        sys.exit(1)
    finally:
        conn.close()


def in_inventory(vuln, invpath: str, lh: LogHandler):
    if invpath == "none":
        return False

    vulnid = (vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"])

    conn = inv_connect(invpath, lh)
    cur = conn.cursor()
    res = []
    try:
        cur.execute('''SELECT * FROM vulnerabilities WHERE 
                    directory="{}" AND package_name="{}" AND vulnerability_id="{}"'''.format(
            vuln["repo"], vuln["package"], vulnid))
        res = cur.fetchall()
    except Exception as e:
        lh.log_msg("Failed to check if vulnerability {},{},{} is in inventory at {}: {}"
                   .format(vuln["repo"], vuln["package"], vulnid, invpath, str(e)), "ERROR")
        sys.exit(1)
    finally:
        conn.close()

    if len(res) < 1:
        return False
    else:
        return True


def check_deps(lh: LogHandler):
    try:
        res = subprocess.run(["local-php-security-checker", "-help"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        lh.log_msg("local-php-security-checker not available: " + str(e), "ERROR")
        sys.exit(1)

    try:
        res = subprocess.run(["npm", "audit", "-h"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        lh.log_msg("npm audit not available: " + str(e), "ERROR")
        sys.exit(1)


def check_npm_report_format():
    res = subprocess.run(["npm", "-v"],
                         stdout=subprocess.PIPE)
    npmver = res.stdout.decode("utf-8").split('.')[0]
    if int(npmver) >= 7:
        return 2
    else:
        return 1


def read_repolist(path: str, lh: LogHandler):
    repolist = []
    try:
        with open(path, 'r') as fh:
            repolist = filter(None, fh.read().split('\n'))
    except Exception as e:
        lh.log_msg("Unable to read repolist: " + str(e), "ERROR")
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


@sleep_and_retry
@limits(calls=10, period=60)
def get_severity_from_nvd(cve_id: str, apikey: str, lh: LogHandler):
    severity = ""

    headers = {"Authorization": "Bearer " + apikey}

    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cve/1.0/" + cve_id, headers=headers)

        if r.status_code != 200:
            raise Exception('API response: {}'.format(r.status_code))

        severity = json.loads(r.text)["result"]["CVE_Items"][0]["impact"]["baseMetricV2"]["severity"]
    except Exception as e:
        lh.log_msg("Failed to get severity for " + cve_id + ": " + str(e), "WARNING")
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


def get_vulns_composer(repopath: str, nvd_apikey: str, invpath: str, lh: LogHandler):
    vulns = []

    try:
        res = subprocess.run(["local-php-security-checker",
                              "-path=" + repopath,
                              "-format", "json"],
                             stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        lh.log_msg("local-php-security-checker failed for " +
                   repopath + ". retcode: " + str(e.returncode), "ERROR")
        return []

    for k, v in json.loads(res.stdout).items():
        for i in v["advisories"]:
            newvuln = {
                "timestamp": datetime.datetime.now().isoformat(),
                "repo": repopath,
                "package": k,
                "severity": get_severity_from_nvd(i["cve"], nvd_apikey, lh),
                "ghsa": "",
                "cve": i["cve"],
                "description": i["title"]}
            if not in_inventory(newvuln, invpath, lh):
                vulns.append(newvuln)
                store_vuln(newvuln, invpath, lh)

    return vulns


def get_vulns_yarn(repopath: str, nvd_apikey: str, invpath: str, lh: LogHandler):
    vulns = []

    try:
        res = subprocess.run(["yarn", "audit", "--json"],
                             cwd=repopath,
                             stdout=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        lh.log_msg("yarn audit failed for " + repopath + ". retcode: " + str(e.returncode), "ERROR")
        return []

    for i in res.stdout.splitlines():
        vulndata = json.loads(i)
        if vulndata["type"] == "auditAdvisory":
            for j in vulndata["data"]["advisory"]["cves"]:
                newvuln = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "repo": repopath,
                    "package": vulndata["data"]["advisory"]["module_name"],
                    "severity": get_severity_from_nvd(j, nvd_apikey, lh),
                    "ghsa": "",
                    "cve": j,
                    "description": vulndata["data"]["advisory"]["overview"]}
                if not in_inventory(newvuln, invpath, lh):
                    vulns.append(newvuln)
                    store_vuln(newvuln, invpath, lh)

    return vulns


def get_vulns_npm(repopath: str, gh_apikey: str, nvd_apikey: str, invpath: str, npm_report_format: int,
                  lh: LogHandler):
    vulns = []

    res = subprocess.run(["npm", "audit",
                          "--registry=https://registry.npmjs.org",
                          "--json"],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         cwd=repopath)

    if res.stderr.decode("utf-8") != "":
        lh.log_msg("npm audit failed for " + repopath + ". stderr: " + res.stderr.decode("utf-8"), "ERROR")
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
                            "severity": get_severity_from_nvd(l, nvd_apikey, lh),
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
                        "severity": get_severity_from_nvd(cveid, nvd_apikey, lh),
                        "ghsa": j["url"].rsplit('/', 1)[1],
                        "cve": cveid,
                        "description": description
                    }
                    if not newvuln in vulns and not in_inventory(newvuln, invpath, lh):
                        vulns.append(newvuln)
                        store_vuln(newvuln, invpath, lh)

    return vulns


def get_vulns_gradle(repopath: str, nvd_apikey: str, invpath: str, lh: LogHandler):
    vulns = []

    gradle_init = """
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
        lh.log_msg("Unable to create " + repopath + "/depcheck-init.gradle: " + str(e), "ERROR")
        return []

    try:
        res = subprocess.run(["gradle", "--init-script", "depcheck-init.gradle", "dependencyCheckAnalyze"],
                             cwd=repopath,
                             stderr=subprocess.PIPE,
                             stdout=subprocess.PIPE)
    except Exception as e:
        lh.log_msg("Failed to run gradle dependency check on " + repopath + ": " + str(e), "ERROR")
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
                            "severity": get_severity_from_nvd(k["name"], nvd_apikey, lh),
                            "cve": k["name"],
                            "description": k["description"]
                        }

                        if not newvuln in vulns and not in_inventory(newvuln, invpath, lh):
                            vulns.append(newvuln)
                            store_vuln(newvuln, invpath, lh)

    return vulns


def get_vulns(checker: str, repopath: str, npm_report_format: int,
              gh_apikey: str, nvd_apikey: str, invpath: str, lh: LogHandler):
    vulns = []

    if checker == "composer":
        vulns += get_vulns_composer(repopath, nvd_apikey, invpath, lh)
    elif checker == "yarn":
        vulns += get_vulns_yarn(repopath, nvd_apikey, invpath, lh)
    elif checker == "npm":
        vulns += get_vulns_npm(repopath, gh_apikey, nvd_apikey, invpath, npm_report_format, lh)
    elif checker == "gradle":
        vulns += get_vulns_gradle(repopath, nvd_apikey, invpath, lh)
    else:
        lh.log_msg("Unsupported checker: " + checker, "ERROR")
        sys.exit(1)

    return vulns


def read_apikey(file: str, lh: LogHandler):
    try:
        with open(file, 'r') as fh:
            return fh.read().rstrip('\n')
    except Exception:
        lh.log_msg("Unable to read apikey from " + file, "ERROR")
        sys.exit(1)


def to_ecs(vuln):
    return {
        "timestamp": vuln["timestamp"],
        "service": {
            "name": "dep-vuln-checker"
        },
        "vulnerability": {
            "id": vuln["cve"] if vuln["cve"] != "" else vuln["ghsa"],
            "severity": vuln["severity"],
            "description": vuln["description"]
        },
        "package": {
            "name": vuln["package"]
        },
        "file": {
            "directory": vuln["repo"]
        }
    }


def print_vulns(vulns):
    for i in vulns:
        print(','.join([
            str(time.time()),
            i["repo"],
            i["package"],
            i["severity"],
            i["ghsa"],
            i["cve"]]))


def write_vulns_json(vulns, vulnlog: str, lh: LogHandler):
    if vulnlog != "stdout":
        try:
            fh = open(vulnlog, "a")
        except OSError:
            lh.log_msg("Failed to open " + vulnlog, "ERROR")
            sys.exit(1)

    if vulnlog != "stdout":
        with fh:
            for i in vulns:
                fh.write(json.dumps(to_ecs(i)) + "\n")
    else:
        for i in vulns:
            print(json.dumps(to_ecs(i)))


def patch_req_cache(redis_host, redis_port):
    redisbackend = requests_cache.backends.RedisCache(host=redis_host, port=redis_port)
    requests_cache.install_cache('globalcache', backend=redisbackend, expire_after=datetime.timedelta(days=7))


def main():
    args = parse_args()

    lh = LogHandler.LogHandler(args.applog, args.s)

    lh.log_msg("Started", "INFO")
    check_deps(lh)

    if args.invpath != "none":
        create_inventory(args.invpath, lh)

    if args.cachetype == "redis":
        patch_req_cache(args.redishost, args.redisport)

    allvulns = []
    # check a single repo
    if os.path.isdir(args.repolist):
        repo = args.repolist
        checkers = determine_checkers(repo)
        if len(checkers) > 0:
            for j in checkers:
                lh.log_msg("Getting vulnerabilities for repo=" + repo + ",checker=" + j, "INFO")
                allvulns = get_vulns(j, repo, check_npm_report_format(),
                                     read_apikey(args.gh_apikey_file, lh),
                                     read_apikey(args.nvd_apikey_file, lh),
                                     args.invpath, lh)
                lh.log_msg(str(len(allvulns)) + " new vulnerabilities found for repo=" + repo + ",checker=" + j, "INFO")
    # check a list of repos
    elif os.path.isfile(args.repolist):
        for i in read_repolist(args.repolist, lh):
            checkers = determine_checkers(i)
            if len(checkers) > 0:
                for j in checkers:
                    lh.log_msg("Getting vulnerabilities for repo=" + i + ",checker=" + j, "INFO")
                    newvulns = get_vulns(j, i, check_npm_report_format(),
                                         read_apikey(args.gh_apikey_file, lh),
                                         read_apikey(args.nvd_apikey_file, lh),
                                         args.invpath, lh)
                    allvulns += newvulns
                    lh.log_msg(str(len(newvulns)) + " new vulnerabilities found for repo=" + i + ",checker=" + j,
                               "INFO")
    else:
        lh.log_msg("repolist argument is not a dir or file, exit", "ERROR")

    write_vulns_json(allvulns, args.vulnlog, lh)
    lh.log_msg("Done", "INFO")


if __name__ == '__main__':
    main()
