#!/usr/bin/python3
#
# VulnCheckers.py - dependency checker classes
#

from abc import ABC, abstractmethod
from LogHandler import LogHandler
from InventoryRepository import InventoryRepository
from NvdRepository import NvdRepository
from GhsaRepository import GhsaRepository
from Vulnerability import Vulnerability
from typing import List
import subprocess
import json
import glob


class VulnChecker(ABC):
    def __init__(self, directory: str, nvdrepo: NvdRepository, ghsarepo: GhsaRepository,
                 lh: LogHandler, invrepo: InventoryRepository = None):
        self.directory = directory
        self.invrepo = invrepo
        self.nvdrepo = nvdrepo
        self.ghasrepo = ghsarepo
        self.lh = lh

    @abstractmethod
    def do_check(self) -> List[Vulnerability]:
        pass

    def in_invrepo(self, vuln: Vulnerability) -> bool:
        if self.invrepo is not None:
            return self.invrepo.in_inventory(vuln)
        else:
            return False

    def append_to_invrepo(self, vuln: Vulnerability) -> None:
        if self.invrepo is not None:
            self.invrepo.store_vuln(vuln)


class ComposerVulnChecker(VulnChecker):
    def __init__(self, directory: str, nvdrepo: NvdRepository, ghsarepo: GhsaRepository,
                 lh: LogHandler, invrepo: InventoryRepository = None):
        super().__init__(directory, nvdrepo, ghsarepo, lh, invrepo)

    def do_check(self) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []

        try:
            res = subprocess.run(["local-php-security-checker",
                                  "-path=" + self.directory,
                                  "-format", "json"],
                                 stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.lh.log_msg("local-php-security-checker failed for " +
                            self.directory + ". retcode: " + str(e.returncode), "ERROR")
            return []

        for k, v in json.loads(res.stdout).items():
            for i in v["advisories"]:
                newvuln = Vulnerability(
                    dirpath=self.directory,
                    package=k,
                    vulnid=i["cve"],
                    severity=self.nvdrepo.get_severity(i["cve"]),
                    description=i["title"]
                )
                if not self.in_invrepo(newvuln):
                    vulns.append(newvuln)
                    self.append_to_invrepo(newvuln)

        return vulns


class YarnVulnChecker(VulnChecker):
    def __init__(self, directory: str, nvdrepo: NvdRepository, ghsarepo: GhsaRepository,
                 lh: LogHandler, invrepo: InventoryRepository = None):
        super().__init__(directory, nvdrepo, ghsarepo, lh, invrepo)

    def do_check(self) -> []:
        vulns = []

        try:
            res = subprocess.run(["yarn", "audit", "--json"],
                                 cwd=self.directory,
                                 stdout=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            self.lh.log_msg("yarn audit failed for " + self.directory + ". retcode: " + str(e.returncode), "ERROR")
            return []

        for i in res.stdout.splitlines():
            vulndata = json.loads(i)
            if vulndata["type"] == "auditAdvisory":
                for j in vulndata["data"]["advisory"]["cves"]:
                    newvuln = Vulnerability(
                        dirpath=self.directory,
                        package=vulndata["data"]["advisory"]["module_name"],
                        vulnid=j,
                        severity=self.nvdrepo.get_severity(j),
                        description=vulndata["data"]["advisory"]["title"]
                    )
                    if newvuln not in vulns and not self.in_invrepo(newvuln):
                        vulns.append(newvuln)
                        self.append_to_invrepo(newvuln)

        return vulns


class NpmVulnChecker(VulnChecker):
    def __init__(self, directory: str, nvdrepo: NvdRepository, ghsarepo: GhsaRepository,
                 lh: LogHandler, invrepo: InventoryRepository = None):
        super().__init__(directory, nvdrepo, ghsarepo, lh, invrepo)
        self.npm_report_format = self.check_npm_report_format()

    @staticmethod
    def check_npm_report_format() -> int:
        res = subprocess.run(["npm", "-v"],
                             stdout=subprocess.PIPE)
        npmver = res.stdout.decode("utf-8").split('.')[0]
        if int(npmver) >= 7:
            return 2
        else:
            return 1

    def do_check(self) -> []:
        vulns = []

        res = subprocess.run(["npm", "audit",
                              "--registry=https://registry.npmjs.org",
                              "--json"],
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             cwd=self.directory)

        if res.stderr.decode("utf-8") != "":
            self.lh.log_msg("npm audit failed for " + self.directory + ". stderr: " + res.stderr.decode("utf-8"),
                            "ERROR")
            return []

        if self.npm_report_format == 1:
            for i in json.loads(res.stdout)['advisories'].values():
                newvuln = Vulnerability(
                    dirpath=self.directory,
                    package=i["module_name"],
                    vulnid=i["cves"][0],
                    severity=self.nvdrepo.get_severity(i["cves"][0]),
                    description=self.ghasrepo.get_details(i["github_advisory_id"])
                )
                if newvuln not in vulns and not self.in_invrepo(newvuln):
                    vulns.append(newvuln)
                    self.append_to_invrepo(newvuln)

        elif self.npm_report_format == 2:
            for i in json.loads(res.stdout)["vulnerabilities"].values():
                for j in i["via"]:
                    if "url" in j and type(j) is dict:
                        cveid, description = self.ghasrepo.get_details(j["url"].rsplit('/', 1)[1])
                        newvuln = Vulnerability(
                            dirpath=self.directory,
                            package=i["name"],
                            vulnid=cveid,
                            severity=self.nvdrepo.get_severity(cveid),
                            description=description
                        )
                        if newvuln not in vulns and not self.in_invrepo(newvuln):
                            vulns.append(newvuln)
                            self.append_to_invrepo(newvuln)

        else:
            self.lh.log_msg("Wrong npm report format: " + str(self.npm_report_format), "ERROR")

        return vulns


class GradleVulnChecker(VulnChecker):
    def __init__(self, directory: str, nvdrepo: NvdRepository, ghsarepo: GhsaRepository,
                 lh: LogHandler, invrepo: InventoryRepository = None):
        super().__init__(directory, nvdrepo, ghsarepo, lh, invrepo)

    def do_check(self) -> []:
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
            with open(self.directory + "/depcheck-init.gradle", 'w') as fh:
                fh.write(gradle_init)
        except Exception as e:
            self.lh.log_msg("Unable to create " + self.directory + "/depcheck-init.gradle: " + str(e), "ERROR")
            return []

        try:
            subprocess.run(["gradle", "--init-script", "depcheck-init.gradle", "dependencyCheckAnalyze"],
                           cwd=self.directory,
                           stderr=subprocess.PIPE,
                           stdout=subprocess.PIPE)
        except Exception as e:
            self.lh.log_msg("Failed to run gradle dependency check on " + self.directory + ": " + str(e), "ERROR")
            return []

        for i in glob.glob(self.directory + "/**/build/reports/dependency-check-report.json"):
            with open(i, 'r') as fh:
                report = json.load(fh)
                for j in report["dependencies"]:
                    if "vulnerabilities" in j.keys():
                        for k in j["vulnerabilities"]:
                            newvuln = Vulnerability(
                                dirpath=self.directory,
                                package=j["packages"][0]["id"].split(':')[1],
                                vulnid=k["name"],
                                severity=self.nvdrepo.get_severity(k["name"]),
                                description=k["description"]
                            )

                            if newvuln not in vulns and not self.in_invrepo(newvuln):
                                vulns.append(newvuln)
                                self.append_to_invrepo(newvuln)

        return vulns
