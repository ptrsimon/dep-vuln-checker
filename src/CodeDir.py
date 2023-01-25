#!/usr/bin/python3
#
# CodeDir.py - handle vulncheck target directories
#

import os
import sys
import json
from typing import List
import VulnCheckers
from LogHandler import LogHandler
from InventoryRepository import InventoryRepository
from NvdRepository import NvdRepository
from GhsaRepository import GhsaRepository
from Vulnerability import Vulnerability


class CodeDir:
    def __init__(self, path: str, lh: LogHandler):
        self.path = path
        self.checkers: List[VulnCheckers.VulnChecker] = []
        self.lh = lh
        self.vulnerabilities: List[Vulnerability] = []

    def set_checkers(self, nvdrepo: NvdRepository, ghsarepo: GhsaRepository, invrepo: InventoryRepository = None):
        if os.path.isfile(self.path + "/package.json") and os.path.isfile(self.path + "/package-lock.json"):
            self.checkers.append(VulnCheckers.NpmVulnChecker(self.path, nvdrepo, ghsarepo, self.lh, invrepo))
            self.lh.log_msg("npm vulnerability checker set for directory " + self.path, "INFO")
        if os.path.isfile(self.path + "/composer.lock"):
            self.checkers.append(VulnCheckers.ComposerVulnChecker(self.path, nvdrepo, ghsarepo, self.lh, invrepo))
            self.lh.log_msg("composer vulnerability checker set for directory " + self.path, "INFO")
        if os.path.isfile(self.path + "/yarn.lock"):
            self.checkers.append(VulnCheckers.YarnVulnChecker(self.path, nvdrepo, ghsarepo, self.lh, invrepo))
            self.lh.log_msg("yarn vulnerability checker set for directory " + self.path, "INFO")
        if os.path.isdir(self.path + "/gradle"):
            self.checkers.append(VulnCheckers.GradleVulnChecker(self.path, nvdrepo, ghsarepo, self.lh, invrepo))
            self.lh.log_msg("gradle vulnerability checker set for directory " + self.path, "INFO")

    def run_checkers(self):
        for i in self.checkers:
            self.lh.log_msg("Running " + str(type(i)) + " on " + self.path, "INFO")
            self.vulnerabilities += i.do_check()

    def write_vulns_json(self, vulnlog: str):
        if vulnlog != "stdout":
            try:
                fh = open(vulnlog, "a")
            except OSError:
                self.lh.log_msg("Failed to open " + vulnlog, "ERROR")
                sys.exit(1)

            with fh:
                for i in self.vulnerabilities:
                    fh.write(json.dumps(i.to_ecs()) + "\n")
        else:
            for i in self.vulnerabilities:
                print(json.dumps(i.to_ecs()))
