#!/usr/bin/python3
#
# NvdRepository.py - fetch, update and query local NVD cache
#

import sys
import LogHandler
import gzip
import json
from urllib.request import urlopen
from datetime import date
import requests
import redis
from ratelimit import limits, sleep_and_retry


class NvdRepository:
    def __init__(self, nvd_apikey: str, rediscon: redis.Redis, lh: LogHandler):
        self.nvd_apikey = nvd_apikey
        self.rediscon = rediscon
        self.lh = lh

    def fetch_json(self, years):
        for i in years:
            try:
                self.lh.log_msg("Downloading https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz".format(i), "INFO")
                resp = urlopen("https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz".format(i))
                CHUNK = 16 * 1024
                with open("{}/{}.json.gz".format("/tmp", i), 'wb') as fh:
                    while True:
                        chunk = resp.read(CHUNK)
                        if not chunk:
                            break
                        fh.write(chunk)
            except Exception as e:
                self.lh.log_msg("Failed to download NVD JSON files: " + str(e), "ERROR")
                sys.exit(1)

        self.lh.log_msg("Downloaded NVD JSON files", "INFO")

    def load_jsongz(self, path):
        try:
            with gzip.open(path, 'rb') as fh:
                cvedb = json.load(fh)
        except Exception as e:
            self.lh.log_msg("Failed to parse NVD JSON dump: " + str(e), "ERROR")
            sys.exit(1)

        self.lh.log_msg("Processing {}".format(path), "INFO")

        for i in cvedb["CVE_Items"]:
            severity = "unknown"
            if "baseMetricV2" in i["impact"] and "severity" in i["impact"]["baseMetricV2"]:
                severity = i["impact"]["baseMetricV2"]["severity"]
            if "baseMetricV3" in i["impact"] and "severity" in i["impact"]["baseMetricV3"]:
                severity = i["impact"]["baseMetricV3"]["severity"]
            if "baseMetricV31" in i["impact"] and "severity" in i["impact"]["baseMetricV31"]:
                severity = i["impact"]["baseMetricV31"]["severity"]

            self.rediscon.hset("nvd_severity_cache", i["cve"]["CVE_data_meta"]["ID"], severity)

    # downloads this year's json and adds new entries to DB
    def update(self):
        self.fetch_json([date.today().year])
        self.load_jsongz("/tmp/" + str(date.today().year) + ".json.gz")

    # downloads all available jsons and adds all entries to DB
    def first_run(self):
        self.fetch_json(range(2002, date.today().year))
        for i in range(2002, date.today().year):
            self.load_jsongz("/tmp/" + str(i) + ".json.gz")

    @sleep_and_retry
    @limits(calls=10, period=60)
    def get_severity_from_nvd(self, cve_id: str):
        severity = ""

        headers = {"apiKey": self.nvd_apikey}

        try:
            r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cve_id, headers=headers)

            if r.status_code != 200:
                raise Exception('API response: {}'.format(r.status_code))

            severity = json.loads(r.text)["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"][
                "baseSeverity"]
        except Exception as e:
            self.lh.log_msg("Failed to get severity for " + cve_id + " from NVD API: " + str(e), "WARNING")
            return "unknown"

        return severity

    def get_severity(self, cveid: str):
        severity = ""

        if cveid == "":
            self.lh.log_msg("Empty CVE ID for vulnerability, setting severity to unknown", "INFO")
            return "unknown"

        try:
            severity = self.rediscon.hget("nvd_severity_cache", cveid)
        except Exception as e:
            self.lh.log_msg("Failed to get severity for " + cveid + " from local severity cache: " + str(e), "WARNING")

        if severity is None:
            self.lh.log_msg("Severity for " + cveid + " not found in local cache, falling back to querying NVD API", "WARNING")
            return self.get_severity_from_nvd(cveid)
        else:
            return severity.decode("utf-8")
