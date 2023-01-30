#!/usr/bin/python3
#
# GhsaRepository.py - query GHSA API
#

from LogHandler import LogHandler
import requests
import json


class GhsaRepository:
    def __init__(self, gh_apikey: str, lh: LogHandler):
        self.gh_apikey = gh_apikey
        self.lh = lh

    def get_details(self, ghsa_id: str):
        cveid = ""

        headers = {"Authorization": "Bearer " + self.gh_apikey}
        query = {"query": "query {securityAdvisory(ghsaId:\"" + ghsa_id + "\") { summary identifiers {type value}}}"}

        r = requests.post('https://api.github.com/graphql', json=query, headers=headers)

        if r.status_code != 200:
            raise Exception('Failed to get details from GHSA, API response: {}'.format(r.status_code))

        rdict = json.loads(r.text)
        for i in rdict["data"]["securityAdvisory"]["identifiers"]:
            if i["type"] == "CVE":
                cveid = i["value"]

        return cveid, rdict["data"]["securityAdvisory"]["summary"]
