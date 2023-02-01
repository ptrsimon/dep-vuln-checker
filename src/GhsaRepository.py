#!/usr/bin/python3
#
# GhsaRepository.py - query GHSA API
#
import git

from LogHandler import LogHandler
import requests
import json
import redis
import sys
import glob
from git import Repo
from os import path


class GhsaRepository:
    def __init__(self, gh_apikey: str, redis_host: str, redis_port: int, lh: LogHandler):
        self.gh_apikey = gh_apikey
        self.lh = lh
        self.redis_host = redis_host
        self.redis_port = redis_port

        try:
            self.rediscon = redis.Redis(host=self.redis_host, port=self.redis_port)
        except Exception as e:
            self.lh.log_msg("Failed to connect to " + self.redis_host + ": " + str(e), "ERROR")
            sys.exit(1)

        self.lh.log_msg("Connected to redis at {}:{}".format(self.redis_host, self.redis_port), "INFO")

    def download_ghsa_data(self, advrepopath):
        try:
            if path.isdir(advrepopath + "/.git"):
                self.lh.log_msg("Pulling GHSA repository at {}".format(advrepopath), "INFO")
                git.Repo(advrepopath).remotes.origin.pull()
                self.lh.log_msg("Finished pulling GHSA repository at {}".format(advrepopath), "INFO")
            else:
                self.lh.log_msg("Cloning GHSA repository to {}".format(advrepopath), "INFO")
                Repo.clone_from("https://github.com/github/advisory-database.git", advrepopath)
                self.lh.log_msg("Finished cloning GHSA repository to {}".format(advrepopath), "INFO")
        except Exception as e:
            self.lh.log_msg("Failed to clone GHSA repository to {}: {}".format(advrepopath, str(e)), "ERROR")
            sys.exit(1)

    def load_ghsa_data(self, advrepopath):
        for i in glob.glob(advrepopath + "/**/*.json", recursive=True):
            fh = open(i, 'r')
            data = json.load(fh)
            if "summary" in data:
                self.rediscon.hset("ghsa_details_cache", data["id"], data["summary"])
            else:
                self.rediscon.hset("ghsa_details_cache", data["id"], data["details"])

    def get_details_from_gh(self, ghsa_id: str):
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

        if "summary" in data:
            return cveid, rdict["data"]["securityAdvisory"]["summary"]
        else:
            return cveid, rdict["data"]["securityAdvisory"]["details"]

    def get_details(self, ghsa_id: str):
        details = ""

        try:
            details = self.rediscon.hget("ghsa_details_cache", ghsa_id)
        except Exception as e:
            self.lh.log_msg("Failed to get details for " + ghsa_id + " from local details cache: " + str(e), "WARNING")

        if details is None:
            return self.get_details_from_gh(ghsa_id)
        else:
            return details.decode("utf-8")