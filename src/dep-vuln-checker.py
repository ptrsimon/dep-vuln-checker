#!/usr/bin/python3
#
# dep-vuln-checker.py - check project dependencies for known vulnerabilities
#

import sys
import subprocess
import os.path
import requests_cache
import datetime
import argparse
import LogHandler
import NvdRepository
import GhsaRepository
import InventoryRepository
from CodeDir import CodeDir


def parse_args():
    parser = argparse.ArgumentParser(description='Check project dependencies for known vulnerabilities')

    parser.add_argument('-g', dest="gh_apikey_file", type=str,
                        help="GitHub apikey location (default: /etc/dep-vuln-checker/gh-apikey)",
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
    parser.add_argument('-c', dest="reqcachetype", type=str,
                        help="request cache type. Allowed values: redis, sqlite (no request cache used if omitted)",
                        default=None)
    parser.add_argument('-cp', dest="reqcachepath", type=str,
                        help="reqest cache database path when using sqlite cache type (default: /var/lib/dep-vuln-checker/reqcache.db",
                        default="/var/lib/dep-vuln-checker/reqcache.db")
    parser.add_argument('-rh', dest="redishost", type=str,
                        help="redis host for request cache and/or severity cache (default: 127.0.0.1)",
                        default="127.0.0.1")
    parser.add_argument('-rp', dest="redisport", type=int,
                        help="redis port for request cache and/or severity cache (default: 6379)",
                        default=6379)
    parser.add_argument("-s", action="store_true",
                        help="silent mode - no output")
    parser.add_argument("-t", dest="nvd_download_tmpdir", type=str,
                        help="temp directory to download NVD JSON files (default: /tmp)",
                        default="/tmp")
    parser.add_argument("-I", action="store_true",
                        help="initialize local NVD cache and exit")
    parser.add_argument('dirlist', nargs='?' if '-I' in sys.argv else 1,
                        help="location of newline separated file which contains the project dir paths to check OR a single path if only one project needs to be checked")

    return parser.parse_args()


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

    try:
        res = subprocess.run(["yarn", "-v"],
                             stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        if res.returncode != 0:
            raise Exception()
    except Exception as e:
        lh.log_msg("yarn not available: " + str(e), "ERROR")
        sys.exit(1)



def read_repolist(path: str, lh: LogHandler):
    repolist = []
    try:
        with open(path, 'r') as fh:
            repolist = filter(None, fh.read().split('\n'))
    except Exception as e:
        lh.log_msg("Unable to read repolist: " + str(e), "ERROR")
        sys.exit(1)
    return repolist


def read_apikey(file: str, lh: LogHandler):
    try:
        with open(file, 'r') as fh:
            return fh.read().rstrip('\n')
    except Exception:
        lh.log_msg("Unable to read apikey from " + file, "ERROR")
        sys.exit(1)


def patch_req_cache_redis(redis_host, redis_port):
    redisbackend = requests_cache.backends.RedisCache(host=redis_host, port=redis_port)
    requests_cache.install_cache('globalcache', backend=redisbackend, expire_after=datetime.timedelta(days=7))


def patch_req_cache_sqlite(reqcachepath):
    sqlitebackend = requests_cache.backends.SQLiteCache(db_path=reqcachepath)
    requests_cache.install_cache('globalcache', backend=sqlitebackend, expire_after=datetime.timedelta(days=7))


def main():
    args = parse_args()

    lh = LogHandler.LogHandler(args.applog, args.s)
    nvdrepo = NvdRepository.NvdRepository(read_apikey(args.nvd_apikey_file, lh),
                                          args.redishost, args.redisport, lh)
    ghsarepo = GhsaRepository.GhsaRepository(read_apikey(args.gh_apikey_file, lh), lh)

    check_deps(lh)

    if args.invpath != "none":
        inventoryrepo = InventoryRepository.InventoryRepository(args.invpath, lh)
    else:
        inventoryrepo = None

    if args.reqcachetype == "redis":
        patch_req_cache_redis(args.redishost, args.redisport)
    if args.reqcachetype == "sqlite":
        patch_req_cache_sqlite(args.reqcachepath)

    if args.I:
        lh.log_msg("-I given, creating local severity database from scratch", "INFO")
        nvdrepo.first_run()
        sys.exit(0)

    if os.path.isdir(args.dirlist):
        directory = CodeDir(args.dirlist, lh)
        directory.set_checkers(nvdrepo, ghsarepo, inventoryrepo)
        directory.run_checkers()
        directory.write_vulns_json(args.vulnlog)
    elif os.path.isfile(args.dirlist):
        for i in read_repolist(args.dirlist, lh):
            directory = CodeDir(i, lh)
            directory.set_checkers(nvdrepo, ghsarepo, inventoryrepo)
            directory.run_checkers()
            directory.write_vulns_json(args.vulnlog)
    else:
        lh.log_msg("repolist argument is not a dir or file, exit", "ERROR")

    lh.log_msg("Done", "INFO")


if __name__ == '__main__':
    main()
