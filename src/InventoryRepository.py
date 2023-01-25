#!/usr/bin/python3
#
# InventoryRepository.py - create, update and query repo of already logged vulnerabilities
#

import sys
import sqlite3
from LogHandler import LogHandler
from Vulnerability import Vulnerability


class InventoryRepository:
    def __init__(self, invpath: str, lh: LogHandler):
        self.lh = lh
        self.invpath = invpath
        try:
            self.conn = sqlite3.connect(invpath)
            self.create_inventory()
        except Exception as e:
            lh.log_msg("Failed to create SQLite database at " + invpath + ": " + str(e), "ERROR")
            sys.exit(1)

    def create_inventory(self):
        cur = self.conn.cursor()
        try:
            cur.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities
                            (directory TEXT, package_name TEXT, vulnerability_id TEXT)''')
            self.conn.commit()
        except Exception as e:
            self.lh.log_msg("Failed to create table in inventory at {}: {}".format(self.invpath, str(e)), "ERROR")
            self.conn.close()
            sys.exit(1)

    def store_vuln(self, vuln: Vulnerability):
        if self.invpath == "none":
            return

        cur = self.conn.cursor()
        try:
            cur.execute('''INSERT INTO vulnerabilities(directory, package_name, vulnerability_id)
                            VALUES(?,?,?)''', (vuln.dirpath, vuln.package, vuln.vulnid))
            self.conn.commit()
        except Exception as e:
            self.lh.log_msg("Failed to insert vulnerability {};{};{} into inventory at {}: {}"
                            .format(vuln.dirpath, vuln.package, vuln.vulnid, self.invpath, str(e)), "ERROR")
            self.conn.close()
            sys.exit(1)

    def in_inventory(self, vuln: Vulnerability):
        if self.invpath == "none":
            return False

        cur = self.conn.cursor()
        res = []
        try:
            cur.execute('''SELECT * FROM vulnerabilities WHERE 
                            directory="{}" AND package_name="{}" AND vulnerability_id="{}"'''.format(
                vuln.dirpath, vuln.package, vuln.package))
            res = cur.fetchall()
        except Exception as e:
            self.lh.log_msg("Failed to check if vulnerability {},{},{} is in inventory at {}: {}"
                            .format(vuln.dirpath, vuln.package, vuln.package, self.invpath, str(e)), "ERROR")
            self.conn.close()
            sys.exit(1)

        if len(res) < 1:
            return False
        else:
            return True
