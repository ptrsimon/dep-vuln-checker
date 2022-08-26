#!/usr/bin/python3
#
# LocalNvd.py - handle local nvd cache
#

class LocalNvd:
    def __init__(self, backend, nvd_apikey):
        self.backend = backend
        self.nvd_apikey = nvd_apikey

    def initdb(self):
        if self.backend == "mysql":
            self.initdb_mysql()
        else:
            pass

    def initdb_mysql(self):
        pass

    def update(self):
        pass

    def get_severity(self, cveid):
        pass
