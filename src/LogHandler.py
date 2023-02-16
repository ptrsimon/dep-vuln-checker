#!/usr/bin/python3
#
# LogHandler.py - write application log
#

import datetime
import sys

class LogHandler:
    def __init__(self, logfile: str, silent: bool):
        self.logfile = logfile
        self.silent = silent

    def log_msg(self, msg: str, level: str):
        if not self.silent:
            print("[{}] {}".format(level, msg))

        if self.logfile == "none":
            return

        try:
            fh = open(self.logfile, 'a')
        except OSError:
            print("Failed to open logfile: " + self.logfile)
            sys.exit(1)

        with fh:
            fh.write("{} {} {}\n".format(
                datetime.datetime.now().isoformat(),
                level,
                msg))
