# Copyright (C) 2025  Sisyphus1813
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import json
import sys
from json.decoder import JSONDecodeError
from typing import Literal

from systemd import journal


def save(current_ips, info, verbose):
    if verbose:
        print("saving settings...")
    try:
        if current_ips:
            with open("/var/lib/firewalld-ext/blocked_ips.json", "w") as f:
                json.dump(current_ips, f)
        if info:
            with open("/var/lib/firewalld-ext/info.json", "w") as f:
                json.dump(info, f)
        if verbose:
            print("done")
    except Exception as e:
        journal.send(
            f"/var/lib/firewalld-ext/ directory possibly corrupted. {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        sys.exit(1)


def load(value: Literal["info", "profile", "ips"]):
    try:
        match value:
            case "info" | "profile":
                with open("/var/lib/firewalld-ext/info.json", "r") as f:
                    try:
                        data = json.loads(f.read())
                        if value == "profile":
                            return data["Profile"].lower()
                        else:
                            return data
                    except JSONDecodeError:
                        journal.send(
                            "Failed to json decode /var/lib/firewalld-ext/info.json\nTry sudo firewalld-ext --remove-all\nthen\nsudo firewalld-ext --complete-reload",
                            PRIORITY=4,
                            SYSLOG_IDENTIFIER="firewalld-ext",
                        )
                        return None
            case "ips":
                with open("/var/lib/firewalld-ext/blocked_ips.json", "r") as f:
                    try:
                        current_ips = json.loads(f.read())
                        return current_ips
                    except JSONDecodeError:
                        journal.send(
                            "Failed to json decode /var/lib/firewalld-ext/blocked_ips.json.\nTry sudo firewalld-ext --remove-all\nthen\nsudo firewalld-ext --complete-reload",
                            PRIORITY=4,
                            SYSLOG_IDENTIFIER="firewalld-ext",
                        )
                        return None
    except FileNotFoundError:
        match value:
            case "info" | "profile":
                journal.send(
                    "Failed to find info.json in application directory.",
                    PRIORITY=4,
                    SYSLOG_IDENTIFIER="firewalld-ext",
                )
            case "ips":
                journal.send(
                    "Failed to find blocked_ips.json in application directory",
                    PRIORITY=4,
                    SYSLOG_IDENTIFIER="firewalld-ext",
                )
        return None
