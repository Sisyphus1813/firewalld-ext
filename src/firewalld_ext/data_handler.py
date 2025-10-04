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
import os
from systemd import journal
from json.decoder import JSONDecodeError


def save(current_ips, info, verbose):
    if verbose:
        print("Saving settings...")
    try:
        os.makedirs("/var/lib/firewalld-ext", exist_ok=True)
        if current_ips:
            with open("/var/lib/firewalld-ext/blocked_ips.json", "w") as f:
                json.dump(current_ips, f)
        if info:
            with open("/var/lib/firewalld-ext/info.json", "w") as f:
                json.dump(info, f)
        if verbose:
            print("Done")
    except Exception as e:
        match e:
            case PermissionError():
                journal.send(
                    f"Permission denied for the following reason: {e}. Please ensure you are running with sudo.",
                    PRIORITY=3,
                    SYSLOG_IDENTIFIER="firewalld-ext"
                )
            case IsADirectoryError():
                journal.send(
                    "/var/lib/firewalld-ext/ Directory is corrupted. Please run sudo firewalld-ext --remove-all\nthen\n sudo firewalld-ext --complete-reload",
                    PRIORITY=3,
                    SYSLOG_IDENTIFIER="firewalld-ext"
                )
            case OSError():
                journal.send(
                    f"Fatal OS error occured: {e}",
                    PRIORITY=2,
                    SYSLOG_IDENTIFIER="firewalld-ext"
                )
            case _:
                journal.send(
                    f"Unhandled exception: {e}",
                    PRIORITY=3,
                    SYSLOG_IDENTIFIER="firewalld-ext"
                )


def load(value):
    if os.path.isdir("/var/lib/firewalld-ext"):
        try:
            match value:
                case "info"|"profile":
                    with open("/var/lib/firewalld-ext/info.json", "r") as f:
                        try:
                            info = json.loads(f.read())
                        except JSONDecodeError:
                            journal.send(
                                "Failed to json decode /var/lib/firewalld-ext/info.json\nTry sudo firewalld-ext --remove-all\nthen\nsudo firewalld-ext --complete-reload",
                                PRIORITY=4,
                                SYSLOG_IDENTIFIER="firewalld-ext"
                            )
                            return None
                    if value == "profile":
                        return info["Profile"].lower()
                    else:
                        return info
                case "ips":
                    with open("/var/lib/firewalld-ext/blocked_ips.json", "r") as f:
                        try:
                            current_ips = json.loads(f.read())
                        except JSONDecodeError:
                            journal.send(
                                "Failed to json decode /var/lib/firewalld-ext/blocked_ips.json.\nTry sudo firewalld-ext --remove-all\nthen\nsudo firewalld-ext --complete-reload",
                                PRIORITY=4,
                                SYSLOG_IDENTIFIER="firewalld-ext"
                            )
                            return None
                    return current_ips
                case _:
                    journal.send(
                        "Invalid value recieved on load() function in data_handler.py",
                        PRIORITY=4,
                        SYSLOG_IDENTIFIER="firewalld-ext"
                    )
        except FileNotFoundError:
            match value:
                case "info"|"profile":
                    journal.send(
                        "Failed to find info.json in application directory.",
                        PRIORITY=4,
                        SYSLOG_IDENTIFIER="firewalld-ext"
                    )
                case "ips":
                    journal.send(
                        "Failed to find blocked_ips.json in application directory",
                        PRIORITY=4,
                        SYSLOG_IDENTIFIER="firewalld-ext"
                    )
            return None
    else:
        os.makedirs("/var/lib/firewalld-ext/")
        journal.send(
            "No application directory found. Making Directory...",
            PRIORITY=4,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return None
