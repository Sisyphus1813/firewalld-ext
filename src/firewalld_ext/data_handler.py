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


def save(current_ips, info):
    print("Saving settings...")
    if current_ips:
        with open("/var/lib/firewalld-ext/blocked_ips.json", "w") as f:
            json.dump(current_ips, f)
    if info:
        with open("/var/lib/firewalld-ext/info.json", "w") as f:
            json.dump(info, f)
    print("Done")


def load(value):
    if os.path.isdir("/var/lib/firewalld-ext"):
        match value:
            case "info"|"profile":
                try:
                    with open("/var/lib/firewalld-ext/info.json", "r") as f:
                        info = json.loads(f.read())
                except FileNotFoundError:
                    return None
                if value == "profile":
                    return info["Profile"].lower()
                else:
                    return info
            case "ips":
                try:
                    with open("/var/lib/firewalld-ext/blocked_ips.json", "r") as f:
                        current_ips = json.loads(f.read())
                except FileNotFoundError:
                    return None
                return current_ips
    else:
        os.mkdir("/var/lib/firewalld-ext/")
        return None
