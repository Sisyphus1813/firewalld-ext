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

import argparse
import asyncio
import os
import shutil
import subprocess
import sys

import data_handler
import update
from sources import Profile

parser = argparse.ArgumentParser()
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Enable verbose output"
)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--status",
    help="Show firewalld-ext status and statistics",
    action="store_true",
)
group.add_argument(
    "--show-subnets",
    help="Dump all currently blocked CIDR ranges to stdout",
    action="store_true",
)
group.add_argument(
    "--refresh",
    help="Update blocked CIDRs",
    action="store_true",
)
group.add_argument(
    "--remove-all",
    help=(
        "*DANGEROUS*: Remove all currently blocked CIDRs and reset firewall state. "
        "This clears ipsets, firewalld direct rules, and application configuration. "
        "Only use this if you fully understand the consequences."
    ),
    action="store_true",
)
group.add_argument(
    "--set-profile",
    metavar="<PROFILE>",
    help="Set the active profile to <PROFILE>",
    type=str,
)


def remove_all() -> None:
    paths = {
        "/etc/firewalld/direct.xml",
        "/etc/firewalld/ipsets/blocked_v4.xml",
        "/etc/firewalld/ipsets/blocked_v6.xml",
        "/etc/firewalld/temp",
        "/etc/firewalld-ext",
        "/var/lib/firewalld-ext/",
    }
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            print(f"{path} does not exist, skipping...")
        except IsADirectoryError:
            shutil.rmtree(path)
    subprocess.run(["firewall-cmd", "--complete-reload"])


def main() -> None:
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("Operation aborted: Please run as root!")
        sys.exit(1)
    os.makedirs("/var/lib/firewalld-ext/", exist_ok=True)
    os.makedirs("/etc/firewalld/temp", exist_ok=True)
    if args.remove_all:
        remove_all()
        return
    appdata = data_handler.load_appdata(args.verbose)
    if not appdata or args.refresh:
        appdata = asyncio.run(update.main(args.verbose, appdata if appdata else None))
        data_handler.save(appdata, args.verbose)
    elif args.set_profile:
        match args.set_profile.lower():
            case "open":
                appdata.profile = Profile.OPEN
            case "lenient":
                appdata.profile = Profile.LENIENT
            case "balanced":
                appdata.profile = Profile.BALANCED
            case "firm":
                appdata.profile = Profile.FIRM
            case "strict":
                appdata.profile = Profile.STRICT
            case _:
                print(
                    "Unexpected value for Profile. Expected one of: [open, lenient, balanced, firm, strict]"
                )
        print("success")
        data_handler.save(appdata, args.verbose)
    elif args.status:
        print(appdata)
    elif args.show_subnets:
        print("IPv4 Networks:")
        for ip in appdata.ipv4_networks:
            print(f"\t{ip}")
        print("\nIPv6 Networks:")
        for ip in appdata.ipv6_networks:
            print(f"\t{ip}")
