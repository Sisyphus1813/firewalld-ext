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

from firewalld_ext import data_handler, update

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


def remove_all():
    paths = {
        "/etc/firewalld/direct.xml",
        "/etc/firewalld/ipsets/blocked_v4.xml",
        "/etc/firewalld/ipsets/blocked_v6.xml",
        "/var/lib/firewalld-ext/",
        "/etc/firewalld-ext",
    }
    for path in paths:
        try:
            os.remove(path)
        except FileNotFoundError:
            print(f"{path} does not exist, skipping...")
        except IsADirectoryError:
            shutil.rmtree(path)
    subprocess.run(["firewall-cmd", "--complete-reload"])


def main():
    args = parser.parse_args()
    if os.geteuid() != 0 and not args.status and not args.show_subnets:
        print("Operation aborted: Please run as root!")
        sys.exit(1)
    os.makedirs("/var/lib/firewalld-ext/", exist_ok=True)
    os.makedirs("/etc/firewalld-ext/temp", exist_ok=True)
    match True:
        case _ if args.refresh:
            asyncio.run(update.main(args.verbose))
        case _ if args.remove_all:
            remove_all()
        case _ if args.status:
            info = data_handler.load("info")
            for key, value in info.items():
                print(f"{key}: {value}")
        case _ if args.show_subnets:
            current_ips = data_handler.load("ips")
            for key, value in current_ips.items():
                print(f"\n{key.upper()} Networks:")
                for ip in value:
                    print(ip)
        case _ if args.set_profile:
            info = data_handler.load("info")
            if not info:
                info = {}
            info["Profile"] = args.set_profile
            data_handler.save(None, info, args.verbose)
            print("success")
        case _:
            raise AssertionError(
                "This code should be unreachable. Argparse may not be working."
            )
