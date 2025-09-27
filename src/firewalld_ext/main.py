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

from firewalld_ext import update
from firewalld_ext import data_handler
import argparse
import asyncio
import sys
import os

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--refresh",
    help="Update blocked IPs while keeping older entries.",
    action="store_true",
)
group.add_argument(
    "--complete-refresh",
    help="Update blocked IPs, removing all prior entries.",
    action="store_true",
)
group.add_argument(
    "--remove-all",
    help="Remove ALL currently blocked IPs from iptables.",
    action="store_true",
)
group.add_argument(
    "--status",
    help="Show firewalld-ext status and statistics",
    action="store_true",
)
group.add_argument(
    "--show-ips", help="Show all currently blocked IPs.", action="store_true"
)
group.add_argument(
    "--set-profile",
    metavar="PROFILE",
    help="Set the active profile to PROFILE.",
    type=str,
)
parser.add_argument(
    "-v", "--verbose",
    action="store_true",
    help="Enable verbose output"
)

def main():
    args = parser.parse_args()
    if os.geteuid() != 0 and not args.status and not args.show_ips:
        print("Operation aborted: Please run as root!")
        return
    elif len(sys.argv) == 1:
        print("Must include an argument. Try: firewalld-ext --help")
        return
    match True:
        case _ if args.refresh:
            asyncio.run(update.main("refresh", args.verbose))
        case _ if args.complete_refresh:
            asyncio.run(update.main("complete_refresh", args.verbose))
        case _ if args.remove_all:
            asyncio.run(update.main("remove_all", args.verbose))
        case _ if args.status:
            info = data_handler.load("info")
            for key, value in info.items():
                print(f"{key}: {value}")
        case _ if args.show_ips:
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
