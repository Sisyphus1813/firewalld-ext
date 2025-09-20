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

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--refresh-keep",
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
    "--show-stats",
    help="Show statistics on the number of currently blocked IPs.",
    action="store_true",
)
group.add_argument(
    "--show-ips", help="Show all currently blocked IPs.", action="store_true"
)

def main():
    args = parser.parse_args()
    match True:
        case _ if args.refresh_keep:
            asyncio.run(update.main("refresh_keep"))
        case _ if args.complete_refresh:
            asyncio.run(update.main("complete_refresh"))
        case _ if args.remove_all:
            asyncio.run(update.main("remove_all"))
        case _ if args.show_stats:
            info = data_handler.load("info")
            for key, value in info.items():
                print(f"{key}: {value}")
        case _ if args.show_ips:
            current_ips = data_handler.load("ips")
            print(current_ips)
