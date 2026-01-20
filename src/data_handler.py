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

import pickle
import sys
from datetime import datetime
from enum import Enum, auto
from ipaddress import (
    IPv4Network,
    IPv6Network,
)
from typing import Optional

from sources import Profile
from systemd import journal


class MetaData(Enum):
    IPV4_LEN = auto()
    IPV6_LEN = auto()
    TOTAL_LEN = auto()


class AppData:
    def __init__(
        self,
        profile: Profile,
        ipv4_networks: set[IPv4Network],
        ipv6_networks: set[IPv6Network],
        time_stamp: datetime,
    ) -> None:
        self.profile = profile
        self.ipv4_networks = ipv4_networks
        self.ipv6_networks = ipv6_networks
        self.metadata: dict[MetaData, int] = {
            MetaData.IPV4_LEN: len(self.ipv4_networks),
            MetaData.IPV6_LEN: len(self.ipv6_networks),
            MetaData.TOTAL_LEN: len(self.ipv4_networks.union(self.ipv6_networks)),
        }
        self.last_updated = time_stamp
        self.white_list = set()

    def __str__(self) -> str:
        return (
            f"Profile: {self.profile.name.title()}\n"
            f"IPV4 Networks: {self.metadata[MetaData.IPV4_LEN]}\n"
            f"IPV6 Networks: {self.metadata[MetaData.IPV6_LEN]}\n"
            f"Total Number of networks blocked: {self.metadata[MetaData.TOTAL_LEN]}\n"
            f"Last updated: {self.last_updated}"
        )


def save(appdata: AppData, verbose: bool) -> None:
    if verbose:
        print("saving settings...")
    try:
        with open("/var/lib/firewalld-ext/appdata.pkl", "wb") as file:
            pickle.dump(
                appdata,
                file,
                protocol=pickle.HIGHEST_PROTOCOL,
            )
        if verbose:
            print("done")
    except Exception as e:
        journal.send(
            f"/var/lib/firewalld-ext/ directory possibly corrupted. {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        sys.exit(1)


def load_appdata(verbose: bool) -> Optional[AppData]:
    try:
        with open("/var/lib/firewalld-ext/appdata.pkl", "rb") as file:
            appdata = pickle.load(file)
            return appdata
    except FileNotFoundError:
        journal.send(
            "AppData file not found...Falling back to defaults.",
            PRIORITY=4,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        if verbose:
            print("AppData file not found...Falling back to defaults.")
