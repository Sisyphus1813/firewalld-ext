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

import asyncio
import datetime
import ipaddress
import json
import sys
from json.decoder import JSONDecodeError
from typing import Optional

import aiohttp

from apply_rules import apply_rules
from data_handler import AppData
from sources import Profile
from systemd import journal


async def fetch(session: aiohttp.ClientSession, source: str) -> dict[str, str] | None:
    for i in range(5):
        try:
            async with session.get(source) as response:
                data = await response.text()
                if not data:
                    journal.send(
                        f"Failed to fetch {source}...retrying",
                        PRIORITY=4,
                        SYSLOG_IDENTIFIER="firewalld-ext",
                    )
                    await asyncio.sleep(i)
                    continue
                else:
                    return {"source": source, "response": data}
        except Exception as e:
            journal.send(
                f"Failed to fetch {source}...retrying\n(ERROR: {e})",
                PRIORITY=4,
                SYSLOG_IDENTIFIER="firewalld-ext",
            )
            await asyncio.sleep(i)
            continue
    journal.send(
        f"Failed to fetch {source} 5 times in a row. Retries expired.",
        PRIORITY=3,
        SYSLOG_IDENTIFIER="firewalld-ext",
    )
    return None


async def poll_sources(sources: Profile) -> list[dict[str, str] | None]:
    async with aiohttp.ClientSession() as session:
        tasks = {fetch(session, source) for source in sources.value}
        return await asyncio.gather(*tasks)


def parse(
    data: dict[str, str],
) -> tuple[set[ipaddress.IPv4Network], set[ipaddress.IPv6Network]]:
    ipv4 = set()
    ipv6 = set()
    for line in data["response"].splitlines():
        if "spamhaus" in data["source"]:
            try:
                line = json.loads(line)
                line = line["cidr"]
            except (JSONDecodeError, KeyError):
                journal.send(
                    f"Parse function threw out {line}",
                    PRIORITY=5,
                    SYSLOG_IDENTIFIER="firewalld-ext",
                )
                continue
        elif "csv" in data["source"]:
            try:
                line = line[: line.index(",") :]
            except ValueError:
                journal.send(
                    f"Parse function threw out {line}",
                    PRIORITY=5,
                    SYSLOG_IDENTIFIER="firewalld-ext",
                )
                continue
        try:
            ip = ipaddress.ip_network(line.strip())
            if isinstance(ip, ipaddress.IPv4Network):
                ipv4.add(ip)
            elif isinstance(ip, ipaddress.IPv6Network):
                ipv6.add(ip)
        except ValueError:
            journal.send(
                f"parse function threw out invalid IP {line}",
                PRIORITY=4,
                SYSLOG_IDENTIFIER="firewalld-ext",
            )
            continue
    return ipv4, ipv6


async def main(verbose: bool, appdata: Optional[AppData] = None) -> AppData:
    profile = (
        a.profile
        if (a := appdata) is not None
        else (
            journal.send(
                "No set profile found, falling back to default...",
                PRIORITY=6,
                SYSLOG_IDENTIFIER="firewalld-ext",
            ),
            verbose and print("No set profile found, falling back to default..."),
            Profile.BALANCED,
        )[-1]
    )
    if verbose:
        print("polling sources...")
    results = await poll_sources(profile)
    if verbose:
        print("done")
        print("parsing data...")
    parsed = await asyncio.gather(
        *(asyncio.to_thread(parse, result) for result in results if result is not None)
    )
    if not any(v4 or v6 for (v4, v6) in parsed):
        journal.send(
            "Failed to recieve any valid response from any source.",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        print("Failed to recieve any valid response from any source, exiting...")
        sys.exit(1)
    ipv4, ipv6 = set(), set()
    for i4, i6 in parsed:
        ipv4 |= i4
        ipv6 |= i6
    ipv4: set[ipaddress.IPv4Network] = {ip for ip in ipaddress.collapse_addresses(ipv4)}
    ipv6: set[ipaddress.IPv6Network] = {ip for ip in ipaddress.collapse_addresses(ipv6)}
    if verbose:
        print("done")
    apply_rules({str(ip) for ip in ipv4}, {str(ip) for ip in ipv6}, verbose)
    return AppData(
        profile=profile,
        ipv4_networks=ipv4,
        ipv6_networks=ipv6,
        time_stamp=datetime.datetime.now(),
    )
