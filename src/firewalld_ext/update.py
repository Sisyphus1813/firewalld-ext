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

import aiohttp

from firewalld_ext import data_handler
from firewalld_ext.apply_rules import apply_rules
from firewalld_ext.sources import profiles
from systemd import journal


async def fetch(session: aiohttp.ClientSession, source: str):
    tries = 0
    while True:
        tries += 1
        try:
            async with session.get(source) as response:
                data = await response.text()
                data = {"source": source, "response": data}
                if not data["response"] and tries < 5:
                    journal.send(
                        f"Failed to fetch {data['source']}...retrying",
                        PRIORITY=4,
                        SYSLOG_IDENTIFIER="firewalld-ext",
                    )
                    await asyncio.sleep(tries)
                    continue
                break
        except Exception as e:
            data = {"source": source, "response": str(e)}
            if tries < 5:
                journal.send(
                    f"Failed to fetch {data['source']}...retrying",
                    PRIORITY=4,
                    SYSLOG_IDENTIFIER="firewalld-ext",
                )
                await asyncio.sleep(tries)
                continue
            break
    return data


async def poll_sources(sources: set[str]):
    async with aiohttp.ClientSession() as session:
        tasks = {fetch(session, source) for source in sources}
        return await asyncio.gather(*tasks)


def parse(data):
    ipv4 = set()
    ipv6 = set()
    if not data["response"]:
        journal.send(
            f"Never recieved reply from {data['source']}",
            PRIORITY=4,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        return set()
    for line in data["response"].splitlines():
        if "spamhaus" in data["source"]:
            line = json.loads(line)
            try:
                line = line["cidr"]
            except KeyError:
                continue
        elif "csv" in data["source"]:
            try:
                line = line[: line.index(",") :]
            except ValueError:
                continue
        try:
            ip = ipaddress.ip_network(line.strip())
            if isinstance(ip, ipaddress.IPv4Network):
                ipv4.add(ip)
            elif isinstance(ip, ipaddress.IPv6Network):
                ipv6.add(ip)
        except ValueError:
            journal.send(
                f"parse function threw out invalid IP {line.strip()}",
                PRIORITY=4,
                SYSLOG_IDENTIFIER="firewalld-ext",
            )
            continue
    return ipv4, ipv6


def catalog(ipv4: set[str], ipv6: set[str], profile, verbose):
    all_networks = {"ipv4": list(ipv4), "ipv6": list(ipv6)}
    info = {
        "Profile": profile.capitalize(),
        "IPV4 Networks": len(ipv4),
        "IPV6 Networks": len(ipv6),
        "Total number of Networks blocked": sum(len(v) for v in all_networks.values()),
        "Last updated": str(datetime.datetime.now()),
    }
    data_handler.save(all_networks, info, verbose)


async def main(verbose: bool):
    if verbose:
        print("loading settings...")
    profile_name = data_handler.load("profile")
    if profile_name:
        profile = profiles[str(profile_name)]
        if verbose:
            print("done")
    else:
        profile_name = "balanced"
        profile = profiles["balanced"]
        journal.send(
            "No set profile found, falling back to default...",
            PRIORITY=6,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        if verbose:
            print("No set profile found, falling back to default...")
    if verbose:
        print("polling sources...")
    results = await poll_sources(profile)
    if verbose:
        print("done")
        print("parsing data...")
    parsed = await asyncio.gather(
        *(asyncio.to_thread(parse, result) for result in results)
    )
    if not parsed:
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
    ipv4 = {str(ip) for ip in ipaddress.collapse_addresses(ipv4)}
    ipv6 = {str(ip) for ip in ipaddress.collapse_addresses(ipv6)}
    if verbose:
        print("done")
    catalog(ipv4, ipv6, profile_name, verbose)
    apply_rules(ipv4, ipv6)
