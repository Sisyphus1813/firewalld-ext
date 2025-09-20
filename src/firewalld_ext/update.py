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

import os
import asyncio
import aiohttp
import json
import ipaddress
import datetime
import subprocess
from firewalld_ext import data_handler
from firewalld_ext.apply_rules import apply_rules
from firewalld_ext.sources import all_sources


async def fetch(session, source):
    try:
        async with session.get(source) as response:
            data = await response.text()
            return {"source": source, "response": data}
    except Exception as e:
        return {"source": source, "response": str(e)}


async def poll_sources():
    async with aiohttp.ClientSession() as session:
        tasks = {fetch(session, source) for source in all_sources}
        return await asyncio.gather(*tasks)


def parse(data):
    ipv4 = set()
    ipv6 = set()
    for line in data["response"].splitlines():
        if "spamhaus" in data["source"]:
            line = json.loads(line)
            try:
                line = line["cidr"]
            except KeyError:
                continue
        try:
            ip = ipaddress.ip_network(line.strip())
            if isinstance(ip, ipaddress.IPv4Network):
                ipv4.add(ip)
            elif isinstance(ip, ipaddress.IPv6Network):
                ipv6.add(ip)
        except ValueError:
            continue
    ipv4 = {str(ip) for ip in ipaddress.collapse_addresses(ipv4)}
    ipv6 = {str(ip) for ip in ipaddress.collapse_addresses(ipv6)}
    return ipv4, ipv6


def catalog(ipv4, ipv6):
    all_networks = {"ipv4": list(ipv4), "ipv6": list(ipv6)}
    info = {
        "IPV4 Networks": len(ipv4),
        "IPV6 Networks": len(ipv6),
        "Total number of Networks blocked": sum(len(v) for v in all_networks.values()),
        "Last updated": str(datetime.datetime.now()),
    }
    data_handler.save(all_networks, info)


async def main(function):
    current_ips = data_handler.load("ips")
    if function != "remove_all":
        results = await poll_sources()
        parsed = await asyncio.gather(
            *(asyncio.to_thread(parse, result) for result in results)
        )
        ipv4, ipv6 = set(), set()
        for i4, i6 in parsed:
            ipv4 |= i4
            ipv6 |= i6
    match function:
        case "refresh_keep":
            if current_ips:
                ipv4.difference_update(set(current_ips["ipv4"]))
                ipv6.difference_update(set(current_ips["ipv6"]))
                combined_ipv4 = ipv4.union(set(current_ips["ipv4"]))
                combined_ipv6 = ipv6.union(set(current_ips["ipv6"]))
                catalog(combined_ipv4, combined_ipv6)
                apply_rules(ipv4, ipv6, function)
            else:
                catalog(ipv4, ipv6)
                apply_rules(ipv4, ipv6, "complete_refresh")

        case "complete_refresh":
            catalog(ipv4, ipv6)
            apply_rules(ipv4, ipv6, function)

        case "remove_all":
            if not current_ips and not os.path.isfile("/etc/firewalld/direct.xml"):
                print("No addresses detected in memory to remove!")
                return
            os.remove("/etc/firewalld/direct.xml")
            os.remove("/etc/firewalld/ipsets/blocked_v4.xml")
            os.remove("/etc/firewalld/ipsets/blocked_v6.xml")
            subprocess.run(["sudo", "firewall-cmd", "--complete-reload"])
