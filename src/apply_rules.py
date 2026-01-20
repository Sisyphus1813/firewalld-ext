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
import subprocess
import sys
from xml.parsers.expat import ExpatError, ParserCreate

from systemd import journal


def validate_form(path: str, verbose: bool) -> None:
    try:
        p = ParserCreate()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                p.Parse(chunk, False)
        p.Parse(b"", True)
    except ExpatError as e:
        journal.send(
            f"Failed to properly format {path}; aborting atomic operation.\n{e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        sys.exit(1)
    if verbose:
        print(f"sucessfully validated {path}")


def create_direct_xml(verbose: bool) -> None:
    if verbose:
        print("writing direct rules...")
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>\n',
        "<direct>\n",
        '   <rule ipv="ipv4" table="filter" chain="INPUT" priority="0">-m set --match-set blocked_v4 src -j DROP</rule>\n',
        '   <rule ipv="ipv4" table="filter" chain="OUTPUT" priority="0">-m set --match-set blocked_v4 dst -j DROP</rule>\n',
        '   <rule ipv="ipv6" table="filter" chain="INPUT" priority="0">-m set --match-set blocked_v6 src -j DROP</rule>\n',
        '   <rule ipv="ipv6" table="filter" chain="OUTPUT" priority="0">-m set --match-set blocked_v6 dst -j DROP</rule>\n',
        "</direct>\n",
    ]
    with open("/etc/firewalld/temp/direct.xml.temp", "w") as f:
        f.writelines(lines)
    validate_form("/etc/firewalld/temp/direct.xml.temp", verbose)
    os.replace("/etc/firewalld/temp/direct.xml.temp", "/etc/firewalld/direct.xml")
    if verbose:
        print("done")


def create_blocked_xml(ipv4: set[str], ipv6: set[str], verbose: bool) -> None:
    if verbose:
        print("writing ipsets...")
    v4_lines = [
        '<?xml version="1.0" encoding="utf-8"?>\n',
        '<ipset type="hash:net">\n',
        '  <option name="family" value="inet"/>\n',
        f'  <option name="maxelem" value="{len(ipv4)}"/>\n',
    ]
    v6_lines = [
        '<?xml version="1.0" encoding="utf-8"?>\n',
        '<ipset type="hash:net">\n',
        '  <option name="family" value="inet6"/>\n',
        f'  <option name="maxelem" value="{len(ipv6)}"/>\n',
    ]
    with open("/etc/firewalld/temp/blocked_v4.xml.tmp", "w") as f:
        f.writelines(v4_lines)
    with open("/etc/firewalld/temp/blocked_v6.xml.tmp", "w") as f:
        f.writelines(v6_lines)


def write_and_replace(ipv4: set[str], ipv6: set[str], verbose: bool) -> None:
    try:
        for tmp_path, ips in [
            ("/etc/firewalld/temp/blocked_v4.xml.tmp", ipv4),
            ("/etc/firewalld/temp/blocked_v6.xml.tmp", ipv6),
        ]:
            with open(tmp_path, "a") as f:
                for ip in ips:
                    f.write(f"  <entry>{ip}</entry>\n")
                f.write("</ipset>\n")
        validate_form("/etc/firewalld/temp/blocked_v4.xml.tmp", verbose)
        validate_form("/etc/firewalld/temp/blocked_v6.xml.tmp", verbose)
        os.replace(
            "/etc/firewalld/temp/blocked_v4.xml.tmp",
            "/etc/firewalld/ipsets/blocked_v4.xml",
        )
        os.replace(
            "/etc/firewalld/temp/blocked_v6.xml.tmp",
            "/etc/firewalld/ipsets/blocked_v6.xml",
        )
    except Exception as e:
        journal.send(
            f"Failed to replace temporary ipset files: {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        sys.exit(1)
    if verbose:
        print("done")


def apply_rules(
    ipv4: set[str] = set(),
    ipv6: set[str] = set(),
    verbose: bool = False,
) -> None:
    create_direct_xml(verbose)
    create_blocked_xml(ipv4, ipv6, verbose)
    write_and_replace(ipv4, ipv6, verbose)
    try:
        if verbose:
            print("blocking for firewalld...")
        subprocess.run(["firewall-cmd", "--complete-reload"], check=True)
    except subprocess.CalledProcessError as e:
        journal.send(
            f"firewall-cmd reload failed with exit code {e.returncode}: {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext",
        )
        sys.exit(1)
