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

from systemd import journal
import subprocess
import shutil
import os


def apply_rules(ipv4=None, ipv6=None, function=None, verbose=False):
    try:
        if function == "complete_refresh":
            if verbose:
                print("Writing rules to firewalld")
            with open("/etc/firewalld/.direct.xml.temp", "w") as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write("<direct>\n")
                f.write(
                    '   <rule ipv="ipv4" table="filter" chain="INPUT" priority="0">-m set --match-set blocked_v4 src -j DROP</rule>\n'
                )
                f.write(
                    '   <rule ipv="ipv4" table="filter" chain="OUTPUT" priority="0">-m set --match-set blocked_v4 dst -j DROP</rule>\n'
                )
                f.write(
                    '   <rule ipv="ipv6" table="filter" chain="INPUT" priority="0">-m set --match-set blocked_v6 src -j DROP</rule>\n'
                )
                f.write(
                    '   <rule ipv="ipv6" table="filter" chain="OUTPUT" priority="0">-m set --match-set blocked_v6 dst -j DROP</rule>\n'
                )
                f.write("</direct>\n")
            os.replace("/etc/firewalld/.direct.xml.temp", "/etc/firewalld/direct.xml")
            with open("/etc/firewalld/ipsets/.blocked_v4.xml.tmp", "w") as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write('<ipset type="hash:net">\n')
                f.write('  <option name="family" value="inet"/>\n')
                f.write('  <option name="maxelem" value="200000"/>\n')
            with open("/etc/firewalld/ipsets/.blocked_v6.xml.tmp", "w") as f:
                f.write('<?xml version="1.0" encoding="utf-8"?>\n')
                f.write('<ipset type="hash:net">\n')
                f.write('  <option name="family" value="inet6"/>\n')
                f.write('  <option name="maxelem" value="200000"/>\n')
            if verbose:
                print("Done")

        elif function == "refresh":
            shutil.copy(
                "/etc/firewalld/ipsets/blocked_v4.xml",
                "/etc/firewalld/ipsets/.blocked_v4.xml.tmp",
            )
            shutil.copy(
                "/etc/firewalld/ipsets/blocked_v6.xml",
                "/etc/firewalld/ipsets/.blocked_v6.xml.tmp",
            )
            with open("/etc/firewalld/ipsets/.blocked_v4.xml.tmp", "rb+") as f:
                lines = f.readlines()
                if lines and lines[-1].strip() == b"</ipset>":
                    f.seek(0)
                    f.writelines(lines[:-1])
                    f.truncate()
            with open("/etc/firewalld/ipsets/.blocked_v6.xml.tmp", "rb+") as f:
                lines = f.readlines()
                if lines and lines[-1].strip() == b"</ipset>":
                    f.seek(0)
                    f.writelines(lines[:-1])
                    f.truncate()

        if verbose:
            print("Updating ipsets")

        if ipv4:
            with open("/etc/firewalld/ipsets/.blocked_v4.xml.tmp", "a") as f:
                for ip in ipv4:
                    f.write(f"  <entry>{ip}</entry>\n")

        if ipv6:
            with open("/etc/firewalld/ipsets/.blocked_v6.xml.tmp", "a") as f:
                for ip in ipv6:
                    f.write(f"  <entry>{ip}</entry>\n")

        with open("/etc/firewalld/ipsets/.blocked_v4.xml.tmp", "a") as f:
            f.write("</ipset>\n")

        with open("/etc/firewalld/ipsets/.blocked_v6.xml.tmp", "a") as f:
            f.write("</ipset>\n")

    except PermissionError as e:
        journal.send(
            f"Permission denied while applying rules: {e}. Run with sudo.",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return
    except FileNotFoundError as e:
        journal.send(
            f"Missing required firewalld file or directory: {e}.",
            PRIORITY=4,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return
    except IsADirectoryError as e:
        journal.send(
            f"Corrupted firewalld directory structure: {e}. Run sudo firewalld-ext --remove-all\nthen\nsudo firewalld-ext --complete-reload",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return
    except OSError as e:
        journal.send(
            f"OS-level error while writing firewalld rules: {e}",
            PRIORITY=2,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return
    except Exception as e:
        journal.send(
            f"Unhandled exception in apply_rules(): {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return

    try:
        os.replace(
            "/etc/firewalld/ipsets/.blocked_v4.xml.tmp",
            "/etc/firewalld/ipsets/blocked_v4.xml",
        )
        os.replace(
            "/etc/firewalld/ipsets/.blocked_v6.xml.tmp",
            "/etc/firewalld/ipsets/blocked_v6.xml",
        )
    except Exception as e:
        journal.send(
            f"Failed to replace temporary ipset files: {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
        return

    if verbose:
        print("Done")
        print("Applying settings to firewalld...")

    try:
        subprocess.run(["sudo", "firewall-cmd", "--complete-reload"], check=True)
    except subprocess.CalledProcessError as e:
        journal.send(
            f"firewall-cmd reload failed with exit code {e.returncode}: {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
    except Exception as e:
        journal.send(
            f"Unexpected error running firewall-cmd reload: {e}",
            PRIORITY=3,
            SYSLOG_IDENTIFIER="firewalld-ext"
        )
