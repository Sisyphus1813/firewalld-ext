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

apnic_telnet_bruteforce_ips = "https://feeds.honeynet.asia/bruteforce/latest-telnetbruteforce-unique.csv"
apnic_ssh_bruteforce_ips = "https://feeds.honeynet.asia/bruteforce/latest-sshbruteforce-unique.csv"
ipsum_level1 = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"
ipsum_level2 = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt"
ipsum_level3 = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
emerging_threats = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
jamesbrine_ssh_bruteforce_ips = "https://jamesbrine.com.au/csv"
blocklist_de_all = "https://lists.blocklist.de/lists/all.txt"
spamhaus_ipv6 = "https://www.spamhaus.org/drop/drop_v6.json"

profiles = {
    "open": {
        ipsum_level3
    },
    "lenient": {
        ipsum_level2,
        spamhaus_ipv6
    },
    "balanced": {
        ipsum_level2,
        spamhaus_ipv6,
        emerging_threats,
        blocklist_de_all
    },
    "firm": {
        ipsum_level2,
        spamhaus_ipv6,
        emerging_threats,
        blocklist_de_all,
        jamesbrine_ssh_bruteforce_ips,
        apnic_telnet_bruteforce_ips
    },
    "strict": {
        ipsum_level2,
        spamhaus_ipv6,
        emerging_threats,
        blocklist_de_all,
        jamesbrine_ssh_bruteforce_ips,
        apnic_ssh_bruteforce_ips,
        apnic_telnet_bruteforce_ips
    }
}
