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

from enum import Enum

APNIC_TELNET_BRUTEFORCE_IPS = (
    "https://feeds.honeynet.asia/bruteforce/latest-telnetbruteforce-unique.csv"
)
APNIC_SSH_BRUTEFORCE_IPS = (
    "https://feeds.honeynet.asia/bruteforce/latest-sshbruteforce-unique.csv"
)
IPSUM_LEVEL1 = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"
IPSUM_LEVEL2 = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt"
IPSUM_LEVEL3 = "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"
EMERGING_THREATS = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
JAMESBRINE_SSH_BRUTEFORCE_IPS = "https://jamesbrine.com.au/csv"
BLOCKLIST_DE_ALL = "https://lists.blocklist.de/lists/all.txt"
SPAMHAUS_IPV6 = "https://www.spamhaus.org/drop/drop_v6.json"


class Profile(Enum):
    OPEN = {IPSUM_LEVEL3}
    LENIENT = {IPSUM_LEVEL2, SPAMHAUS_IPV6}
    BALANCED = {IPSUM_LEVEL2, SPAMHAUS_IPV6, EMERGING_THREATS, BLOCKLIST_DE_ALL}
    FIRM = {
        IPSUM_LEVEL2,
        SPAMHAUS_IPV6,
        EMERGING_THREATS,
        BLOCKLIST_DE_ALL,
        JAMESBRINE_SSH_BRUTEFORCE_IPS,
        APNIC_TELNET_BRUTEFORCE_IPS,
    }
    STRICT = {
        IPSUM_LEVEL2,
        SPAMHAUS_IPV6,
        EMERGING_THREATS,
        BLOCKLIST_DE_ALL,
        JAMESBRINE_SSH_BRUTEFORCE_IPS,
        APNIC_SSH_BRUTEFORCE_IPS,
        APNIC_TELNET_BRUTEFORCE_IPS,
    }
