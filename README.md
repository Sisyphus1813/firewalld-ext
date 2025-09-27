# firewalld-ext

**firewalld-ext** is a lightweight, asynchronous Python extension for [firewalld](https://firewalld.org/) that automatically fetches, parses, and applies threat intelligence feeds (IPv4 & IPv6 addresses/subnets) to blocklists managed by **ipsets** inside firewalld.

It is designed for speed, scalability, and automation—capable of ingesting thousands of IPs and CIDR ranges, deduplicating them, collapsing overlapping networks, and enforcing them via nftables-compatible ipsets.

---

## Features

* **Automated Threat Feed Ingestion**
  Downloads malicious IP/CIDR feeds from multiple sources (e.g., [stamparm/ipsum](https://github.com/stamparm/ipsum), Spamhaus DROP lists).

* **Asynchronous Fetching**
  Uses `asyncio` + `aiohttp` to concurrently pull feeds for speed.

* **Parsing & Deduplication**

  * Validates addresses using Python’s `ipaddress` module.
  * Separates IPv4 and IPv6 into distinct sets.
  * Collapses overlapping networks (`ipaddress.collapse_addresses`).

* **Direct Integration with firewalld**

  * Writes to `/etc/firewalld/direct.xml` and `/etc/firewalld/ipsets/blocked_{v4/v6}.xml`.
  * Applies via `firewall-cmd --complete-reload`.

* **Persistent Storage & Statistics**

  * Stores blocklists and metadata in `/var/lib/firewalld-ext/`.
  * Tracks counts of IPv4, IPv6, and total blocked networks, plus last update timestamp.

* **Systemd Integration**
  Comes with `firewalld-ext.service` and `firewalld-ext.timer` for periodic updates.

---

## Project Structure

```

firewalld-ext/
├──  src
│   └──  firewalld_ext
│       ├──  apply_rules.py                    # Writes XML ipsets + direct rules, reloads firewalld
│       ├──  data_handler.py                   # Handles saving/loading IP + stats JSON
│       ├──  main.py                           # CLI entrypoint (argparse + subcommands)
│       ├──  sources.py                        # Defines threat intelligence feed URLs
│       └──  update.py                         # Fetches feeds, parses, deduplicates, applies rules
├──  systemd
│   ├──  firewalld-ext.service                 # Systemd service unit
│   └──  firewalld-ext.timer                   # Systemd timer unit
├──  LICENSE                                   # License
├──  pyproject.toml                            # Project metadata + dependencies
├── 󰂺 README.md
└──  uv.lock
```

---

## Installation

### Prerequisites

* **Any firewalld-enabled linux distribution**
* Python **≥ 3.11**
* Firewalld with nftables backend
* `pip` or `uv` and `systemd`

### Steps

1. Clone the repo:

   ```bash
   git clone https://github.com/Sisyphus1813/firewalld-ext.git
   cd firewalld-ext
   ```

2. Install system-wide:

   ```bash
   sudo pip install .
   ```

   This installs the CLI as `firewalld-ext`.

3. (Optional) Enable automated updates:

   ```bash
   sudo cp ~/firewalld-ext/systemd/firewalld-ext.service ~/firewalld-ext/systemd/firewalld-ext.timer /etc/systemd/system/
   sudo systemctl enable --now firewalld-ext.timer
   ```

---

## Usage

### CLI Commands

| Command                                       | Description                                           |
| ----------------------------------            | ----------------------------------------------------- |
| `sudo firewalld-ext --set-proifle <PROFILE>`  | Switch to a different threat feed profile             |
| `sudo firewalld-ext --refresh`                | Update feeds, append new entries, preserve old ones   |
| `sudo firewalld-ext --complete-refresh`       | Purge and rebuild blocklists from scratch             |
| `sudo firewalld-ext --remove-all`             | Remove all firewalld-ext ipsets and rules             |
| `firewalld-ext --status`                      | Show firewalld-ext status and statistics              |
| `firewalld-ext --show-ips`                    | Print all blocked IPs/subnets                         |

Any of the above commands can be supplemented with the `--verbose` or `-v` flag to enable verbose output.

### Example

```bash
# Change to the strict threat feed
sudo firewalld-ext --set-profile strict

# Replace current blocklist with latest feeds
sudo firewalld-ext --complete-refresh

# Merge new feeds into existing blocklist
sudo firewalld-ext --refresh-keep

# Show statistics
firewalld-ext --show-stats
```

---

## Internals

1. **Fetching**

   * Uses `aiohttp.ClientSession()` to asynchronously grab raw text or JSON feeds.

2. **Parsing**

   * Detects whether feed line is IPv4 or IPv6.
   * Handles JSON feeds (e.g., Spamhaus v6) differently from plain text.
   * Skips invalid entries.

3. **Deduplication**

   * `collapse_addresses()` merges overlapping subnets (`192.168.0.0/24` absorbs `192.168.0.1/32`).
   * Ensures minimal set of unique networks.

4. **Cataloging**

   * Saves results into `/var/lib/firewalld-ext/{blocked_ips.json, info.json}`.
   * Tracks metadata (counts, timestamp).

5. **Rule Application**

   * Writes ipsets into `/etc/firewalld/ipsets/blocked_v4.xml` and `/etc/firewalld/ipsets/blocked_v6.xml`.
   * Writes direct rules into `/etc/firewalld/direct.xml` (INPUT/OUTPUT drops).
   * Calls `firewall-cmd --complete-reload`.

---

## Systemd Integration

### Service (`firewalld-ext.service`)

Runs the updater as a systemd-managed service.

### Timer (`firewalld-ext.timer`)

Schedules automatic execution (e.g., hourly/daily depending on your setup).

Enable both:

```bash
sudo systemctl enable --now firewalld-ext.timer
```

Check logs:

```bash
journalctl -u firewalld-ext.service -f
```

---

## Example Stats Output

```bash
$ firewalld-ext --status
Profile: Balanced
IPV4 Networks: 34011
IPV6 Networks: 78
Total number of Networks blocked: 34089
Last updated: 2025-09-20 11:50:17.685592
```

---

## Threat feed profiles

* **Open:** Minimal threat feed containing only the bare essentialls.
* **Lenient:** Expands on the "Open" threat feed and includes IPV6 addresses
* **Balanced:** The goldilocks zone, A good amount of threat feed covering a wide variety of threats; low to no chance of breaking during everyday usage.
* **Firm:** Expands significantly on the Balanced profile by adding brute force SSH/telnet threat feeds. Expect occassion breakage or slow initial network connection.
* **Srict:** Generally not reccomended, but it's there if you want it. You'll still be able to access the internet but expecgt frequent breakage and extremely slow initial network connection.


## Troubleshooting

* **Problem:** `Failed to write new rules to ipsets!`
  **Fix:** Remove stale ipset files and retry.

  ```bash
  sudo rm -f /etc/firewalld/direct.xml /etc/firewalld/ipsets/blocked_v4.xml /etc/firewalld/ipsets/blocked_v6.xml
  sudo firewall-cmd --complete-reload
  sudo firewalld-ext --complete-refresh
  ```

* **Problem:** `ModuleNotFoundError` when running systemd.
  **Fix:** Ensure package was installed system-wide with `sudo pip install .`.

* **Problem:** No stats or IPs showing.
  **Fix:** `sudo firewalld-ext --complete-refresh`.

* **Problem:** Ipsets failed to update due to overlapping subenets.
  **Fix:** This can happen if you attempt to --refresh after changing threat feed profiles before calling --complete-refresh. Simply `sudo firewalld-ext --complete-refresh`

---

## Contributing

Contributions are welcome! If you’d like to add features, fix bugs, or improve documentation:

Fork the repository.

Create a feature branch (git checkout -b my-feature).

Commit your changes with clear messages.

Submit a pull request.

Please follow Python best practices and ensure your changes don’t break existing functionality.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.
