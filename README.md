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

* **Flexible Update Modes**

  * **`--complete-refresh`**: wipe and replace blocklists.
  * **`--refresh-keep`**: merge new feeds while retaining existing entries.
  * **`--remove-all`**: clear all firewalld-ext rules.
  * **`--show-stats`**: view number of blocked networks and update time.
  * **`--show-ips`**: dump currently blocked IPs.

* **Systemd Integration**
  Comes with `firewalld-ext.service` and `firewalld-ext.timer` for periodic updates.

---

## Project Structure

```
firewalld-ext/
├── apply_rules.py       # Writes XML ipsets + direct rules, reloads firewalld
├── data_handler.py      # Handles saving/loading IP + stats JSON
├── main.py              # CLI entrypoint (argparse + subcommands)
├── sources.py           # Defines threat intelligence feed URLs
├── update.py            # Fetches feeds, parses, deduplicates, applies rules
├── firewalld-ext.service # Systemd service unit
├── firewalld-ext.timer   # Systemd timer unit
├── pyproject.toml        # Project metadata + dependencies
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

Run with one of the following flags:

| Command                            | Description                                           |
| ---------------------------------- | ----------------------------------------------------- |
| `firewalld-ext --refresh-keep`     | Update feeds, append new entries, preserve old ones   |
| `firewalld-ext --complete-refresh` | Purge and rebuild blocklists from scratch             |
| `firewalld-ext --remove-all`       | Remove all firewalld-ext ipsets and rules             |
| `firewalld-ext --show-stats`       | Show counts of IPv4, IPv6, and total blocked networks |
| `firewalld-ext --show-ips`         | Print all blocked IPs/subnets                         |

### Example

```bash
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
$ firewalld-ext --show-stats
IPV4 Networks: 34011
IPV6 Networks: 78
Total number of Networks blocked: 34089
Last updated: 2025-09-20 11:50:17.685592
```

---

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
  **Fix:** `firewalld-ext --complete-refresh`.

---

## Roadmap

* [ ] Add support for more OSINT feeds.
* [ ] Configurable update interval via YAML/JSON.
* [ ] Support for whitelists / exceptions.

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
