# firewalld-ext

**firewalld-ext** is a lightweight, asynchronous Python extension for [firewalld](https://firewalld.org/) that automatically fetches, parses, and applies open source threat intelligence feeds (IPv4 & IPv6 addresses/subnets) to blocklists managed by **ipsets** inside firewalld.

---

## Overview
- Designed to make open-source threat intelligence easy to apply locally without sacrificing customization.
- Automatically polls, parses, and normalizes multiple open-source threat intelligence feeds.
- Writes reported malicious IPv4 and IPv6 subnets directly into firewalld-managed ipsets.
- Supports multiple preconfigured threat profiles, allowing users to control how aggressively intelligence is applied.

---

## Requirements

- A firewalld and (optionally) systemd enabled linux distribution
- Python 3.13+

---

## Installation
### Clone Repository

```bash
git clone https://github.com/Sisyphus1813/firewalld-ext.git  
cd firewalld-ext
```

### Install
```bash
sudo pip install .
```
or using `uv`
```bash
sudo uv pip install --system .
```
### enable systemd service (optional)
```bash
sudo install -m 0644 ~/firewalld-ext/systemd/firewalld-ext.service \
               ~/firewalld-ext/systemd/firewalld-ext.timer \
               /etc/systemd/system/
sudo systemctl enable --now firewalld-ext.timer
```
---

## Configuration

firewalld-ext includes five preconfigured threat profiles, each corresponding to a different combination of up to nine supported open-source threat intelligence feeds:

- `open`
- `lenient`
- `balanced`
- `firm`
- `strict`

Each profile represents an increasing number of sources, allowing users to balance coverage, false positives, and operational impact. Most users will achieve the best balance of coverage, low false positives, and minimal ipset overhead by using the default `balanced` profile.

You can change your threat profile easily like so:
```bash
sudo firewalld-ext set-profile <PROFILE>
sudo firewalld-ext --refresh
```

---

## Usage

| Command                                       | Description                                           |
| ----------------------------------            | ----------------------------------------------------- |
| `sudo firewalld-ext --set-profile <PROFILE>`  | Set the active profile to PROFILE             |
| `sudo firewalld-ext --refresh`                | Update blocked CIDRs    |
| `sudo firewalld-ext --remove-all`             | Completely revert any changes made to firewalld              |
| `firewalld-ext --status`                      | Show firewalld-ext status and statistics              |
| `firewalld-ext --show-subnets`                    | Dump all currently blocked CIDR ranges to stdout                         |

Any of the above commands can be supplemented with the `--verbose` or `-v` flag to enable verbose output.

---

## Checking Logs

firewalld-ext logs any debug or error information to system journal. To view:

  ```bash
  sudo journalctl -t firewalld-ext
  ```
---

## Limitations

- Linux native; Windows support is not planned and will not be added.
- firewalld is the primary performance bottleneck of this project:
	- when managing large ipsets (hundreds of thousands of subnets) network throughput and overall connectivity may suffer
	- complete reloads are necessary to apply updated ipsets; these can take several seconds with large ipsets

These limitations are inherent to firewalld itself. Addressing them is explicitly out of scope for this project.
firewalld-ext, as the name suggests, is intended to extend the capabilities of firewalld, not replace it, re-architect it, or work around its internal design.

---

## Contributing
Contributions are welcome! If you’d like to add features, fix bugs, or improve documentation:
- Fork the repository
- Create a feature branch (git checkout -b my-feature)
- Commit your changes with clear messages
- Submit a pull request

Please follow Python best practices and ensure your changes don’t break existing functionality. This project relies on [Ruff](https://astral.sh/ruff) for formatting and linting.


---

## License

This project is licensed under the GNU General Public License v3.0 or later (GPL-3.0-or-later).

See the [LICENSE](LICENSE)
