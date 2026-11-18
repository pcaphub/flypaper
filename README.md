# flypaper

Turn a cheap Linux VPS into a honeypot that feeds [PcapHub](https://pcaphub.com) with short, focused, deduplicated packet captures of real attacks.

One command installs the honeypots, the capture ring buffer and the collector. The collector slices every attacker session into its own small pcap, joins it with what the honeypot logged (credentials, commands, downloads), scores it, drops the repeats, writes a plain-language description, and uploads the interesting ones as private captures to your PcapHub account. PcapHub does the rest: tshark dissection, Suricata, artifacts, timeline.

Everything is open source and free of charge: [Cowrie](https://github.com/cowrie/cowrie) (SSH and Telnet, BSD-3), [OpenCanary](https://github.com/thinkst/opencanary) (HTTP, FTP, MySQL, MSSQL, Redis, RDP, VNC, TFTP, HTTP proxy, a banner on 445; BSD-3), `dumpcap` from Wireshark for the ring buffer, and this Go collector (MIT). No root honeypots: Cowrie gets ports 22 and 23 from systemd socket activation, OpenCanary runs with only `CAP_NET_BIND_SERVICE`, the ring buffer runs as an unprivileged user in the `wireshark` group.

## Quick start

On a fresh Ubuntu 24.04 VPS (1 vCPU, 1 GB RAM is plenty):

```sh
curl -fsSL https://raw.githubusercontent.com/pcaphub/flypaper/main/install/install.sh -o install.sh
sudo PCAPHUB_API_KEY=phk_... FLYPAPER_NAME=hel-1 bash install.sh
```

The installer moves your real SSH to port 22222 (`MGMT_SSH_PORT`, key auth only), opens the honeypot ports, installs the honeypots and the collector as systemd services, and runs `flypaper check`. Read `install/install.sh` first; it is short and it is your machine.

The API key needs only the `upload` scope (PcapHub, Settings, API Keys). A key with that scope can create private captures and edit their descriptions and nothing else, so a compromised honeypot cannot touch anything you care about.

Start in dry-run (`dry_run: true` in `/etc/flypaper/config.yaml`) for a day: the collector writes the would-be uploads to `/var/lib/flypaper/outbox` with their metadata so you can judge the selection before anything leaves the box.

## What gets uploaded

One capture is one attacker session: one source address, all the ports it touched, split where it goes quiet for five minutes. Captures are capped at 2,000 packets or 2 MB; a password spray is trimmed to its first 20 connections plus the one that logged in, so the technique is visible in 60 KB instead of 6 MB.

Deduplication is layered and measurable, because a honeypot sees the same bot thousands of times:

1. **Scenario fingerprint**, from content and never from the address: class, command sequence with volatile tokens masked (IPs, hashes, random names, ports), credential set, download hosts and normalised paths, HTTP request and payload templates. The first sighting uploads; the same scenario uploads again only after 30 days. Repeats are counted and the representative capture's description is updated with "seen 412 times from 87 addresses since ...".
2. **Family**: class + services + command verbs (or request path set). Variants of one campaign that differ only in arguments share a family, and a family gets at most 3 uploads per 30 days.
3. **Daily cap** (20), of which scans, password sprays and probes share at most 8 (**probe cap**) so a morning of scanners cannot use up the day before a shell session arrives, plus one daily **baseline** sample so plain scanning is still represented.
4. **Ratio guard**: if uploads exceed 5% of sessions over the last 7 days, the collector raises its threshold by 20 points and logs a warning instead of flooding.

`flypaper stats` prints sessions seen vs uploaded, lifetime and per class, and every description carries the collector's totals.

New techniques are caught without anyone writing a rule first: HTTP request lines and POST bodies are read straight from the packets (so a PHP-to-shell probe is seen whether or not the honeypot understands it), a request path, command or payload template never seen on this collector adds a **novelty bonus** to the score (not for scans and password sprays, whose only payload is the protocol handshake), `select.exploit_patterns` in the config takes extra regular expressions without a rebuild, and PcapHub's Suricata pass marks signatures the collector has never produced before.

Classes, lowest to highest score: `scan-only`, `ssh-bruteforce`, `login-bruteforce` (VNC, MSSQL, MySQL, FTP, RDP password sprays), `telnet-iot`, `service-probe`, `ssh-login-success`, `ssh-port-forward`, `commands-executed`, `web-exploit-attempt`, `malware-download`.

Titles say what the attacker did, in the words a visitor would search for: `Telnet IoT bot as root:xc3511: enable, system, shell, +3 more`, `Web exploit attempt on :8080: PHPUnit eval-stdin RCE (CVE-2017-9841)`, `RDP probe on :3389, connection cookie "hello"`, `Port sweep: 443, 7443, 8443, 9443, 10443`. The collector, region and date are tags and the first line of the description. Descriptions are templated from the facts (attacker-supplied credentials, commands, defanged URLs, SHA-256 of downloads) and, once PcapHub has processed the capture, extended with the Suricata signatures that fired.

## Commands

```
flypaper run          service mode, a pass every 2 minutes
flypaper once         one pass
flypaper dry-run      one pass to the outbox, no upload
flypaper check        config, paths and PcapHub reachability
flypaper stats        sessions seen vs uploaded, per class
flypaper slice F.pcap print the sessions one pcap would produce
flypaper upgrade      install the latest release (checksum verified) and restart the service
```

## Security notes

- Nothing of yours is on the honeypot except an upload-only key. Rotate it from PcapHub if the box is ever in doubt and rebuild from the installer.
- Low-interaction only: attackers get Cowrie's emulated shell, never a real one, so your VPS does not attack others. Check your provider's acceptable use policy; low-interaction honeypots are routinely fine.
- Management traffic (your SSH port, WireGuard) is excluded from every slice, both at capture (BPF) and in the collector. Connections the honeypot opens itself (updates, DNS) are dropped too.
- Uploads are private. Promote the good ones to a public collection by hand.

## Licence

MIT. See `LICENSE`.
