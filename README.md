# flypaper

Turn a cheap Linux VPS into a honeypot that feeds [PcapHub](https://pcaphub.com) with short, focused, deduplicated packet captures of real attacks.

One command installs the honeypots, the capture ring buffer and the collector. The collector slices every attacker session into its own small pcap, joins it with what the honeypot logged (credentials, commands, downloads), scores it, drops the repeats, writes a plain-language description, and uploads the interesting ones as private captures to your PcapHub account. PcapHub does the rest: tshark dissection, Suricata, artifacts, timeline.

Everything is open source and free of charge: [Cowrie](https://github.com/cowrie/cowrie) (SSH and Telnet), the [honeypots](https://github.com/qeeqbox/honeypots) package (HTTP, Redis, MySQL, SMB, RDP, VNC and more), `dumpcap` from Wireshark for the ring buffer, and this Go collector.

## Quick start

On a fresh Ubuntu 24.04 VPS (1 vCPU, 1 GB RAM is plenty):

```sh
curl -fsSL https://raw.githubusercontent.com/pcaphub/flypaper/main/install/install.sh -o install.sh
sudo PCAPHUB_API_KEY=phk_... FLYPAPER_NAME=hel-1 bash install.sh
```

The installer moves your real SSH to port 2222 (key auth only), opens the honeypot ports, installs the honeypots and the collector as systemd services, and runs `flypaper check`. Read `install/install.sh` first; it is short and it is your machine.

The API key needs only the `upload` scope (PcapHub, Settings, API Keys). A key with that scope can create private captures and edit their descriptions and nothing else, so a compromised honeypot cannot touch anything you care about.

Start in dry-run (`dry_run: true` in `/etc/flypaper/config.yaml`) for a day: the collector writes the would-be uploads to `/var/lib/flypaper/outbox` with their metadata so you can judge the selection before anything leaves the box.

## What gets uploaded

One capture is one attacker session: one source address, all the ports it touched, split where it goes quiet for five minutes. Captures are capped at 2,000 packets or 2 MB; a password spray is trimmed to its first 20 connections plus the one that logged in, so the technique is visible in 60 KB instead of 6 MB.

Every session gets a scenario fingerprint from its content, never from the address: class, command sequence with volatile tokens masked, credential set, download hosts and normalised paths, HTTP request templates. The first sighting of a fingerprint uploads. Repeats are counted and the representative capture's description is updated with "seen 412 times from 87 addresses since ...". The same scenario uploads again only after 30 days, or when it fires a Suricata signature this collector has not produced before. A daily cap (20) and one daily baseline sample keep the account tidy.

Classes, lowest to highest score: `scan-only`, `ssh-bruteforce`, `telnet-iot`, `service-probe`, `ssh-login-success`, `ssh-port-forward`, `commands-executed`, `web-exploit-attempt`, `malware-download`.

Descriptions are templated from the facts (attacker-supplied credentials, commands, defanged URLs, SHA-256 of downloads) and, once PcapHub has processed the capture, extended with the Suricata signatures that fired.

## Commands

```
flypaper run          service mode, a pass every 2 minutes
flypaper once         one pass
flypaper dry-run      one pass to the outbox, no upload
flypaper check        config, paths and PcapHub reachability
flypaper slice F.pcap print the sessions one pcap would produce
```

## Security notes

- Nothing of yours is on the honeypot except an upload-only key. Rotate it from PcapHub if the box is ever in doubt and rebuild from the installer.
- Low-interaction only: attackers get Cowrie's emulated shell, never a real one, so your VPS does not attack others. Check your provider's acceptable use policy; low-interaction honeypots are routinely fine.
- Management traffic (your SSH port, WireGuard) is excluded from every slice, both at capture (BPF) and in the collector.
- Uploads are private. Promote the good ones to a public collection by hand.

## Licence

MIT. See `LICENSE`.
