#!/bin/bash
# flypaper installer: turns a fresh Ubuntu 24.04 host into a honeypot that
# feeds PcapHub. Idempotent: re-running updates in place.
#
#   sudo PCAPHUB_API_KEY=phk_... FLYPAPER_NAME=hel-1 bash install.sh
#
# Environment (all optional except the key, or FLYPAPER_DRY_RUN=1):
#   PCAPHUB_API_KEY        upload-scope API key (never a write key)
#   PCAPHUB_URL            default https://pcaphub.com
#   PCAPHUB_COLLECTION_ID  collection UUID to add uploads to
#   FLYPAPER_NAME          collector name, default: hostname
#   FLYPAPER_REGION        free text tag, e.g. eu-north
#   FLYPAPER_DRY_RUN=1     write would-be uploads to /var/lib/flypaper/outbox instead
#   FLYPAPER_VERSION       release tag, default: latest release
#   FLYPAPER_BIN           path to a local flypaper binary (skips the download)
#   MGMT_SSH_PORT          where your real SSH moves to, default 22222
#   COWRIE_VERSION         default 3.1.6
#   OPENCANARY_VERSION     default 0.9.10
#   OPENCANARY_SERVICES    default "http ftp mysql redis rdp vnc mssql tftp httpproxy smbbanner"
#   HTTP_EXTRA_PORTS       more ports answered by the web honeypot (nftables redirect), default "81 8000 8081 8088 8443 8888 9000 7547 2375 9200 5601"
#   CAPTURE_IFACE          default: the default-route interface
#
# What it does, in order: packages; move sshd to MGMT_SSH_PORT (key auth only
# when a key is present); firewall; users and directories; Cowrie (SSH 22,
# Telnet 23) via systemd socket activation; OpenCanary for the other services;
# dumpcap ring buffer; the flypaper collector; self-check.
set -euo pipefail

: "${PCAPHUB_URL:=https://pcaphub.com}"
: "${PCAPHUB_COLLECTION_ID:=}"
: "${FLYPAPER_NAME:=$(hostname -s)}"
: "${FLYPAPER_REGION:=}"
: "${FLYPAPER_DRY_RUN:=0}"
: "${FLYPAPER_VERSION:=latest}"
: "${FLYPAPER_BIN:=}"
: "${MGMT_SSH_PORT:=22222}"
: "${COWRIE_VERSION:=3.1.6}"
: "${OPENCANARY_VERSION:=0.9.10}"
: "${OPENCANARY_SERVICES:=http ftp mysql redis rdp vnc mssql tftp httpproxy smbbanner}"
# Extra ports answered by the OpenCanary web honeypot via an nftables redirect
# (install/http-ports.sh). Empty to skip.
: "${HTTP_EXTRA_PORTS:=81 8000 8081 8088 8443 8888 9000 7547 2375 9200 5601}"
: "${HTTP_PORTS_SCRIPT:=https://raw.githubusercontent.com/pcaphub/flypaper/main/install/http-ports.sh}"
: "${CAPTURE_IFACE:=}"
REPO="pcaphub/flypaper"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
[ -r /etc/os-release ] && . /etc/os-release
if [ "${ID:-}" != "ubuntu" ] || [ "${VERSION_ID:-}" != "24.04" ]; then
  warn "tested on Ubuntu 24.04; this is ${PRETTY_NAME:-unknown}. Continuing."
fi
if [ "$FLYPAPER_DRY_RUN" != 1 ] && [ -z "${PCAPHUB_API_KEY:-}" ]; then
  die "PCAPHUB_API_KEY is required (or FLYPAPER_DRY_RUN=1)"
fi
case "$MGMT_SSH_PORT" in ''|*[!0-9]*) die "MGMT_SSH_PORT must be a number";; esac
[ "$MGMT_SSH_PORT" != 22 ] && [ "$MGMT_SSH_PORT" != 23 ] || die "MGMT_SSH_PORT must not be a honeypot port"

ARCH=$(dpkg --print-architecture)
case "$ARCH" in amd64|arm64) ;; *) die "unsupported architecture $ARCH";; esac
if [ -z "$CAPTURE_IFACE" ]; then
  CAPTURE_IFACE=$(ip -o route show default | awk '{print $5}' | head -1)
  [ -n "$CAPTURE_IFACE" ] || die "could not detect the default interface; set CAPTURE_IFACE"
fi

# ---------------------------------------------------------------- packages
log "Installing packages"
export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get update -q
apt-get install -y -q --no-install-recommends \
  ca-certificates curl ufw unattended-upgrades python3 python3-venv python3-pip \
  libssl-dev libffi-dev build-essential python3-dev wireshark-common libcap2-bin jq
dpkg-reconfigure -f noninteractive wireshark-common
dpkg-reconfigure -f noninteractive unattended-upgrades >/dev/null 2>&1 || true

# ---------------------------------------------------------------- sshd
log "Moving management SSH to port $MGMT_SSH_PORT"
have_key=0
for f in /root/.ssh/authorized_keys "/home/${SUDO_USER:-nobody}/.ssh/authorized_keys"; do
  [ -s "$f" ] && have_key=1
done
mkdir -p /etc/ssh/sshd_config.d
{
  echo "# flypaper: real SSH lives here; port 22 belongs to the honeypot"
  echo "Port $MGMT_SSH_PORT"
  echo "PermitRootLogin prohibit-password"
  echo "X11Forwarding no"
  if [ "$have_key" = 1 ]; then
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
  fi
} > /etc/ssh/sshd_config.d/00-flypaper.conf
[ "$have_key" = 1 ] || warn "no authorized_keys found: password login stays on. Add a key and set PasswordAuthentication no."
# allow the new port before anything else touches the firewall
ufw allow "$MGMT_SSH_PORT"/tcp >/dev/null
# Ubuntu 24.04 starts sshd through ssh.socket, which ignores Port in sshd_config
if systemctl is-enabled ssh.socket >/dev/null 2>&1; then
  systemctl disable --now ssh.socket >/dev/null 2>&1 || true
fi
systemctl enable ssh.service >/dev/null 2>&1 || true
install -d -m 0755 /run/sshd   # sshd -t needs it on a host where sshd never ran
sshd -t
systemctl restart ssh.service
sleep 1
ss -ltn "sport = :$MGMT_SSH_PORT" | grep -q LISTEN || die "sshd is not listening on $MGMT_SSH_PORT; aborting before the firewall changes"
log "sshd listening on $MGMT_SSH_PORT. Open a second session on that port before you close this one."

# ---------------------------------------------------------------- firewall
log "Configuring the firewall"
ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null
ufw limit "$MGMT_SSH_PORT"/tcp >/dev/null
for p in 22 23; do ufw allow "$p"/tcp >/dev/null; done
declare -A SVC_PORT=( [http]=80 [ftp]=21 [mysql]=3306 [redis]=6379 [rdp]=3389 [vnc]=5900 [mssql]=1433 [httpproxy]=8080 [smbbanner]=445 [git]=9418 [mongodb]=27017 [tftp]=69 )
declare -A SVC_PROTO=( [tftp]=udp )
HONEY_PORTS=()
for s in $OPENCANARY_SERVICES; do
  [ -n "${SVC_PORT[$s]:-}" ] || die "unknown OPENCANARY_SERVICES entry: $s"
  proto=${SVC_PROTO[$s]:-tcp}
  ufw allow "${SVC_PORT[$s]}/$proto" >/dev/null
  HONEY_PORTS+=("${SVC_PORT[$s]}")
done
ufw --force enable >/dev/null
ufw status | sed 's/^/    /'

if [ -n "$HTTP_EXTRA_PORTS" ] && echo "$OPENCANARY_SERVICES" | grep -qw http; then
  log "Redirecting extra HTTP ports to the web honeypot"
  if [ -f "$HTTP_PORTS_SCRIPT" ]; then
    cp "$HTTP_PORTS_SCRIPT" /root/http-ports.sh
  else
    curl -fsSL "$HTTP_PORTS_SCRIPT" -o /root/http-ports.sh
  fi
  HTTP_EXTRA_PORTS="$HTTP_EXTRA_PORTS" HTTP_TARGET_PORT=80 MGMT_SSH_PORT="$MGMT_SSH_PORT" bash /root/http-ports.sh | sed 's/^/    /'
fi

# ---------------------------------------------------------------- users, dirs
log "Creating users and directories"
for u in cowrie opencanary flypaper; do
  id "$u" >/dev/null 2>&1 || useradd --system --home-dir "/opt/$u" --create-home --shell /usr/sbin/nologin "$u"
done
usermod -aG wireshark flypaper
usermod -aG cowrie flypaper
usermod -aG opencanary flypaper
install -d -o cowrie -g cowrie -m 0750 /var/log/cowrie /var/lib/cowrie /var/lib/cowrie/downloads /var/lib/cowrie/tty
install -d -o opencanary -g opencanary -m 0750 /var/log/opencanary
install -d -o flypaper -g flypaper -m 0750 /var/lib/flypaper /var/lib/flypaper/ring /var/lib/flypaper/state /var/lib/flypaper/outbox
install -d -o root -g flypaper -m 0750 /etc/flypaper
install -d -m 0755 /etc/opencanaryd
chmod 0750 /var/log/cowrie /var/log/opencanary   # group (flypaper is a member) may read

# ---------------------------------------------------------------- Cowrie
log "Installing Cowrie $COWRIE_VERSION"
if [ ! -x /opt/cowrie/env/bin/cowrie ] || ! /opt/cowrie/env/bin/pip show cowrie 2>/dev/null | grep -q "^Version: $COWRIE_VERSION\$"; then
  runuser -u cowrie -- bash -c "
    set -e
    cd /opt/cowrie
    [ -d env ] || python3 -m venv env
    env/bin/pip install -q --upgrade pip
    env/bin/pip install -q 'cowrie==$COWRIE_VERSION'
  "
fi
# Operator overrides live in ./etc/cowrie.cfg (cwd of the service), layered on
# Cowrie's bundled defaults. Do not run "cowrie init": it writes a full copy of
# the defaults there, which would shadow this file.
install -d -o cowrie -g cowrie -m 0750 /opt/cowrie/etc /opt/cowrie/var
cat > /opt/cowrie/etc/cowrie.cfg <<EOF
# flypaper: operator overrides on top of Cowrie's bundled defaults
[honeypot]
hostname = ${FLYPAPER_NAME//[^a-zA-Z0-9-]/}-srv
log_path = /var/log/cowrie
state_path = /var/lib/cowrie
download_path = /var/lib/cowrie/downloads
ttylog_path = /var/lib/cowrie/tty
auth_class = AuthRandom
auth_class_parameters = 2, 5, 10

[ssh]
enabled = true
# ports come from cowrie.socket (22 then 23)
listen_endpoints = systemd:domain=INET:index=0
version = SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13

[telnet]
enabled = true
listen_endpoints = systemd:domain=INET:index=1

[output_jsonlog]
enabled = true
logfile = /var/log/cowrie/cowrie.json
epoch_timestamp = false
EOF
cat > /etc/systemd/system/cowrie.socket <<'EOF'
[Unit]
Description=Cowrie SSH and Telnet honeypot sockets
PartOf=cowrie.service

[Socket]
ListenStream=0.0.0.0:22
ListenStream=0.0.0.0:23
NoDelay=true

[Install]
WantedBy=sockets.target
EOF
cat > /etc/systemd/system/cowrie.service <<'EOF'
[Unit]
Description=Cowrie SSH and Telnet honeypot
After=network.target
Requires=cowrie.socket

[Service]
User=cowrie
Group=cowrie
WorkingDirectory=/opt/cowrie
Environment=PATH=/opt/cowrie/env/bin:/usr/bin:/bin
Environment=COWRIE_STDOUT=yes
Environment=AUTHBIND_ENABLED=no
Environment=PYTHONUNBUFFERED=1
ExecStart=/opt/cowrie/env/bin/cowrie start
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/cowrie /var/lib/cowrie /opt/cowrie
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF
chown root:cowrie /opt/cowrie/etc/cowrie.cfg && chmod 0640 /opt/cowrie/etc/cowrie.cfg

# ---------------------------------------------------------------- OpenCanary
log "Installing OpenCanary $OPENCANARY_VERSION"
if ! /opt/opencanary/env/bin/pip show opencanary 2>/dev/null | grep -q "^Version: $OPENCANARY_VERSION\$"; then
  runuser -u opencanary -- bash -c "
    set -e
    cd /opt/opencanary
    [ -d env ] || python3 -m venv env
    env/bin/pip install -q --upgrade pip
    env/bin/pip install -q 'opencanary==$OPENCANARY_VERSION'
  "
fi
oc_enabled() { case " $OPENCANARY_SERVICES " in *" $1 "*) echo true;; *) echo false;; esac; }
cat > /etc/opencanaryd/opencanary.conf <<EOF
{
  "device.node_id": "flypaper-${FLYPAPER_NAME}",
  "ip.ignorelist": [],
  "logtype.ignorelist": [],
  "ssh.enabled": false,
  "telnet.enabled": false,
  "ftp.enabled": $(oc_enabled ftp), "ftp.port": 21, "ftp.banner": "220 FTP server ready",
  "http.enabled": $(oc_enabled http), "http.port": 80, "http.skin": "nasLogin", "http.banner": "Apache/2.4.58 (Ubuntu)",
  "http.log_unimplemented_method_requests": true, "http.log_redirect_request": true,
  "https.enabled": false,
  "httpproxy.enabled": $(oc_enabled httpproxy), "httpproxy.port": 8080, "httpproxy.skin": "squid",
  "mysql.enabled": $(oc_enabled mysql), "mysql.port": 3306, "mysql.banner": "5.7.42-0ubuntu0.18.04.1", "mysql.log_connection_made": true,
  "mssql.enabled": $(oc_enabled mssql), "mssql.port": 1433, "mssql.version": "2012",
  "redis.enabled": $(oc_enabled redis), "redis.port": 6379,
  "rdp.enabled": $(oc_enabled rdp), "rdp.port": 3389,
  "vnc.enabled": $(oc_enabled vnc), "vnc.port": 5900,
  "tftp.enabled": $(oc_enabled tftp), "tftp.port": 69,
  "git.enabled": $(oc_enabled git), "git.port": 9418,
  "mongodb.enabled": $(oc_enabled mongodb), "mongodb.port": 27017,
  "tcpbanner.enabled": $(oc_enabled smbbanner), "tcpbanner.maxnum": 10,
  "tcpbanner_1.enabled": $(oc_enabled smbbanner), "tcpbanner_1.port": 445,
  "tcpbanner_1.datareceivedbanner": "", "tcpbanner_1.initbanner": "",
  "tcpbanner_1.alertstring.enabled": false, "tcpbanner_1.alertstring": "",
  "tcpbanner_1.keep_alive.enabled": false, "tcpbanner_1.keep_alive_secret": "",
  "tcpbanner_1.keep_alive_probes": 11, "tcpbanner_1.keep_alive_interval": 300, "tcpbanner_1.keep_alive_idle": 300,
  "portscan.enabled": false, "smb.enabled": false, "snmp.enabled": false, "sip.enabled": false,
  "ntp.enabled": false, "llmnr.enabled": false,
  "logger": {
    "class": "PyLogger",
    "kwargs": {
      "formatters": { "plain": { "format": "%(message)s" } },
      "handlers": {
        "file": {
          "class": "logging.handlers.RotatingFileHandler",
          "filename": "/var/log/opencanary/opencanary.log",
          "maxBytes": 52428800, "backupCount": 5
        }
      }
    }
  }
}
EOF
OC_TAC=$(ls /opt/opencanary/env/bin/opencanary.tac 2>/dev/null || find /opt/opencanary/env -name opencanary.tac | head -1)
[ -n "$OC_TAC" ] || die "opencanary.tac not found in the venv"
cat > /etc/systemd/system/opencanary.service <<EOF
[Unit]
Description=OpenCanary honeypot services
After=network.target

[Service]
User=opencanary
Group=opencanary
WorkingDirectory=/opt/opencanary
ExecStart=/opt/opencanary/env/bin/twistd -noy $OC_TAC --pidfile=
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/opencanary /opt/opencanary
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- dumpcap ring
log "Installing the capture ring buffer on $CAPTURE_IFACE"
META_FILTER="not host 169.254.169.254"
BPF="(ip or ip6) and not tcp port $MGMT_SSH_PORT and $META_FILTER"
cat > /etc/systemd/system/flypaper-capture.service <<EOF
[Unit]
Description=flypaper packet capture ring buffer (dumpcap)
After=network-online.target
Wants=network-online.target

[Service]
User=flypaper
Group=flypaper
ExecStart=/usr/bin/dumpcap -i $CAPTURE_IFACE -q -b duration:3600 -b files:168 -w /var/lib/flypaper/ring/ring.pcap -f "$BPF"
Restart=always
RestartSec=5
# no NoNewPrivileges here: dumpcap gets cap_net_raw/cap_net_admin from file
# capabilities (wireshark group), which NNP would switch off
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/flypaper/ring
PrivateTmp=yes
LockPersonality=yes
MemoryMax=256M

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- flypaper
log "Installing flypaper"
if [ -n "$FLYPAPER_BIN" ]; then
  install -m 0755 "$FLYPAPER_BIN" /usr/local/bin/flypaper
else
  tag="$FLYPAPER_VERSION"
  if [ "$tag" = latest ]; then
    tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name)
    [ -n "$tag" ] && [ "$tag" != null ] || die "could not resolve the latest release"
  fi
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/flypaper" "https://github.com/$REPO/releases/download/$tag/flypaper_linux_$ARCH"
  curl -fsSL -o "$tmp/SHA256SUMS" "https://github.com/$REPO/releases/download/$tag/SHA256SUMS"
  (cd "$tmp" && grep " flypaper_linux_$ARCH\$" SHA256SUMS | sed "s/flypaper_linux_$ARCH/flypaper/" | sha256sum -c --quiet -) || die "checksum mismatch for flypaper $tag"
  install -m 0755 "$tmp/flypaper" /usr/local/bin/flypaper
  rm -rf "$tmp"
fi

if [ "$FLYPAPER_DRY_RUN" != 1 ]; then
  umask 027
  printf '%s\n' "$PCAPHUB_API_KEY" > /etc/flypaper/api_key
  chown root:flypaper /etc/flypaper/api_key
  chmod 0640 /etc/flypaper/api_key
  umask 022
fi
if [ ! -f /etc/flypaper/config.yaml ]; then
  cat > /etc/flypaper/config.yaml <<EOF
# flypaper collector configuration (written by install.sh; edit freely, the
# installer does not overwrite an existing file)
name: $FLYPAPER_NAME
region: "$FLYPAPER_REGION"

pcaphub:
  url: $PCAPHUB_URL
  api_key_file: /etc/flypaper/api_key
  collection_id: "$PCAPHUB_COLLECTION_ID"
  tags: [honeypot, flypaper]

capture:
  dir: /var/lib/flypaper/ring
  pattern: "ring_*.pcap*"
  min_age: 2m
  local_ips: []
  exclude_ports: [$MGMT_SSH_PORT]
  exclude_ips: [169.254.169.254]
  retention: 168h

logs:
  cowrie: /var/log/cowrie/cowrie.json
  opencanary: /var/log/opencanary/opencanary.log

select:
  idle_gap: 5m
  max_packets: 2000
  max_bytes: 2097152
  min_packets: 6
  keep_attempts: 20
  min_score: 40
  daily_cap: 20
  baseline_per_day: 1
  repeat_after: 720h
  family_cap: 3
  novelty_bonus: 25
  max_ratio: 0.05
  min_sessions_for_ratio: 200
  exploit_patterns: []

state_dir: /var/lib/flypaper/state
outbox: /var/lib/flypaper/outbox
dry_run: $([ "$FLYPAPER_DRY_RUN" = 1 ] && echo true || echo false)
EOF
  chown root:flypaper /etc/flypaper/config.yaml
  chmod 0640 /etc/flypaper/config.yaml
else
  log "/etc/flypaper/config.yaml exists, left as is"
fi
cat > /etc/systemd/system/flypaper.service <<'EOF'
[Unit]
Description=flypaper collector (honeypot sessions to PcapHub)
After=network-online.target flypaper-capture.service
Wants=network-online.target

[Service]
User=flypaper
Group=flypaper
ExecStart=/usr/local/bin/flypaper -config /etc/flypaper/config.yaml run
Restart=always
RestartSec=30
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/flypaper
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=yes
MemoryMax=512M

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- start
log "Starting services"
systemctl daemon-reload
systemctl enable --now cowrie.socket >/dev/null
systemctl enable --now cowrie.service opencanary.service flypaper-capture.service >/dev/null
systemctl restart cowrie.service opencanary.service flypaper-capture.service
sleep 3
systemctl enable --now flypaper.service >/dev/null
systemctl restart flypaper.service

# ---------------------------------------------------------------- self-check
log "Self-check"
rc=0
for unit in cowrie.socket cowrie.service opencanary.service flypaper-capture.service flypaper.service; do
  if systemctl is-active --quiet "$unit"; then echo "  ok    $unit"; else echo "  FAIL  $unit"; rc=1; fi
done
for p in 22 23 "${HONEY_PORTS[@]}"; do
  if ss -ltun "sport = :$p" | grep -Eq 'LISTEN|UNCONN'; then echo "  ok    port $p listening"; else echo "  FAIL  port $p not listening"; rc=1; fi
done
sleep 5
if ls /var/lib/flypaper/ring/ring_*.pcap* >/dev/null 2>&1; then echo "  ok    ring buffer writing"; else echo "  FAIL  no ring file yet"; rc=1; fi
runuser -u flypaper -- /usr/local/bin/flypaper -config /etc/flypaper/config.yaml check | sed 's/^/  /' || rc=1

echo
if [ $rc = 0 ]; then
  log "Done. Your SSH is on port $MGMT_SSH_PORT (ssh -p $MGMT_SSH_PORT user@host). Port 22 and 23 are the honeypot."
else
  warn "some checks failed; see journalctl -u <unit>"
fi
if [ "$FLYPAPER_DRY_RUN" = 1 ]; then
  log "Dry run: would-be uploads land in /var/lib/flypaper/outbox. Set dry_run: false in /etc/flypaper/config.yaml and restart flypaper when happy."
fi
echo "  journalctl -fu flypaper        follow the collector"
echo "  flypaper -config /etc/flypaper/config.yaml stats   seen vs uploaded"
exit $rc
