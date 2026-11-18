#!/usr/bin/env bash
# flypaper: put Beelzebub (https://github.com/beelzebub-labs/beelzebub, GPL-3)
# on the web ports instead of OpenCanary's login page.
#
# Beelzebub is a maintained deception framework; its shipped WordPress service
# definition answers the way a real site would, so scanners that check the
# target before sending their payload carry on, and it logs every request
# with the complete body. Nothing is executed: every response is a fixed
# string from the service file. The service file is taken verbatim from the
# upstream tag; flypaper adds nothing to it.
#
# The binary comes from flypaper's release page, built by flypaper's CI from
# the upstream tag with CGO disabled (see THIRD_PARTY.md for the source
# offer), and is verified against the release's SHA256SUMS.
#
# Side effects: OpenCanary's http and httpproxy modules are switched off
# (Beelzebub takes :80 and the redirect sends 8080 and the other HTTP ports
# there), ufw allows 80, http-ports.sh is re-run with 8080 added.
set -euo pipefail

: "${BEELZEBUB_VERSION:=v3.10.0}"
: "${FLYPAPER_VERSION:=latest}"           # flypaper release holding the beelzebub binary
: "${BEELZEBUB_BIN:=}"                    # local binary instead of the download
: "${BEELZEBUB_SERVICES:=http-80.yaml}"   # upstream configurations/services files to install
: "${HTTP_EXTRA_PORTS:=8080 81 8000 8081 8088 8443 8888 9000 7547 2375 9200 5601}"
: "${MGMT_SSH_PORT:=22222}"
REPO=pcaphub/flypaper
UPSTREAM=beelzebub-labs/beelzebub

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }
[ "$(id -u)" = 0 ] || die "run as root"
command -v jq >/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq jq >/dev/null; }

ARCH=$(dpkg --print-architecture)
case "$ARCH" in amd64|arm64) ;; *) die "no beelzebub build for $ARCH" ;; esac

# ---------------------------------------------------------------- binary
id beelzebub >/dev/null 2>&1 || useradd --system --home-dir /opt/beelzebub --create-home --shell /usr/sbin/nologin beelzebub
install -d -m 0755 /opt/beelzebub /etc/beelzebub /etc/beelzebub/services
install -d -o beelzebub -g beelzebub -m 0750 /var/log/beelzebub
usermod -aG beelzebub flypaper 2>/dev/null || true   # the collector reads the log

if [ -n "$BEELZEBUB_BIN" ]; then
  log "Installing beelzebub from $BEELZEBUB_BIN"
  install -m 0755 "$BEELZEBUB_BIN" /opt/beelzebub/beelzebub.new
else
  tag="$FLYPAPER_VERSION"
  if [ "$tag" = latest ]; then
    tag=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | jq -r .tag_name)
  fi
  log "Downloading beelzebub $BEELZEBUB_VERSION ($ARCH) from flypaper release $tag"
  tmp=$(mktemp -d)
  curl -fsSL -o "$tmp/beelzebub_linux_$ARCH" "https://github.com/$REPO/releases/download/$tag/beelzebub_linux_$ARCH"
  curl -fsSL -o "$tmp/SHA256SUMS" "https://github.com/$REPO/releases/download/$tag/SHA256SUMS"
  (cd "$tmp" && grep " beelzebub_linux_$ARCH\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for beelzebub_linux_$ARCH in release $tag"
  install -m 0755 "$tmp/beelzebub_linux_$ARCH" /opt/beelzebub/beelzebub.new
  rm -rf "$tmp"
fi
systemctl stop beelzebub.service 2>/dev/null || true
mv -f /opt/beelzebub/beelzebub.new /opt/beelzebub/beelzebub
/opt/beelzebub/beelzebub version | sed 's/^/    /'

# ---------------------------------------------------------------- configuration
log "Installing upstream service definitions: $BEELZEBUB_SERVICES"
for f in $BEELZEBUB_SERVICES; do
  curl -fsSL -o "/etc/beelzebub/services/$f" "https://raw.githubusercontent.com/$UPSTREAM/$BEELZEBUB_VERSION/configurations/services/$f"
  grep -q '^protocol: "http"' "/etc/beelzebub/services/$f" || die "$f is not an http service definition"
  grep -q 'plugin:' "/etc/beelzebub/services/$f" && die "$f uses a plugin (LLM); only static service files are installed here"
done
cat > /etc/beelzebub/beelzebub.yaml <<EOF
# Beelzebub core configuration (written by flypaper's web-honeypot.sh)
core:
  logging:
    debug: false
    debugReportCaller: false
    logDisableTimestamp: true
    logsPath: /var/log/beelzebub/beelzebub.log
  tracings:
    rabbit-mq:
      enabled: false
      uri: ""
  prometheus:
    enabled: false
    path: "/metrics"
    port: ":2112"
  beelzebub-cloud:
    enabled: false
    uri: ""
    auth-token: ""
EOF
cat > /etc/logrotate.d/beelzebub <<EOF
/var/log/beelzebub/beelzebub.log {
  daily
  rotate 7
  compress
  delaycompress
  missingok
  notifempty
  copytruncate
}
EOF

cat > /etc/systemd/system/beelzebub.service <<EOF
[Unit]
Description=Beelzebub web honeypot (flypaper)
After=network.target

[Service]
User=beelzebub
Group=beelzebub
WorkingDirectory=/opt/beelzebub
ExecStart=/opt/beelzebub/beelzebub run -c /etc/beelzebub/beelzebub.yaml -s /etc/beelzebub/services/ --mem-limit-mib 200
Restart=always
RestartSec=5
StandardOutput=null
StandardError=journal
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/beelzebub
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
MemoryMax=384M

[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------- hand over the web ports
if [ -f /etc/opencanaryd/opencanary.conf ]; then
  log "Switching off OpenCanary's http and httpproxy modules"
  python3 - <<'PY'
import json
p = "/etc/opencanaryd/opencanary.conf"
with open(p) as f:
    c = json.load(f)
c["http.enabled"] = False
c["httpproxy.enabled"] = False
with open(p, "w") as f:
    json.dump(c, f, indent=2)
PY
  systemctl restart opencanary.service 2>/dev/null || true
fi

systemctl daemon-reload
systemctl enable beelzebub.service >/dev/null 2>&1
systemctl restart beelzebub.service
systemctl is-active --quiet flypaper.service && systemctl restart flypaper.service   # picks up the beelzebub group
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  ufw allow 80/tcp >/dev/null
fi

if [ -f /root/http-ports.sh ] || curl -fsSL -o /root/http-ports.sh "https://raw.githubusercontent.com/$REPO/main/install/http-ports.sh"; then
  HTTP_EXTRA_PORTS="$HTTP_EXTRA_PORTS" HTTP_TARGET_PORT=80 MGMT_SSH_PORT="$MGMT_SSH_PORT" bash /root/http-ports.sh | sed 's/^/    /'
fi

# ---------------------------------------------------------------- check
for i in 1 2 3 4 5 6 7 8 9 10; do
  ss -ltn 'sport = :80' | grep -q LISTEN && break
  sleep 1
done
ss -ltn 'sport = :80' | grep -q LISTEN || die "beelzebub is not listening on :80 (journalctl -u beelzebub)"
log "beelzebub $BEELZEBUB_VERSION answering on :80 (and the redirected ports); log /var/log/beelzebub/beelzebub.log"
echo "    the collector reads it once /etc/flypaper/config.yaml has logs.beelzebub set (flypaper >= v0.2.0 reads it by default)"
