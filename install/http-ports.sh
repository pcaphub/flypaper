#!/usr/bin/env bash
# flypaper: answer more HTTP ports with the OpenCanary web honeypot.
#
# Exploit kits sweep 81, 8000, 8081, 8088, 8443, 8888, 9000, 7547 (TR-069),
# 2375 (Docker API), 9200 (Elasticsearch) and 5601 (Kibana) besides 80 and
# 8080. OpenCanary's HTTP module listens on one port, so the others are
# redirected to it with an nftables rule in a table of its own (ufw does not
# touch it). The capture ring sees packets before NAT, so pcaps and titles
# keep the real port; OpenCanary's log shows the target port, the collector
# joins on address and time, not port.
#
# Idempotent: run again with a different HTTP_EXTRA_PORTS to change the list,
# or with HTTP_EXTRA_PORTS="" to remove the redirect.
set -euo pipefail

: "${HTTP_EXTRA_PORTS:=81 8000 8081 8088 8443 8888 9000 7547 2375 9200 5601}"
: "${HTTP_TARGET_PORT:=80}"
: "${MGMT_SSH_PORT:=22222}"

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
for p in $HTTP_EXTRA_PORTS; do
  [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "bad port: $p" >&2; exit 1; }
  [ "$p" != "$MGMT_SSH_PORT" ] || { echo "refusing to redirect the management SSH port $p" >&2; exit 1; }
  [ "$p" != 22 ] && [ "$p" != 23 ] || { echo "ports 22 and 23 belong to Cowrie" >&2; exit 1; }
done

if [ -z "$HTTP_EXTRA_PORTS" ]; then
  systemctl disable --now flypaper-redirect.service 2>/dev/null || true
  rm -f /etc/flypaper/redirect.nft /etc/systemd/system/flypaper-redirect.service
  systemctl daemon-reload
  echo "HTTP port redirect removed"
  exit 0
fi

command -v nft >/dev/null || { export DEBIAN_FRONTEND=noninteractive; apt-get install -y -qq nftables >/dev/null; }

install -d -m 0755 /etc/flypaper
# "table; delete table; table {...}" makes the file re-applicable: the first
# line creates the table if missing so the delete never fails.
cat > /etc/flypaper/redirect.nft <<EOF
table inet flypaper
delete table inet flypaper
table inet flypaper {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    tcp dport { $(echo "$HTTP_EXTRA_PORTS" | tr -s ' ' ',') } redirect to :$HTTP_TARGET_PORT
  }
}
EOF

cat > /etc/systemd/system/flypaper-redirect.service <<EOF
[Unit]
Description=flypaper: redirect extra HTTP ports to the web honeypot
After=network-pre.target
Wants=network-pre.target
Before=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$(command -v nft) -f /etc/flypaper/redirect.nft
ExecStop=$(command -v nft) delete table inet flypaper

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable flypaper-redirect.service >/dev/null 2>&1
systemctl restart flypaper-redirect.service

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  for p in $HTTP_EXTRA_PORTS; do ufw allow "$p"/tcp >/dev/null; done
fi

echo "redirecting tcp ports $HTTP_EXTRA_PORTS to :$HTTP_TARGET_PORT"
nft list table inet flypaper | sed 's/^/    /'
